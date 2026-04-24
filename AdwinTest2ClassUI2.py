import streamlit as st
import pandas as pd
import numpy as np
import random
import time
import matplotlib.pyplot as plt
from sklearn.utils import shuffle
from river import stream, base, compose, preprocessing, metrics, drift, forest
from river import feature_extraction
from datetime import datetime
from collections import Counter
import plotly.graph_objects as go
import plotly.express as px
from plotly.subplots import make_subplots
import threading
import queue
import io
import sys
import warnings
import scapy.all as scapy
from scapy.all import sniff, IP, TCP, UDP, ICMP, Raw
import psutil
import socket
import struct

warnings.filterwarnings('ignore')

# 设置页面配置
st.set_page_config(
    page_title="实时安全检测系统",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# 自定义CSS样式
st.markdown("""
<style>
    .main-header {
        font-size: 2.5rem;
        color: #00ff00;
        text-align: center;
        padding: 1rem;
        background: linear-gradient(90deg, #1e3c72, #2a5298);
        border-radius: 10px;
        margin-bottom: 2rem;
    }
    .metric-card {
        background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
        padding: 1rem;
        border-radius: 10px;
        color: white;
        text-align: center;
    }
    .alert-critical {
        background-color: #ff4444;
        padding: 0.5rem;
        border-radius: 5px;
        animation: blink 1s infinite;
        color: white;
        font-weight: bold;
    }
    @keyframes blink {
        50% { opacity: 0.5; }
    }
    .status-online {
        color: #00ff00;
        font-weight: bold;
    }
    .status-offline {
        color: #ff4444;
        font-weight: bold;
    }
    .attack-highlight {
        background-color: #ff4444;
        padding: 0.5rem;
        border-radius: 5px;
        margin: 0.5rem 0;
    }
    .packet-info {
        background-color: #1e1e1e;
        padding: 0.5rem;
        border-radius: 5px;
        font-family: monospace;
        font-size: 12px;
        margin: 0.2rem 0;
    }
</style>
""", unsafe_allow_html=True)


# ========== 网络抓包分析器 ==========
class NetworkPacketAnalyzer:
    """实时网络数据包捕获和分析器"""

    def __init__(self):
        self.packet_queue = queue.Queue(maxsize=1000)
        self.captured_packets = []
        self.is_capturing = False
        self.capture_thread = None
        self.stats = {
            'total_packets': 0,
            'tcp_packets': 0,
            'udp_packets': 0,
            'icmp_packets': 0,
            'bytes_transferred': 0,
            'unique_ips': set(),
            'protocols': Counter(),
            'ports': Counter(),
            'packet_sizes': [],
            'timestamps': []
        }
        self.alert_queue = queue.Queue()

    def extract_features_from_packet(self, packet):
        """从网络包中提取特征用于安全检测"""
        features = {
            'duration': 0.0,  # 持续时间（需要前后包对比）
            'src_bytes': 0,
            'dst_bytes': 0,
            'protocol_type': 'unknown',
            'service': 'unknown'
        }

        try:
            if IP in packet:
                # 协议类型
                if TCP in packet:
                    features['protocol_type'] = 'tcp'
                    features['src_bytes'] = len(packet[TCP].payload) if packet[TCP].payload else 0
                    features['dst_bytes'] = len(packet[TCP].payload) if packet[TCP].payload else 0

                    # 服务识别（基于端口）
                    src_port = packet[TCP].sport
                    dst_port = packet[TCP].dport

                    if dst_port == 80 or src_port == 80:
                        features['service'] = 'http'
                    elif dst_port == 443 or src_port == 443:
                        features['service'] = 'https'
                    elif dst_port == 21 or src_port == 21:
                        features['service'] = 'ftp'
                    elif dst_port == 22 or src_port == 22:
                        features['service'] = 'ssh'
                    elif dst_port == 25 or src_port == 25:
                        features['service'] = 'smtp'
                    elif dst_port == 53 or src_port == 53:
                        features['service'] = 'dns'
                    else:
                        features['service'] = 'other'

                elif UDP in packet:
                    features['protocol_type'] = 'udp'
                    features['src_bytes'] = len(packet[UDP].payload) if packet[UDP].payload else 0
                    features['dst_bytes'] = len(packet[UDP].payload) if packet[UDP].payload else 0

                    # UDP服务识别
                    dst_port = packet[UDP].dport
                    if dst_port == 53:
                        features['service'] = 'dns'
                    elif dst_port == 123:
                        features['service'] = 'ntp'
                    else:
                        features['service'] = 'other'

                elif ICMP in packet:
                    features['protocol_type'] = 'icmp'
                    features['service'] = 'icmp'
                    features['src_bytes'] = len(packet[ICMP].payload) if packet[ICMP].payload else 0
                    features['dst_bytes'] = 0

                # 数据包大小
                features['duration'] = len(packet) / 1000.0  # 模拟持续时间

        except Exception as e:
            pass

        return features

    def packet_callback(self, packet):
        """抓包回调函数"""
        if not self.is_capturing:
            return

        try:
            timestamp = datetime.now()
            packet_info = {
                'timestamp': timestamp,
                'packet': packet,
                'features': self.extract_features_from_packet(packet),
                'size': len(packet)
            }

            # 更新统计信息
            self.stats['total_packets'] += 1
            self.stats['bytes_transferred'] += len(packet)
            self.stats['packet_sizes'].append(len(packet))
            self.stats['timestamps'].append(timestamp)

            if IP in packet:
                src_ip = packet[IP].src
                dst_ip = packet[IP].dst
                self.stats['unique_ips'].add(src_ip)
                self.stats['unique_ips'].add(dst_ip)

                if TCP in packet:
                    self.stats['tcp_packets'] += 1
                    self.stats['protocols']['TCP'] += 1
                    self.stats['ports'][packet[TCP].dport] += 1
                elif UDP in packet:
                    self.stats['udp_packets'] += 1
                    self.stats['protocols']['UDP'] += 1
                    self.stats['ports'][packet[UDP].dport] += 1
                elif ICMP in packet:
                    self.stats['icmp_packets'] += 1
                    self.stats['protocols']['ICMP'] += 1

            # 添加到队列
            self.packet_queue.put(packet_info, timeout=1)

            # 保留最近1000个包
            self.captured_packets.append(packet_info)
            if len(self.captured_packets) > 1000:
                self.captured_packets.pop(0)

        except Exception as e:
            pass

    def start_capture(self, interface=None, filter_str=None, packet_count=0):
        """开始抓包"""
        if self.is_capturing:
            return False

        self.is_capturing = True
        self.stats = {
            'total_packets': 0,
            'tcp_packets': 0,
            'udp_packets': 0,
            'icmp_packets': 0,
            'bytes_transferred': 0,
            'unique_ips': set(),
            'protocols': Counter(),
            'ports': Counter(),
            'packet_sizes': [],
            'timestamps': []
        }

        # 在后台线程中抓包
        def capture_thread():
            try:
                sniff(
                    iface=interface,
                    prn=self.packet_callback,
                    store=0,
                    filter=filter_str,
                    count=packet_count if packet_count > 0 else None,
                    timeout=1
                )
            except Exception as e:
                st.error(f"抓包错误: {e}")
                self.is_capturing = False

        self.capture_thread = threading.Thread(target=capture_thread, daemon=True)
        self.capture_thread.start()
        return True

    def stop_capture(self):
        """停止抓包"""
        self.is_capturing = False
        if self.capture_thread:
            self.capture_thread.join(timeout=2)
        return True

    def get_latest_packet(self):
        """获取最新的数据包"""
        try:
            return self.packet_queue.get_nowait()
        except queue.Empty:
            return None

    def get_stats(self):
        """获取统计信息"""
        stats = self.stats.copy()
        stats['unique_ips_count'] = len(stats['unique_ips'])
        if stats['packet_sizes']:
            stats['avg_packet_size'] = np.mean(stats['packet_sizes'])
            stats['max_packet_size'] = np.max(stats['packet_sizes'])
        else:
            stats['avg_packet_size'] = 0
            stats['max_packet_size'] = 0
        return stats

    def get_bandwidth_usage(self):
        """获取带宽使用情况"""
        if len(self.stats['timestamps']) < 2:
            return 0

        time_diff = (self.stats['timestamps'][-1] - self.stats['timestamps'][0]).total_seconds()
        if time_diff > 0:
            bytes_per_sec = self.stats['bytes_transferred'] / time_diff
            return bytes_per_sec * 8  # bits per second
        return 0


# ========== 自定义特征处理器 ==========
class FeatureProcessor:
    """处理混合类型的特征（数值和类别）"""

    def __init__(self):
        self.numerical_features = ['duration', 'src_bytes', 'dst_bytes']
        self.categorical_features = ['protocol_type', 'service']
        self.scalers = {}
        for feat in self.numerical_features:
            self.scalers[feat] = preprocessing.StandardScaler()
        self.is_fitted = False
        self.n_samples = 0

    def _ensure_numeric(self, value):
        """确保值是数值类型"""
        if isinstance(value, (int, float)):
            return float(value)
        try:
            return float(value)
        except (ValueError, TypeError):
            return 0.0

    def learn_one(self, x):
        """更新标准化器的统计信息"""
        for feat in self.numerical_features:
            if feat in x:
                val = self._ensure_numeric(x[feat])
                self.scalers[feat].learn_one({feat: val})
        self.is_fitted = True
        self.n_samples += 1

    def transform_one(self, x):
        """转换单个样本"""
        transformed_x = {}

        for feat in self.numerical_features:
            if feat in x:
                val = self._ensure_numeric(x[feat])
                if self.is_fitted and self.n_samples > 1:
                    scaled = self.scalers[feat].transform_one({feat: val})
                    transformed_x[feat] = scaled[feat]
                else:
                    transformed_x[feat] = val
            else:
                transformed_x[feat] = 0.0

        for feat in self.categorical_features:
            if feat in x:
                transformed_x[feat] = str(x[feat])
            else:
                transformed_x[feat] = 'unknown'

        return transformed_x


# ========== 实时检测引擎 ==========
class RealTimeSecurityEngine:
    def __init__(self):
        self.model = None
        self.feature_processor = FeatureProcessor()
        self.is_trained = False
        self.metrics = {
            'accuracy': metrics.Accuracy(),
            'precision': metrics.WeightedPrecision(),
            'recall': metrics.WeightedRecall(),
            'f1': metrics.WeightedF1()
        }
        self.drift_detector = drift.ADWIN(delta=0.002)
        self.detection_history = []
        self.drift_events = []
        self.instance_count = 0
        self.start_time = time.time()
        self.attack_count = 0
        self.benign_count = 0

    def initialize_model(self, n_estimators=10, lambda_value=6.0):
        """初始化自适应随机森林 (ARF)"""
        arf_classifier = forest.ARFClassifier(
            n_models=n_estimators,
            max_features="sqrt",
            lambda_value=lambda_value,
            seed=42,
            grace_period=30,
            delta=0.01
        )
        self.model = arf_classifier
        self.is_trained = True
        return self.model

    def train_initial(self, X_train, y_train):
        """初始训练"""
        if not self.is_trained:
            self.initialize_model()

        progress_bar = st.progress(0)
        total = len(X_train)

        for idx, (idx_name, row) in enumerate(X_train.iterrows()):
            try:
                x = row.to_dict()
                y_true = y_train[idx_name]

                for feat in self.feature_processor.numerical_features:
                    if feat in x:
                        x[feat] = float(x[feat]) if x[feat] is not None else 0.0

                self.feature_processor.learn_one(x)
                x_processed = self.feature_processor.transform_one(x)
                self.model.learn_one(x_processed, y_true)

                if idx % max(1, total // 100) == 0:
                    progress_bar.progress(min(idx / total, 1.0))

            except Exception as e:
                continue

        progress_bar.progress(1.0)
        st.success(f"✅ 初始训练完成，共处理 {total} 条记录")
        return self.model

    def detect_single(self, features):
        """单条记录检测"""
        if not self.is_trained:
            return None, None

        try:
            for feat in self.feature_processor.numerical_features:
                if feat in features:
                    features[feat] = float(features[feat]) if features[feat] is not None else 0.0

            x_processed = self.feature_processor.transform_one(features)
            prediction = self.model.predict_one(x_processed)
            proba = self.model.predict_proba_one(x_processed)
            confidence = max(proba.values()) if proba else 0

            return prediction, confidence
        except Exception as e:
            return None, None

    def update_with_label(self, features, true_label):
        """用真实标签更新模型"""
        if not self.is_trained:
            return None

        try:
            for feat in self.feature_processor.numerical_features:
                if feat in features:
                    features[feat] = float(features[feat]) if features[feat] is not None else 0.0

            self.feature_processor.learn_one(features)
            x_processed = self.feature_processor.transform_one(features)
            prediction = self.model.predict_one(x_processed)

            if true_label == 'Attack':
                self.attack_count += 1
            else:
                self.benign_count += 1

            for metric in self.metrics.values():
                metric.update(true_label, prediction)

            error = int(prediction != true_label)
            self.drift_detector.update(error)

            if self.drift_detector.drift_detected:
                self.drift_events.append(self.instance_count)

            self.model.learn_one(x_processed, true_label)
            proba = self.model.predict_proba_one(x_processed)
            confidence = max(proba.values()) if proba else 0

            self.detection_history.append({
                'instance': self.instance_count,
                'true_label': true_label,
                'predicted': prediction,
                'confidence': confidence,
                'timestamp': datetime.now(),
                'is_correct': prediction == true_label
            })

            self.instance_count += 1
            return prediction
        except Exception as e:
            return None

    def get_current_metrics(self):
        """获取当前性能指标"""
        if self.instance_count == 0:
            return {'accuracy': 0, 'precision': 0, 'recall': 0, 'f1': 0, 'attack_rate': 0}

        return {
            'accuracy': self.metrics['accuracy'].get(),
            'precision': self.metrics['precision'].get(),
            'recall': self.metrics['recall'].get(),
            'f1': self.metrics['f1'].get(),
            'attack_rate': self.attack_count / self.instance_count if self.instance_count > 0 else 0
        }

    def get_uptime(self):
        return time.time() - self.start_time

    def reset(self):
        """重置引擎"""
        self.model = None
        self.feature_processor = FeatureProcessor()
        self.is_trained = False
        self.metrics = {
            'accuracy': metrics.Accuracy(),
            'precision': metrics.WeightedPrecision(),
            'recall': metrics.WeightedRecall(),
            'f1': metrics.WeightedF1()
        }
        self.drift_detector = drift.PageHinkley()
        self.detection_history = []
        self.drift_events = []
        self.instance_count = 0
        self.start_time = time.time()
        self.attack_count = 0
        self.benign_count = 0


# ========== 数据预处理函数 ==========
def preprocess_data(df):
    """预处理上传的数据"""
    label_columns = ['Label', 'label', 'Class', 'class', 'type', 'attack_type']
    label_col = None

    for col in label_columns:
        if col in df.columns:
            label_col = col
            break

    if label_col is None:
        st.error("❌ 未找到标签列！")
        return None, None

    X = df.drop(columns=[label_col])
    y = df[label_col].copy()
    y = y.apply(lambda x: 'Attack' if str(x).lower() != 'benign' else 'Benign')

    numerical_features = ['duration', 'src_bytes', 'dst_bytes']
    categorical_features = ['protocol_type', 'service']

    for feat in numerical_features:
        if feat not in X.columns:
            X[feat] = 0.0
        else:
            X[feat] = pd.to_numeric(X[feat], errors='coerce').fillna(0).astype(float)

    for feat in categorical_features:
        if feat not in X.columns:
            X[feat] = 'unknown'
        else:
            X[feat] = X[feat].astype(str).fillna('unknown')

    return X, y


# ========== 主应用 ==========
def main():
    # 初始化session state
    if 'engine' not in st.session_state:
        st.session_state.engine = RealTimeSecurityEngine()
    if 'packet_analyzer' not in st.session_state:
        st.session_state.packet_analyzer = NetworkPacketAnalyzer()
    if 'is_running' not in st.session_state:
        st.session_state.is_running = False
    if 'data_generator' not in st.session_state:
        st.session_state.data_generator = None
    if 'uploaded_data' not in st.session_state:
        st.session_state.uploaded_data = None
    if 'initial_trained' not in st.session_state:
        st.session_state.initial_trained = False
    if 'capture_mode' not in st.session_state:
        st.session_state.capture_mode = False

    # 侧边栏配置
    with st.sidebar:
        st.title("⚙️ 系统配置")

        # 模式选择
        st.subheader("🎯 运行模式")
        mode = st.radio("选择模式", ["模拟数据流", "上传CSV文件", "实时网络抓包"])

        if mode == "实时网络抓包":
            st.subheader("📡 抓包配置")

            # 获取网络接口
            try:
                interfaces = scapy.get_if_list()
                selected_interface = st.selectbox("网络接口", interfaces)
            except:
                selected_interface = st.text_input("网络接口", value="eth0")
                st.warning("无法自动获取网卡列表，请手动输入")

            filter_str = st.text_input("BPF过滤器", placeholder="例如: tcp port 80 or udp",
                                       help="Berkeley Packet Filter语法")
            packet_limit = st.number_input("抓包数量限制", min_value=0, max_value=10000, value=0, help="0表示无限制")

            if st.button("🎯 开始抓包", type="primary", use_container_width=True):
                with st.spinner("正在启动抓包..."):
                    st.session_state.packet_analyzer.start_capture(
                        interface=selected_interface,
                        filter_str=filter_str if filter_str else None,
                        packet_count=packet_limit
                    )
                    st.session_state.capture_mode = True
                    st.success("✅ 抓包已启动！")
                    st.rerun()

            if st.session_state.capture_mode:
                if st.button("🛑 停止抓包", type="secondary", use_container_width=True):
                    st.session_state.packet_analyzer.stop_capture()
                    st.session_state.capture_mode = False
                    st.rerun()

        st.divider()

        st.subheader("📊 模型参数")
        n_estimators = st.slider("集成模型数量 (ARF)", 5, 20, 10)
        lambda_value = st.slider("泊松参数 λ", 1.0, 10.0, 6.0)

        st.subheader("🎯 检测参数")
        confidence_threshold = st.slider("置信度阈值", 0.5, 1.0, 0.7)

        if mode != "实时网络抓包":
            attack_rate = st.slider("模拟攻击率", 0.01, 0.5, 0.1)
            speed = st.slider("数据处理速度 (条/秒)", 1, 30, 10)

        st.divider()

        # 数据源处理
        if mode == "上传CSV文件":
            uploaded_file = st.file_uploader("上传CSV文件", type=['csv'])
            if uploaded_file is not None:
                try:
                    df = pd.read_csv(uploaded_file)
                    st.info("📊 数据预览:")
                    st.dataframe(df.head())
                    X, y = preprocess_data(df)
                    if X is not None:
                        st.session_state.uploaded_data = (X, y)
                        st.success(f"✅ 已加载 {len(X)} 条记录")
                except Exception as e:
                    st.error(f"读取文件错误: {e}")

        st.divider()

        # 系统控制
        st.subheader("🎮 系统控制")
        if not st.session_state.is_running:
            if st.button("🚀 启动检测系统", type="primary", use_container_width=True):
                with st.spinner("正在初始化系统..."):
                    st.session_state.engine.reset()
                    st.session_state.engine.initialize_model(n_estimators, lambda_value)

                    if st.session_state.uploaded_data is not None:
                        st.info("正在进行初始训练...")
                        X_train, y_train = st.session_state.uploaded_data
                        st.session_state.engine.train_initial(X_train, y_train)
                        st.session_state.initial_trained = True
                    else:
                        st.session_state.initial_trained = False

                    st.session_state.is_running = True
                    st.success("✅ 系统已启动！")
                    st.rerun()
        else:
            if st.button("🛑 停止系统", type="secondary", use_container_width=True):
                st.session_state.is_running = False
                st.session_state.initial_trained = False
                if st.session_state.capture_mode:
                    st.session_state.packet_analyzer.stop_capture()
                    st.session_state.capture_mode = False
                st.rerun()

        if st.button("🔄 重置系统", use_container_width=True):
            st.session_state.engine.reset()
            st.session_state.is_running = False
            st.session_state.uploaded_data = None
            if st.session_state.capture_mode:
                st.session_state.packet_analyzer.stop_capture()
                st.session_state.capture_mode = False
            st.success("系统已重置")
            st.rerun()

        # 系统状态
        st.divider()
        st.subheader("📊 系统状态")
        if st.session_state.is_running:
            st.markdown("**状态:** <span class='status-online'>● 运行中</span>", unsafe_allow_html=True)
        else:
            st.markdown("**状态:** <span class='status-offline'>● 已停止</span>", unsafe_allow_html=True)

        if st.session_state.engine.instance_count > 0:
            st.metric("已处理实例", f"{st.session_state.engine.instance_count:,}")
            uptime = st.session_state.engine.get_uptime()
            st.metric("运行时间", f"{uptime:.1f} 秒")

    # 主界面
    st.markdown('<div class="main-header">🛡️ 实时安全检测系统</div>', unsafe_allow_html=True)

    # 显示当前模式
    if mode == "实时网络抓包":
        st.info("🔍 当前模式: 实时网络抓包分析")
        if st.session_state.capture_mode:
            st.success("📡 正在捕获网络数据包...")
        else:
            st.warning("⏸️ 抓包未启动，请在侧边栏点击'开始抓包'")

    # 创建四列布局显示指标
    col1, col2, col3, col4 = st.columns(4)
    with col1:
        metrics = st.session_state.engine.get_current_metrics()
        st.metric("🎯 准确率", f"{metrics['accuracy'] * 100:.2f}%")
    with col2:
        st.metric("📈 精确率", f"{metrics['precision'] * 100:.2f}%")
    with col3:
        st.metric("📉 召回率", f"{metrics['recall'] * 100:.2f}%")
    with col4:
        st.metric("🏆 F1分数", f"{metrics['f1'] * 100:.2f}%")

    # 网络抓包统计面板
    if mode == "实时网络抓包":
        st.subheader("📊 网络流量统计")

        col_stats1, col_stats2, col_stats3, col_stats4 = st.columns(4)
        stats = st.session_state.packet_analyzer.get_stats()

        with col_stats1:
            st.metric("总数据包", stats['total_packets'])
            st.metric("TCP包", stats['tcp_packets'])
        with col_stats2:
            st.metric("UDP包", stats['udp_packets'])
            st.metric("ICMP包", stats['icmp_packets'])
        with col_stats3:
            st.metric("独立IP数", stats['unique_ips_count'])
            st.metric("平均包大小", f"{stats['avg_packet_size']:.0f} bytes")
        with col_stats4:
            bandwidth = st.session_state.packet_analyzer.get_bandwidth_usage()
            st.metric("当前带宽", f"{bandwidth / 1000:.2f} Kbps")
            st.metric("总流量", f"{stats['bytes_transferred'] / 1024:.2f} KB")

        # 协议分布图
        if stats['protocols']:
            fig_protocol = go.Figure(data=[go.Pie(
                labels=list(stats['protocols'].keys()),
                values=list(stats['protocols'].values()),
                hole=.3
            )])
            fig_protocol.update_layout(title="协议分布")
            st.plotly_chart(fig_protocol, use_container_width=True)

        # 端口分布
        if stats['ports']:
            top_ports = dict(sorted(stats['ports'].items(), key=lambda x: x[1], reverse=True)[:10])
            fig_ports = go.Figure(data=[go.Bar(
                x=[str(p) for p in top_ports.keys()],
                y=list(top_ports.values()),
                marker_color='lightblue'
            )])
            fig_ports.update_layout(title="Top 10 端口", xaxis_title="端口", yaxis_title="连接数")
            st.plotly_chart(fig_ports, use_container_width=True)

    # 实时检测面板
    st.subheader("🔍 实时检测面板")
    left_col, right_col = st.columns([2, 1])

    with right_col:
        st.subheader("🚨 最新告警")
        alert_placeholder = st.empty()

        if st.session_state.engine.detection_history:
            latest = st.session_state.engine.detection_history[-1]
            if latest['true_label'] == 'Attack' and latest['confidence'] >= confidence_threshold:
                alert_placeholder.markdown(f"""
                <div class="alert-critical">
                    ⚠️ 攻击告警！<br>
                    时间: {latest['timestamp'].strftime('%H:%M:%S')}<br>
                    置信度: {latest['confidence'] * 100:.1f}%<br>
                    预测: {latest['predicted']}
                </div>
                """, unsafe_allow_html=True)
            else:
                alert_placeholder.info("暂无告警")

        if st.session_state.engine.drift_events:
            st.warning(f"📊 概念漂移检测: {len(st.session_state.engine.drift_events)} 次")

    # 实时数据流处理
    if st.session_state.is_running:
        table_placeholder = st.empty()
        status_placeholder = st.empty()

        try:
            if mode == "实时网络抓包" and st.session_state.capture_mode:
                # 从抓包队列获取数据
                while st.session_state.is_running:
                    packet_info = st.session_state.packet_analyzer.get_latest_packet()
                    if packet_info is None:
                        time.sleep(0.1)
                        continue

                    features = packet_info['features']

                    # 检测
                    prediction, confidence = st.session_state.engine.detect_single(features)

                    # 这里需要根据实际情况设置标签（抓包数据没有真实标签）
                    # 可以基于规则或历史数据判断
                    true_label = 'Attack' if prediction == 'Attack' else 'Benign'

                    st.session_state.engine.update_with_label(features, true_label)

                    # 显示检测结果
                    if prediction == 'Attack' and confidence >= confidence_threshold:
                        status_placeholder.markdown(f"""
                        <div class="alert-critical">
                            ⚠️ 检测到攻击流量！<br>
                            时间: {packet_info['timestamp'].strftime('%H:%M:%S.%f')[:-3]}<br>
                            置信度: {confidence * 100:.1f}%<br>
                            协议: {features['protocol_type']}<br>
                            服务: {features['service']}
                        </div>
                        """, unsafe_allow_html=True)

                    # 更新表格
                    recent = st.session_state.engine.detection_history[-20:]
                    if recent:
                        df_display = pd.DataFrame(recent)
                        df_display['timestamp'] = df_display['timestamp'].dt.strftime('%H:%M:%S')
                        df_display['confidence'] = df_display['confidence'].apply(lambda x: f"{x * 100:.1f}%")
                        table_placeholder.dataframe(
                            df_display[['timestamp', 'true_label', 'predicted', 'confidence']],
                            use_container_width=True
                        )

                    # 更新指标
                    current_metrics = st.session_state.engine.get_current_metrics()
                    with col1:
                        st.metric("🎯 准确率", f"{current_metrics['accuracy'] * 100:.2f}%")
                    with col2:
                        st.metric("📈 精确率", f"{current_metrics['precision'] * 100:.2f}%")
                    with col3:
                        st.metric("📉 召回率", f"{current_metrics['recall'] * 100:.2f}%")
                    with col4:
                        st.metric("🏆 F1分数", f"{current_metrics['f1'] * 100:.2f}%")

            elif mode == "模拟数据流":
                if st.session_state.data_generator is None:
                    st.session_state.data_generator = DataSimulator().generate_stream(attack_rate, speed)

                for features, true_label in st.session_state.data_generator:
                    if not st.session_state.is_running:
                        break

                    prediction, confidence = st.session_state.engine.detect_single(features)
                    st.session_state.engine.update_with_label(features, true_label)

                    # 显示结果
                    if prediction == 'Attack' and confidence >= confidence_threshold:
                        status_placeholder.markdown(f"""
                        <div class="alert-critical">
                            ⚠️ 检测到攻击！<br>
                            时间: {datetime.now().strftime('%H:%M:%S.%f')[:-3]}<br>
                            置信度: {confidence * 100:.1f}%<br>
                            特征: {features}
                        </div>
                        """, unsafe_allow_html=True)

                    # 更新显示
                    recent = st.session_state.engine.detection_history[-20:]
                    if recent:
                        df_display = pd.DataFrame(recent)
                        df_display['timestamp'] = df_display['timestamp'].dt.strftime('%H:%M:%S')
                        df_display['confidence'] = df_display['confidence'].apply(lambda x: f"{x * 100:.1f}%")
                        table_placeholder.dataframe(
                            df_display[['timestamp', 'true_label', 'predicted', 'confidence']],
                            use_container_width=True
                        )

                    current_metrics = st.session_state.engine.get_current_metrics()
                    with col1:
                        st.metric("🎯 准确率", f"{current_metrics['accuracy'] * 100:.2f}%")
                    with col2:
                        st.metric("📈 精确率", f"{current_metrics['precision'] * 100:.2f}%")
                    with col3:
                        st.metric("📉 召回率", f"{current_metrics['recall'] * 100:.2f}%")
                    with col4:
                        st.metric("🏆 F1分数", f"{current_metrics['f1'] * 100:.2f}%")

                    time.sleep(1 / speed)

            elif mode == "上传CSV文件" and st.session_state.uploaded_data is not None:
                X_test, y_test = st.session_state.uploaded_data
                for idx in range(len(X_test)):
                    if not st.session_state.is_running:
                        break

                    features = X_test.iloc[idx].to_dict()
                    true_label = y_test.iloc[idx]

                    prediction, confidence = st.session_state.engine.detect_single(features)
                    st.session_state.engine.update_with_label(features, true_label)

                    # 显示进度
                    if idx % 10 == 0:
                        status_placeholder.info(f"处理进度: {idx + 1}/{len(X_test)}")

                    # 更新表格
                    if idx % 5 == 0:
                        recent = st.session_state.engine.detection_history[-20:]
                        if recent:
                            df_display = pd.DataFrame(recent)
                            df_display['timestamp'] = df_display['timestamp'].dt.strftime('%H:%M:%S')
                            df_display['confidence'] = df_display['confidence'].apply(lambda x: f"{x * 100:.1f}%")
                            table_placeholder.dataframe(
                                df_display[['timestamp', 'true_label', 'predicted', 'confidence']],
                                use_container_width=True
                            )

                        current_metrics = st.session_state.engine.get_current_metrics()
                        with col1:
                            st.metric("🎯 准确率", f"{current_metrics['accuracy'] * 100:.2f}%")
                        with col2:
                            st.metric("📈 精确率", f"{current_metrics['precision'] * 100:.2f}%")
                        with col3:
                            st.metric("📉 召回率", f"{current_metrics['recall'] * 100:.2f}%")
                        with col4:
                            st.metric("🏆 F1分数", f"{current_metrics['f1'] * 100:.2f}%")

                    time.sleep(0.1)

                st.success("✅ 数据处理完成！")
                st.session_state.is_running = False

        except StopIteration:
            st.info("数据流已结束")
        except Exception as e:
            st.error(f"处理错误: {e}")
            st.session_state.is_running = False

    # 性能图表
    if st.session_state.engine.detection_history:
        st.subheader("📈 性能分析")
        history_df = pd.DataFrame(st.session_state.engine.detection_history)

        fig_col1, fig_col2 = st.columns(2)

        with fig_col1:
            correct_cumsum = history_df['is_correct'].cumsum()
            accuracy_cumulative = correct_cumsum / (np.arange(len(history_df)) + 1)

            fig1 = go.Figure()
            fig1.add_trace(go.Scatter(
                x=history_df['instance'],
                y=accuracy_cumulative,
                mode='lines',
                name='累积准确率',
                line=dict(color='#00ff00', width=2)
            ))

            for drift in st.session_state.engine.drift_events:
                fig1.add_vline(x=drift, line_dash="dash", line_color="red",
                               annotation_text="漂移", annotation_position="top")

            fig1.update_layout(title='模型准确率趋势', xaxis_title='实例数', yaxis_title='准确率', yaxis_range=[0, 1])
            st.plotly_chart(fig1, use_container_width=True)

        with fig_col2:
            fig2 = go.Figure()
            fig2.add_trace(go.Histogram(
                x=history_df['confidence'],
                nbinsx=20,
                marker_color='#ff9900',
                name='置信度分布'
            ))
            fig2.add_vline(x=confidence_threshold, line_dash="dash", line_color="red",
                           annotation_text="阈值", annotation_position="top")
            fig2.update_layout(title='检测置信度分布', xaxis_title='置信度', yaxis_title='频次')
            st.plotly_chart(fig2, use_container_width=True)

    st.divider()
    st.caption("🛡️ 实时安全检测系统 | 基于自适应随机森林 (ARF) | 支持网络抓包分析")


class DataSimulator:
    def __init__(self):
        self.attack_patterns = [
            {'duration': 0.1, 'src_bytes': 5000, 'dst_bytes': 100, 'protocol_type': 'tcp', 'service': 'http'},
            {'duration': 0.5, 'src_bytes': 10000, 'dst_bytes': 50, 'protocol_type': 'tcp', 'service': 'https'},
            {'duration': 0.05, 'src_bytes': 20000, 'dst_bytes': 10, 'protocol_type': 'udp', 'service': 'dns'},
            {'duration': 2.0, 'src_bytes': 100, 'dst_bytes': 50000, 'protocol_type': 'tcp', 'service': 'ftp'}
        ]

        self.benign_patterns = [
            {'duration': 0.01, 'src_bytes': 100, 'dst_bytes': 500, 'protocol_type': 'tcp', 'service': 'http'},
            {'duration': 0.02, 'src_bytes': 200, 'dst_bytes': 1000, 'protocol_type': 'tcp', 'service': 'https'},
            {'duration': 0.005, 'src_bytes': 50, 'dst_bytes': 200, 'protocol_type': 'udp', 'service': 'dns'},
            {'duration': 0.03, 'src_bytes': 300, 'dst_bytes': 1500, 'protocol_type': 'tcp', 'service': 'smtp'}
        ]

    def generate_stream(self, attack_rate=0.1, speed=1):
        """生成模拟数据流"""
        while True:
            is_attack = random.random() < attack_rate
            if is_attack:
                pattern = random.choice(self.attack_patterns)
                label = 'Attack'
            else:
                pattern = random.choice(self.benign_patterns)
                label = 'Benign'

            features = {
                'duration': max(0.0, float(pattern['duration'] + random.gauss(0, 0.01))),
                'src_bytes': max(0, int(pattern['src_bytes'] + random.randint(-100, 100))),
                'dst_bytes': max(0, int(pattern['dst_bytes'] + random.randint(-50, 50))),
                'protocol_type': str(pattern['protocol_type']),
                'service': str(pattern['service'])
            }
            yield features, label
            time.sleep(1 / speed)


if __name__ == "__main__":
    main()