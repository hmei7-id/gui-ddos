# Part 1/4
# Integrated & extended GUI (part 1)
# Reference original uploaded file: :contentReference[oaicite:1]{index=1}

import sys
import os
import subprocess
import threading
import random
import requests
import re
import psutil
import time
import socket
import json
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor
from PyQt5.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
                             QTabWidget, QLabel, QLineEdit, QPushButton, QSpinBox,
                             QTextEdit, QFileDialog, QGroupBox, QFormLayout, QMessageBox,
                             QComboBox, QProgressBar, QTableWidget, QTableWidgetItem, QHeaderView, QCheckBox)
from PyQt5.QtCore import Qt, QTimer, pyqtSignal, QThread, QDateTime, QSize
from PyQt5.QtGui import QFont, QColor, QIcon, QPixmap
from PyQt5.QtChart import QChart, QChartView, QLineSeries, QValueAxis, QDateTimeAxis

# Helper: settings file path
SETTINGS_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "setting.json")


# ================== Website Status Checker Thread ==================
class WebsiteStatusThread(QThread):
    update_status = pyqtSignal(str)

    def __init__(self, url):
        super().__init__()
        self.url = url
        self.running = True

    def run(self):
        while self.running:
            try:
                r = requests.get(self.url, timeout=5)
                status = f"UP ({r.status_code} {r.reason})"
            except Exception as e:
                status = f"DOWN ({str(e)})"
            self.update_status.emit(status)
            self.msleep(3000)

    def stop(self):
        self.running = False
        self.quit()
        self.wait()


# ================== Statistik Serangan ==================
class AttackStatsWidget(QWidget):
    def __init__(self):
        super().__init__()
        self.initUI()

    def initUI(self):
        layout = QVBoxLayout()
        title = QLabel("Statistik Serangan Real-time")
        title.setFont(QFont("Arial", 14, QFont.Bold))
        title.setAlignment(Qt.AlignCenter)
        layout.addWidget(title)

        # chart
        self.chart = QChart()
        self.chart.setTitle("Requests per Second")
        self.chart.legend().setVisible(True)

        self.series = QLineSeries()
        self.series.setName("RPS")
        self.chart.addSeries(self.series)

        self.axis_x = QDateTimeAxis()
        self.axis_x.setFormat("hh:mm:ss")
        self.axis_x.setTitleText("Waktu")

        self.axis_y = QValueAxis()
        self.axis_y.setTitleText("Requests")

        self.chart.addAxis(self.axis_x, Qt.AlignBottom)
        self.chart.addAxis(self.axis_y, Qt.AlignLeft)
        self.series.attachAxis(self.axis_x)
        self.series.attachAxis(self.axis_y)

        self.chart_view = QChartView(self.chart)
        self.chart_view.setMinimumHeight(220)
        layout.addWidget(self.chart_view)

        stats_layout = QHBoxLayout()
        self.requests_label = QLabel("Total Requests: 0")
        self.success_label = QLabel("Success: 0")
        self.failed_label = QLabel("Failed: 0")
        self.status_label = QLabel("Website Status: Unknown")
        self.status_label.setStyleSheet("font-weight: bold; color: blue;")

        # consistent fonts
        for lbl in (self.requests_label, self.success_label, self.failed_label, self.status_label):
            lbl.setFont(QFont("Arial", 10))
        stats_layout.addWidget(self.requests_label)
        stats_layout.addWidget(self.success_label)
        stats_layout.addWidget(self.failed_label)
        stats_layout.addWidget(self.status_label)

        layout.addLayout(stats_layout)
        self.setLayout(layout)

        self.request_data = []
        self.total_requests = 0
        self.success_count = 0
        self.failed_count = 0

    def update_stats(self, requests, success, failed):
        self.total_requests += requests
        self.success_count += success
        self.failed_count += failed

        current_time = QDateTime.currentDateTime()
        self.request_data.append((current_time, requests))

        self.requests_label.setText(f"Total Requests: {self.total_requests}")
        self.success_label.setText(f"Success: {self.success_count}")
        self.failed_label.setText(f"Failed: {self.failed_count}")

        if len(self.request_data) > 120:  # keep more points but bounded
            self.request_data = self.request_data[-120:]

        self.series.clear()
        min_y, max_y = 0, 0
        for t, value in self.request_data:
            self.series.append(t.toMSecsSinceEpoch(), value)
            if value > max_y:
                max_y = value

        # set ranges safely
        if self.request_data:
            self.axis_x.setRange(self.request_data[0][0], self.request_data[-1][0])
        self.axis_y.setRange(0, max(max_y * 1.1, 10))


    def update_status(self, status):
        if "UP" in status:
            self.status_label.setStyleSheet("font-weight: bold; color: green;")
        else:
            self.status_label.setStyleSheet("font-weight: bold; color: red;")
        self.status_label.setText(f"Website Status: {status}")


# ================== Log Widget dengan ANSI Color Support ==================
class LogWidget(QTextEdit):
    ansi_pattern = re.compile(r'\x1b\[(\d+)(;\d+)*m')

    ansi_colors = {
        30: QColor("black"),
        31: QColor("red"),
        32: QColor("green"),
        33: QColor("yellow"),
        34: QColor("blue"),
        35: QColor("magenta"),
        36: QColor("cyan"),
        37: QColor("white"),
        90: QColor("gray"),
    }

    def __init__(self):
        super().__init__()
        self.setReadOnly(True)
        self.setFont(QFont("Courier", 10))
        # keep its own background to avoid theme overriding ANSI colors
        self.setStyleSheet("background-color: #1e1e1e; color: white;")
        # ensure consistent size policy
        self.setMinimumHeight(200)

    def parse_ansi(self, text):
        pos = 0
        for match in self.ansi_pattern.finditer(text):
            start, end = match.span()
            code = int(match.group(1))
            if start > pos:
                self.insertPlainText(text[pos:start])
            if code in self.ansi_colors:
                self.setTextColor(self.ansi_colors[code])
            elif code == 0:
                self.setTextColor(QColor("white"))
            pos = end
        if pos < len(text):
            self.insertPlainText(text[pos:])

    def append_log(self, message, color=None):
        # preserve current cursor and append; do not alter ANSI parsing behavior
        cursor = self.textCursor()
        cursor.movePosition(cursor.End)
        self.setTextCursor(cursor)

        if self.ansi_pattern.search(message):
            self.parse_ansi(message)
            self.insertPlainText("\n")
        else:
            if color:
                self.setTextColor(color)
            self.insertPlainText(f"[{datetime.now().strftime('%H:%M:%S')}] {message}\n")

        self.verticalScrollBar().setValue(self.verticalScrollBar().maximum())
        self.setTextColor(QColor("white"))


# ================== Proxy Checker Tab ==================
class ProxyCheckerWidget(QWidget):
    def __init__(self):
        super().__init__()
        self.initUI()

    def initUI(self):
        layout = QVBoxLayout()

        self.load_btn = QPushButton("Load Proxy File")
        self.check_btn = QPushButton("Check Proxies")
        self.check_btn.setEnabled(False)

        self.table = QTableWidget()
        self.table.setColumnCount(5)
        self.table.setHorizontalHeaderLabels(["IP", "Port", "Status", "Ping (ms)", "Country"])
        self.table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)

        btn_layout = QHBoxLayout()
        btn_layout.addWidget(self.load_btn)
        btn_layout.addWidget(self.check_btn)

        layout.addLayout(btn_layout)
        layout.addWidget(self.table)
        self.setLayout(layout)

        self.proxies = []
        self.load_btn.clicked.connect(self.load_file)
        self.check_btn.clicked.connect(self.check_proxies)

    def load_file(self):
        file_path, _ = QFileDialog.getOpenFileName(self, "Select Proxy File", "", "Text Files (*.txt)")
        if file_path:
            with open(file_path, "r") as f:
                self.proxies = [line.strip() for line in f if line.strip()]
            self.table.setRowCount(len(self.proxies))
            for i, proxy in enumerate(self.proxies):
                parts = proxy.split(":")
                ip, port = (parts[0], parts[1]) if len(parts) >= 2 else (proxy, "-")
                self.table.setItem(i, 0, QTableWidgetItem(ip))
                self.table.setItem(i, 1, QTableWidgetItem(port))
            self.check_btn.setEnabled(True)

    def check_proxies(self):
        def check(proxy, row):
            parts = proxy.split(":")
            if len(parts) < 2:
                self.table.setItem(row, 2, QTableWidgetItem("Invalid"))
                return
            ip, port = parts[0], int(parts[1])
            start = time.time()
            try:
                s = socket.socket()
                s.settimeout(2)
                s.connect((ip, port))
                ping = int((time.time() - start) * 1000)
                self.table.setItem(row, 2, QTableWidgetItem("Alive"))
                self.table.setItem(row, 3, QTableWidgetItem(str(ping)))
                self.table.setItem(row, 4, QTableWidgetItem("Unknown"))
                s.close()
            except:
                self.table.setItem(row, 2, QTableWidgetItem("Dead"))
                self.table.setItem(row, 3, QTableWidgetItem("-"))
                self.table.setItem(row, 4, QTableWidgetItem("-"))

        with ThreadPoolExecutor(max_workers=20) as executor:
            for i, proxy in enumerate(self.proxies):
                executor.submit(check, proxy, i)
# Part 2/4
# Resource Monitor chart + Settings (save/load) + SpeedTest tab

# ================== System Resource Monitor (with chart + icons) ==================
class ResourceMonitorWidget(QWidget):
    def __init__(self):
        super().__init__()
        self.initUI()
        # data buffers
        self.cpu_history = []
        self.ram_history = []
        self.net_history = []
        self.max_points = 60

    def initUI(self):
        layout = QVBoxLayout()

        # Top row: icons and labels
        top_row = QHBoxLayout()
        # using emoji icons for simplicity; fontscale big
        self.icon_cpu = QLabel("💻")
        self.icon_cpu.setFont(QFont("Arial", 24))
        self.cpu_label = QLabel("CPU: 0%")
        self.cpu_label.setFont(QFont("Arial", 11, QFont.Bold))

        self.icon_ram = QLabel("🧠")
        self.icon_ram.setFont(QFont("Arial", 24))
        self.ram_label = QLabel("RAM: 0%")
        self.ram_label.setFont(QFont("Arial", 11, QFont.Bold))

        self.icon_net = QLabel("🌐")
        self.icon_net.setFont(QFont("Arial", 24))
        self.net_label = QLabel("Net: 0 KB/s")
        self.net_label.setFont(QFont("Arial", 11, QFont.Bold))

        top_row.addWidget(self.icon_cpu)
        top_row.addWidget(self.cpu_label)
        top_row.addSpacing(20)
        top_row.addWidget(self.icon_ram)
        top_row.addWidget(self.ram_label)
        top_row.addSpacing(20)
        top_row.addWidget(self.icon_net)
        top_row.addWidget(self.net_label)
        top_row.addStretch()
        layout.addLayout(top_row)

        # Chart
        self.chart = QChart()
        self.chart.setTitle("System Usage (last 60s)")
        self.chart_view = QChartView(self.chart)
        self.chart_view.setMinimumHeight(180)

        # series
        self.cpu_series = QLineSeries(); self.cpu_series.setName("CPU")
        self.ram_series = QLineSeries(); self.ram_series.setName("RAM")
        self.net_series = QLineSeries(); self.net_series.setName("Net (KB/s)")
        # add them
        self.chart.addSeries(self.cpu_series)
        self.chart.addSeries(self.ram_series)
        self.chart.addSeries(self.net_series)

        # axes
        self.axis_x = QDateTimeAxis(); self.axis_x.setFormat("hh:mm:ss"); self.axis_x.setTitleText("Time")
        self.axis_y = QValueAxis(); self.axis_y.setTitleText("Value")
        self.chart.addAxis(self.axis_x, Qt.AlignBottom)
        self.chart.addAxis(self.axis_y, Qt.AlignLeft)
        self.cpu_series.attachAxis(self.axis_x); self.cpu_series.attachAxis(self.axis_y)
        self.ram_series.attachAxis(self.axis_x); self.ram_series.attachAxis(self.axis_y)
        self.net_series.attachAxis(self.axis_x); self.net_series.attachAxis(self.axis_y)

        # color styling by series (chart palette)
        # QChart/QLineSeries colors adopt pen settings:
        from PyQt5.QtGui import QPen
        self.cpu_series.setPen(QPen(QColor("#FF7F50"), 2))   # coral
        self.ram_series.setPen(QPen(QColor("#7CFC00"), 2))   # lawn green
        self.net_series.setPen(QPen(QColor("#1E90FF"), 2))   # dodger blue

        layout.addWidget(self.chart_view)
        self.setLayout(layout)

        # network counters baseline
        self.net_old = psutil.net_io_counters()
        # timer to update
        self.timer = QTimer()
        self.timer.timeout.connect(self.update_stats)
        self.timer.start(1000)

    def update_stats(self):
        cpu = psutil.cpu_percent()
        ram = psutil.virtual_memory().percent
        net_new = psutil.net_io_counters()
        sent = (net_new.bytes_sent - self.net_old.bytes_sent) / 1024.0
        recv = (net_new.bytes_recv - self.net_old.bytes_recv) / 1024.0
        net_rate = sent + recv  # KB since last second approx

        self.net_old = net_new

        # update labels
        self.cpu_label.setText(f"CPU: {cpu:.1f}%")
        self.ram_label.setText(f"RAM: {ram:.1f}%")
        self.net_label.setText(f"Net: {net_rate:.1f} KB/s")

        now = QDateTime.currentDateTime()
        # append history
        self.cpu_history.append((now, cpu))
        self.ram_history.append((now, ram))
        self.net_history.append((now, net_rate))
        if len(self.cpu_history) > self.max_points:
            self.cpu_history = self.cpu_history[-self.max_points:]
            self.ram_history = self.ram_history[-self.max_points:]
            self.net_history = self.net_history[-self.max_points:]

        # update series
        self.cpu_series.clear(); self.ram_series.clear(); self.net_series.clear()
        max_y = 10
        for i, (t, v) in enumerate(self.cpu_history):
            self.cpu_series.append(t.toMSecsSinceEpoch(), v)
            max_y = max(max_y, v)
        for t, v in self.ram_history:
            self.ram_series.append(t.toMSecsSinceEpoch(), v)
            max_y = max(max_y, v)
        for t, v in self.net_history:
            self.net_series.append(t.toMSecsSinceEpoch(), v)
            max_y = max(max_y, v)
        if self.cpu_history:
            self.axis_x.setRange(self.cpu_history[0][0], self.cpu_history[-1][0])
        self.axis_y.setRange(0, max_y * 1.2)


# ================== Settings Tab (with save/load to setting.json) ==================
class SettingsWidget(QWidget):
    def __init__(self):
        super().__init__()
        self.initUI()

    def initUI(self):
        layout = QFormLayout()

        self.theme_select = QComboBox()
        self.theme_select.addItems(["Light", "Dark"])

        self.default_threads = QSpinBox(); self.default_threads.setRange(1, 100); self.default_threads.setValue(5)
        self.default_rate = QSpinBox(); self.default_rate.setRange(1, 10000); self.default_rate.setValue(100)
        self.default_time = QSpinBox(); self.default_time.setRange(1, 3600); self.default_time.setValue(60)

        self.save_log_checkbox = QCheckBox("Auto-save logs after attack")

        # Save button
        self.save_btn = QPushButton("Save Settings")
        self.save_btn.setFixedWidth(140)

        layout.addRow("Theme:", self.theme_select)
        layout.addRow("Default Threads:", self.default_threads)
        layout.addRow("Default Rate:", self.default_rate)
        layout.addRow("Default Time:", self.default_time)
        layout.addRow(self.save_log_checkbox)
        layout.addRow(self.save_btn)

        self.setLayout(layout)

    def to_dict(self):
        return {
            "theme": self.theme_select.currentText(),
            "default_threads": self.default_threads.value(),
            "default_rate": self.default_rate.value(),
            "default_time": self.default_time.value(),
            "autosave_log": self.save_log_checkbox.isChecked()
        }

    def load_from_dict(self, d):
        try:
            if "theme" in d:
                idx = self.theme_select.findText(d.get("theme", "Light"))
                if idx != -1:
                    self.theme_select.setCurrentIndex(idx)
            if "default_threads" in d:
                self.default_threads.setValue(d.get("default_threads", 5))
            if "default_rate" in d:
                self.default_rate.setValue(d.get("default_rate", 100))
            if "default_time" in d:
                self.default_time.setValue(d.get("default_time", 60))
            if "autosave_log" in d:
                self.save_log_checkbox.setChecked(d.get("autosave_log", False))
        except Exception:
            pass


# ================== Speed Test Worker & Widget ==================
class SpeedTestThread(QThread):
    update_result = pyqtSignal(dict)
    progress = pyqtSignal(str)

    def run(self):
        # Try multiple CLIs: speedtest-cli or speedtest
        # Will run as subprocess to avoid blocking; parse JSON if available
        try:
            self.progress.emit("Running speedtest (trying speedtest-cli)...")
            proc = subprocess.run(["speedtest-cli", "--json"], capture_output=True, text=True, timeout=180)
            if proc.returncode == 0 and proc.stdout:
                data = json.loads(proc.stdout)
                self.update_result.emit({
                    "ping": data.get("ping"),
                    "download": data.get("download") / 1e6 if data.get("download") else None,  # Mbps
                    "upload": data.get("upload") / 1e6 if data.get("upload") else None
                })
                return
        except Exception:
            pass

        # try 'speedtest' (Ookla) if available
        try:
            self.progress.emit("Trying 'speedtest' cli...")
            proc = subprocess.run(["speedtest", "--format=json"], capture_output=True, text=True, timeout=180)
            if proc.returncode == 0 and proc.stdout:
                data = json.loads(proc.stdout)
                ping = data.get("ping", {}).get("latency") if isinstance(data.get("ping"), dict) else data.get("ping")
                download = data.get("download", {}).get("bandwidth") if isinstance(data.get("download"), dict) else data.get("download")
                upload = data.get("upload", {}).get("bandwidth") if isinstance(data.get("upload"), dict) else data.get("upload")
                # Ookla reports bandwidth in bits/sec
                self.update_result.emit({
                    "ping": ping,
                    "download": (download / 1e6) if download else None,
                    "upload": (upload / 1e6) if upload else None
                })
                return
        except Exception:
            pass

        self.progress.emit("No CLI available. Using simple HTTP test...")
        # fallback: simple HTTP download test (low accuracy)
        try:
            test_url = "https://speed.hetzner.de/100MB.bin"  # may fail if offline
            t0 = time.time()
            r = requests.get(test_url, stream=True, timeout=10)
            total = 0
            for chunk in r.iter_content(chunk_size=1024*64):
                total += len(chunk)
                if time.time() - t0 > 5:  # measure 5 seconds only
                    break
            dt = time.time() - t0
            mbps = (total * 8) / (dt * 1e6) if dt > 0 else None
            self.update_result.emit({"ping": None, "download": mbps, "upload": None})
        except Exception as e:
            self.update_result.emit({"error": str(e)})


class SpeedTestWidget(QWidget):
    def __init__(self):
        super().__init__()
        self.initUI()
        self.thread = None

    def initUI(self):
        layout = QVBoxLayout()
        title = QLabel("Internet Speed Test")
        title.setFont(QFont("Arial", 14, QFont.Bold))
        layout.addWidget(title)

        self.run_btn = QPushButton("Run Speed Test")
        self.run_btn.setFixedWidth(160)
        self.status_label = QLabel("Idle")
        self.ping_label = QLabel("Ping: - ms")
        self.download_label = QLabel("Download: - Mbps")
        self.upload_label = QLabel("Upload: - Mbps")

        layout.addWidget(self.run_btn)
        layout.addWidget(self.status_label)
        layout.addWidget(self.ping_label)
        layout.addWidget(self.download_label)
        layout.addWidget(self.upload_label)
        layout.addStretch()
        self.setLayout(layout)

        self.run_btn.clicked.connect(self.run_test)

    def run_test(self):
        if self.thread and self.thread.isRunning():
            QMessageBox.information(self, "Speed Test", "Speed test already running")
            return
        self.thread = SpeedTestThread()
        self.thread.update_result.connect(self.on_result)
        self.thread.progress.connect(lambda s: self.status_label.setText(s))
        self.status_label.setText("Starting...")
        self.thread.start()
        self.run_btn.setEnabled(False)

    def on_result(self, data):
        self.run_btn.setEnabled(True)
        if data.get("error"):
            self.status_label.setText(f"Error: {data['error']}")
            return
        ping = data.get("ping")
        dl = data.get("download")
        ul = data.get("upload")
        self.status_label.setText("Finished")
        self.ping_label.setText(f"Ping: {ping if ping is not None else '-'} ms")
        self.download_label.setText(f"Download: {dl:.2f} Mbps" if dl else "Download: - Mbps")
        self.upload_label.setText(f"Upload: {ul:.2f} Mbps" if ul else "Upload: - Mbps")
# Part 3/4
# MainWindow UI + wiring (part 3)

class MainWindow(QMainWindow):
    update_log_signal = pyqtSignal(str, object)
    update_stats_signal = pyqtSignal(int, int, int)

    def __init__(self):
        super().__init__()
        self.process = None
        self.is_attacking = False
        self.status_thread = None
        self.stats_timer = None
        self.countdown_timer = None
        self.time_left = 0
        self.load_settings()
        self.initUI()
        self.update_log_signal.connect(self.update_log)
        self.update_stats_signal.connect(self.update_stats)

    def load_settings(self):
        # Load settings.json if exists; else default dict
        self.settings = {
            "theme": "Dark",
            "default_threads": 5,
            "default_rate": 100,
            "default_time": 60,
            "autosave_log": False
        }
        try:
            if os.path.exists(SETTINGS_FILE):
                with open(SETTINGS_FILE, "r") as f:
                    parsed = json.load(f)
                self.settings.update(parsed)
        except Exception:
            pass

    def save_settings(self):
        try:
            # gather from settings tab if exists
            if hasattr(self, "settings_tab"):
                d = self.settings_tab.to_dict()
            else:
                d = self.settings
            with open(SETTINGS_FILE, "w") as f:
                json.dump(d, f, indent=2)
            QMessageBox.information(self, "Settings", "Settings saved to setting.json")
        except Exception as e:
            QMessageBox.warning(self, "Settings", f"Failed to save settings: {e}")

    def initUI(self):
        self.setWindowTitle("Z-DDOS Tool - GUI Interface")
        # initial size larger & fixed minimum to reduce aggressive autoscale
        self.resize(1200, 820)
        self.setMinimumSize(QSize(1000, 700))

        # global font to stabilize scaling between tabs
        app_font = QFont("Segoe UI", 10)
        QApplication.instance().setFont(app_font)

        self.tabs = QTabWidget()
        # better tab behavior: keep widgets from resizing dangerously
        self.tabs.setTabPosition(QTabWidget.North)
        self.tabs.setMovable(False)
        self.tabs.setDocumentMode(True)

        self.setCentralWidget(self.tabs)

        # Setup tabs (Attack, Stats, Log, Proxy, Resource, SpeedTest, Settings)
        self.attack_tab = QWidget()
        self.setup_attack_tab()
        self.tabs.addTab(self.attack_tab, "Attack Configuration")

        self.stats_tab = AttackStatsWidget()
        self.tabs.addTab(self.stats_tab, "Attack Statistics")

        self.log_tab = LogWidget()
        self.tabs.addTab(self.log_tab, "Realtime Log")

        self.proxy_tab = ProxyCheckerWidget()
        self.tabs.addTab(self.proxy_tab, "Proxy Checker")

        self.resource_tab = ResourceMonitorWidget()
        self.tabs.addTab(self.resource_tab, "System Monitor")

        self.speed_tab = SpeedTestWidget()
        self.tabs.addTab(self.speed_tab, "Internet Speed Test")

        self.settings_tab = SettingsWidget()
        self.tabs.addTab(self.settings_tab, "Settings")

        # hook settings save/load
        self.settings_tab.save_btn.clicked.connect(self.on_save_settings)
        # when theme changed in settings, apply immediately (but don't override LogWidget)
        self.settings_tab.theme_select.currentTextChanged.connect(self.apply_theme)

        # fill settings into widgets from loaded settings
        self.settings_tab.load_from_dict(self.settings)
        # set defaults to attack inputs
        self.threads_input.setValue(self.settings.get("default_threads", 5))
        self.rate_input.setValue(self.settings.get("default_rate", 100))
        self.time_input.setValue(self.settings.get("default_time", 60))

        # apply theme from settings at startup
        self.apply_theme(self.settings.get("theme", "Dark"))

        # keep consistent style for buttons and fonts
        self.statusBar().showMessage("Ready")

    def on_save_settings(self):
        # update settings object from settings_tab then save and apply theme
        if hasattr(self, "settings_tab"):
            d = self.settings_tab.to_dict()
            self.settings.update(d)
            # write file
            try:
                with open(SETTINGS_FILE, "w") as f:
                    json.dump(self.settings, f, indent=2)
                QMessageBox.information(self, "Settings", "Saved to setting.json")
            except Exception as e:
                QMessageBox.warning(self, "Settings", f"Failed to save: {e}")
            # apply theme now
            self.apply_theme(self.settings.get("theme", "Dark"))

    # ---------------- Attack Tab Setup ----------------
    def setup_attack_tab(self):
        layout = QVBoxLayout()
        input_group = QGroupBox("Attack Parameters")
        input_layout = QFormLayout()

        self.target_input = QLineEdit()
        self.time_input = QSpinBox(); self.time_input.setRange(1, 3600)
        self.rate_input = QSpinBox(); self.rate_input.setRange(1, 10000)
        self.threads_input = QSpinBox(); self.threads_input.setRange(1, 100)

        self.proxy_input = QLineEdit()
        self.browse_btn = QPushButton("Browse")
        self.browse_btn.clicked.connect(self.browse_proxy_file)

        proxy_layout = QHBoxLayout()
        proxy_layout.addWidget(self.proxy_input)
        proxy_layout.addWidget(self.browse_btn)

        self.js_selector = QComboBox()
        self.refresh_btn = QPushButton("Refresh Script List")
        self.refresh_btn.clicked.connect(self.refresh_scripts)
        js_layout = QHBoxLayout()
        js_layout.addWidget(self.js_selector)
        js_layout.addWidget(self.refresh_btn)
        self.refresh_scripts()

        self.progress_bar = QProgressBar()
        self.progress_bar.setAlignment(Qt.AlignCenter)
        self.progress_bar.setTextVisible(True)
        self.progress_bar.setFixedHeight(24)

        # set sensible default values from loaded settings
        self.time_input.setValue(self.settings.get("default_time", 60))
        self.rate_input.setValue(self.settings.get("default_rate", 100))
        self.threads_input.setValue(self.settings.get("default_threads", 5))

        input_layout.addRow("Target URL:", self.target_input)
        input_layout.addRow("Time (seconds):", self.time_input)
        input_layout.addRow("Rate:", self.rate_input)
        input_layout.addRow("Threads:", self.threads_input)
        input_layout.addRow("Proxy File:", proxy_layout)
        input_layout.addRow("Attack Script (.js):", js_layout)
        input_layout.addRow("Countdown:", self.progress_bar)

        input_group.setLayout(input_layout)
        layout.addWidget(input_group)

        button_layout = QHBoxLayout()
        self.start_btn = QPushButton("Start Attack")
        self.start_btn.setFixedWidth(140)
        self.stop_btn = QPushButton("Stop Attack")
        self.stop_btn.setFixedWidth(140)
        self.stop_btn.setEnabled(False)

        # ensure button font remains readable in dark mode
        btn_style = "padding:6px 10px; font-size:12px; font-weight:600;"
        self.start_btn.setStyleSheet("background-color: #4CAF50; color: white;" + btn_style)
        self.stop_btn.setStyleSheet("background-color: #f44336; color: white;" + btn_style)

        self.start_btn.clicked.connect(self.start_attack)
        self.stop_btn.clicked.connect(self.stop_attack)
        button_layout.addWidget(self.start_btn); button_layout.addWidget(self.stop_btn)
        button_layout.addStretch()
        layout.addLayout(button_layout)

        # attach to widget
        self.attack_tab.setLayout(layout)
# Part 4/4
# Attack control, run loop, progress updates, theme application, main entry

    # refresh available attack scripts
    def refresh_scripts(self):
        try:
            js_files = sorted([f for f in os.listdir(".") if f.endswith(".js")])
            if not js_files:
                js_files = ["z_new.js"]
            self.js_selector.clear()
            self.js_selector.addItems(js_files)
        except Exception:
            self.js_selector.clear()
            self.js_selector.addItem("z_new.js")

    def browse_proxy_file(self):
        file_path, _ = QFileDialog.getOpenFileName(self, "Select Proxy File", "", "Text Files (*.txt)")
        if file_path:
            self.proxy_input.setText(file_path)

    # ================== Attack Control ==================
    def start_attack(self):
        if not self.target_input.text():
            QMessageBox.warning(self, "Error", "Please enter a target URL")
            return
        if not self.proxy_input.text() or not os.path.exists(self.proxy_input.text()):
            QMessageBox.warning(self, "Error", "Please select a valid proxy file")
            return

        attack_js = self.js_selector.currentText()
        cmd = [
            "node", attack_js,
            self.target_input.text(),
            str(self.time_input.value()),
            str(self.rate_input.value()),
            str(self.threads_input.value()),
            self.proxy_input.text()
        ]

        self.is_attacking = True
        self.start_btn.setEnabled(False)
        self.stop_btn.setEnabled(True)
        self.statusBar().showMessage("Attack in progress...")

        # countdown
        self.time_left = self.time_input.value()
        self.progress_bar.setMaximum(self.time_left)
        self.progress_bar.setValue(self.time_left)
        self.update_progress_bar()

        self.countdown_timer = QTimer()
        self.countdown_timer.timeout.connect(self.update_countdown)
        self.countdown_timer.start(1000)

        # run attack in thread
        self.attack_thread = threading.Thread(target=self.run_attack, args=(cmd,))
        self.attack_thread.daemon = True
        self.attack_thread.start()

        # status website checker
        self.status_thread = WebsiteStatusThread(self.target_input.text())
        self.status_thread.update_status.connect(self.stats_tab.update_status)
        self.status_thread.start()

        # Timer for statistics updates (random by default; replace by parsing output if available)
        self.stats_timer = QTimer()
        self.stats_timer.timeout.connect(self.generate_random_stats)
        self.stats_timer.start(1000)

        self.update_log_signal.emit("Attack started", QColor(0, 200, 0))

    def stop_attack(self):
        if self.process:
            try:
                self.process.terminate()
            except Exception:
                pass
            self.process = None
        self.is_attacking = False
        self.start_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)
        self.statusBar().showMessage("Attack stopped")

        if hasattr(self, 'stats_timer') and self.stats_timer:
            self.stats_timer.stop()

        if hasattr(self, 'countdown_timer') and self.countdown_timer:
            self.countdown_timer.stop()

        if self.status_thread:
            self.status_thread.stop()
            self.status_thread = None

        # auto-save logs if setting enabled
        try:
            if getattr(self, "settings", {}).get("autosave_log", False):
                self.save_attack_log()
        except Exception:
            pass

        self.update_log_signal.emit("Attack stopped", QColor(200, 0, 0))

    def run_attack(self, cmd):
        try:
            self.process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                universal_newlines=True,
                bufsize=1
            )
            # read stdout line by line
            for line in iter(self.process.stdout.readline, ''):
                if not self.is_attacking:
                    break
                if line:
                    self.update_log_signal.emit(line.rstrip(), None)
            # read stderr
            for line in iter(self.process.stderr.readline, ''):
                if line:
                    self.update_log_signal.emit(line.rstrip(), QColor(255, 0, 0))
        except Exception as e:
            self.update_log_signal.emit(f"Error: {e}", QColor(255, 0, 0))

    def update_countdown(self):
        if self.time_left > 0:
            self.time_left -= 1
            self.progress_bar.setValue(self.time_left)
            self.update_progress_bar()
        else:
            # stop attack when time finished
            self.stop_attack()

    def update_progress_bar(self):
        # show percent and color steps (green/yellow/red) and time left format
        maxv = self.progress_bar.maximum() if self.progress_bar.maximum() > 0 else 1
        percent = (self.progress_bar.value() / maxv) * 100
        if percent > 50:
            chunk_color = "#2ecc71"  # green
            text_color = "#ffffff"
        elif percent > 25:
            chunk_color = "#f1c40f"  # yellow
            text_color = "#000000"
        else:
            chunk_color = "#e74c3c"  # red
            text_color = "#ffffff"
        # apply style only to chunk (avoid affecting QTextEdit)
        self.progress_bar.setStyleSheet(
            f"QProgressBar {{background-color: #2d2d30; color: {text_color}; border: 1px solid #3c3c3c;}}"
            f"QProgressBar::chunk {{background-color: {chunk_color};}}"
        )
        self.progress_bar.setFormat(f"Time Left: {self.time_left}s")

    # ---------------- Stats generation (kept random if no real parsing) ----------------
    def generate_random_stats(self):
        if self.is_attacking:
            requests_n = random.randint(50, 200)
            success = random.randint(40, requests_n)
            failed = requests_n - success
            self.update_stats_signal.emit(requests_n, success, failed)

    # ---------------- Log & Stats update slots ----------------
    def update_log(self, message, color):
        # keep the LogWidget behaviour untouched
        self.log_tab.append_log(message, color)

    def update_stats(self, requests, success, failed):
        self.stats_tab.update_stats(requests, success, failed)

    # ---------------- Theme application (do not override LogWidget styling) ----------------
    def apply_theme(self, theme):
        # keep LogWidget's own stylesheet untouched by not styling QTextEdit globally
        if theme == "Dark":
            sheet = """
                QWidget { background-color: #1e1e1e; color: #e6e6e6; }
                QGroupBox { border:1px solid #333; margin-top:8px; padding:8px; }
                QLabel { color: #e6e6e6; }
                QLineEdit, QSpinBox, QComboBox, QTableWidget {
                    background-color: #252526; color: #ffffff; border: 1px solid #3c3c3c;
                }
                QPushButton {
                    background-color: #3a3d41; color: #ffffff; border-radius: 4px; padding:6px 8px; font-size:12px;
                }
                QHeaderView::section { background-color: #2d2d30; color: #ffffff; }
                QProgressBar { background-color: #2d2d30; color: #ffffff; border: 1px solid #3c3c3c; }
                QTabBar::tab { padding:8px; min-width: 120px; }
            """
        else:
            sheet = """
                QWidget { background-color: #ffffff; color: #111111; }
                QGroupBox { border:1px solid #ddd; margin-top:8px; padding:8px; }
                QLabel { color: #111111; }
                QLineEdit, QSpinBox, QComboBox, QTableWidget {
                    background-color: #ffffff; color: #111111; border: 1px solid #ccc;
                }
                QPushButton {
                    background-color: #f0f0f0; color: #111111; border-radius: 4px; padding:6px 8px; font-size:12px;
                }
                QHeaderView::section { background-color: #f5f5f5; color: #111111; }
                QProgressBar { background-color: #f5f5f5; color: #111111; border: 1px solid #ccc; }
                QTabBar::tab { padding:8px; min-width: 120px; }
            """
        # apply stylesheet
        self.setStyleSheet(sheet)
        # ensure LogWidget keeps its own dark background (only when global is light, preserve log look)
        try:
            if theme == "Light":
                # keep log readable on light: set dark bg for log
                self.log_tab.setStyleSheet("background-color: #1e1e1e; color: white;")
            else:
                # dark theme: keep log dark too
                self.log_tab.setStyleSheet("background-color: #1e1e1e; color: white;")
        except Exception:
            pass

    # Save attack log helper
    def save_attack_log(self):
        try:
            text = self.log_tab.toPlainText()
            fname = f"attack_log_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
            with open(fname, "w") as f:
                f.write(text)
            self.statusBar().showMessage(f"Saved log to {fname}")
        except Exception as e:
            self.statusBar().showMessage(f"Failed to save log: {e}")


# ---------------- Main Entry ----------------
if __name__ == "__main__":
    app = QApplication(sys.argv)
    # prevent font scaling issues between platforms
    app.setAttribute(Qt.AA_UseHighDpiPixmaps, True)
    app.setAttribute(Qt.AA_EnableHighDpiScaling, True)

    window = MainWindow()
    window.show()
    sys.exit(app.exec_())
