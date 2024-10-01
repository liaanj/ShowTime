import sys
import threading
import datetime
import time
import os
import json
import win32evtlog
import win32gui
import win32process
import psutil
import ctypes
import win32con
from PySide6 import QtWidgets, QtCore, QtGui
import xml.etree.ElementTree as ET
import getpass
import winreg
import subprocess
from PySide6.QtCore import QSharedMemory
import platform
import win32api

# 配置文件路径
CONFIG_FILE_PATH = os.path.join(os.path.expanduser('~'), '.my_app_config.json')

def is_admin():
    """
    检查当前用户是否拥有管理员权限
    """
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

def run_as_admin(argv=None):
    """
    重新启动程序并请求管理员权限
    """
    shell32 = ctypes.windll.shell32
    if argv is None and sys.argv:
        argv = sys.argv
    if not argv:
        argv = ['']
    executable = sys.executable
    params = ' '.join([f'"{arg}"' for arg in argv])
    show_cmd = 1  # SW_NORMAL
    lpVerb = 'runas'
    try:
        ret = shell32.ShellExecuteW(None, lpVerb, executable, params, None, show_cmd)
        if ret <= 32:
            return False
        return True
    except:
        return False

def restart_program():
    """
    重启当前程序，保持管理员权限
    """
    try:
        if is_admin():
            # 获取当前执行的可执行文件路径
            if hasattr(sys, 'frozen'):
                executable = sys.executable
            else:
                executable = sys.argv[0]
            # 使用 subprocess 重新启动程序
            subprocess.Popen([executable] + sys.argv[1:], shell=True)
            sys.exit(0)
        else:
            # 以管理员身份重新启动程序
            if run_as_admin(sys.argv):
                sys.exit(0)
            else:
                QtWidgets.QMessageBox.warning(None, "管理员权限", "需要管理员权限才能运行此程序。")
                sys.exit()
    except Exception as e:
        QtWidgets.QMessageBox.critical(None, "重启错误", f"无法重启程序: {e}")
        sys.exit(1)

def get_current_time():
    """
    获取当前本地时间，包含时区信息
    """
    return datetime.datetime.now(datetime.timezone.utc).astimezone()

def get_last_unlock_time():
    """
    从 Windows 安全日志中获取最近一次解锁或登录事件的时间
    """
    current_user = getpass.getuser().lower()
    query = "*[System/EventID=4624]"
    try:
        hand = win32evtlog.EvtQuery('Security', win32evtlog.EvtQueryReverseDirection, query)
        while True:
            events = win32evtlog.EvtNext(hand, 10)
            if not events:
                break
            for event in events:
                try:
                    xml_str = win32evtlog.EvtRender(event, win32evtlog.EvtRenderEventXml)
                    xml_root = ET.fromstring(xml_str)
                except Exception:
                    continue
                # 获取命名空间
                namespace = {'ns': 'http://schemas.microsoft.com/win/2004/08/events/event'}
                logon_type_elem = xml_root.find(".//ns:Data[@Name='LogonType']", namespaces=namespace)
                if logon_type_elem is not None:
                    logon_type = int(logon_type_elem.text)
                    if logon_type in [2, 7]:
                        # 检查 TargetUserName
                        target_user_elem = xml_root.find(".//ns:Data[@Name='TargetUserName']", namespaces=namespace)
                        if target_user_elem is not None:
                            target_user = target_user_elem.text.lower()
                            if target_user == current_user:
                                # 提取事件生成时间
                                time_created_elem = xml_root.find(".//ns:System/ns:TimeCreated", namespaces=namespace)
                                if time_created_elem is not None:
                                    time_generated_str = time_created_elem.get('SystemTime')
                                    # 处理微秒部分超过 6 位的情况
                                    time_str = time_generated_str.rstrip('Z')
                                    if '.' in time_str:
                                        base_time, microseconds = time_str.split('.')
                                        microseconds = microseconds[:6]  # 截取前 6 位
                                        time_str = f"{base_time}.{microseconds}"
                                        when_utc = datetime.datetime.strptime(time_str, '%Y-%m-%dT%H:%M:%S.%f')
                                    else:
                                        when_utc = datetime.datetime.strptime(time_str, '%Y-%m-%dT%H:%M:%S')
                                    # 将 UTC 时间转换为本地时间
                                    when_utc = when_utc.replace(tzinfo=datetime.timezone.utc)
                                    when_local = when_utc.astimezone()
                                    return when_local
                else:
                    continue
        return None
    except Exception as e:
        print(f"Error reading event log: {e}")
        return None

def update_last_unlock_time():
    """
    定期更新 last_unlock_time
    """
    global last_unlock_time
    while True:
        new_time = get_last_unlock_time()
        with last_unlock_time_lock:
            if new_time and (not last_unlock_time or new_time > last_unlock_time):
                last_unlock_time = new_time
        time.sleep(5)  # 每 5 秒检查一次

def get_active_process_name(window):
    """
    获取当前活动窗口的进程名称，排除程序自身和系统窗口
    """
    try:
        hwnd = win32gui.GetForegroundWindow()
        # 获取窗口类名和窗口标题
        class_name = win32gui.GetClassName(hwnd)
        window_text = win32gui.GetWindowText(hwnd)

        # 获取当前程序的窗口句柄和进程 ID
        current_hwnd = int(window.winId())  # PySide6 中获取窗口句柄
        current_pid = os.getpid()

        # 获取活动窗口的进程 ID
        _, pid = win32process.GetWindowThreadProcessId(hwnd)

        # 检查是否为程序自身的窗口
        if hwnd == current_hwnd or pid == current_pid:
            return None

        # 检查是否为系统窗口
        system_classes = [
            "Shell_TrayWnd", "TrayNotifyWnd", "NotifyIconOverflowWindow",
            "SysListView32", "WorkerW", "Progman", "Button",
            "Windows.UI.Core.CoreWindow", "MultitaskingViewFrame", "TaskSwitcherWnd"
        ]
        if class_name in system_classes:
            return None

        # 获取进程名称
        process = psutil.Process(pid)
        process_name = process.name()

        # 排除特定的系统进程
        system_processes = ["explorer.exe", "searchui.exe", "startmenuexperiencehost.exe"]
        if process_name.lower() in system_processes:
            return None

        return process_name
    except Exception as e:
        print(f"Error getting active process name: {e}")
        return None

def format_timedelta(td):
    """
    将时间差格式化为小时:分钟:秒
    """
    total_seconds = int(td.total_seconds())
    hours, remainder = divmod(total_seconds, 3600)
    minutes, seconds = divmod(remainder, 60)
    return f'{hours:02}:{minutes:02}:{seconds:02}'

class Reminder:
    def __init__(self, reminder_type, duration, start_time):
        self.reminder_type = reminder_type  # 'unlock_time', 'app_time', 'countdown'
        self.duration = duration  # timedelta
        self.start_time = start_time  # 传入的开始时间
        self.target_time = self.start_time + self.duration

class ProgressBarWidget(QtWidgets.QWidget):
    def __init__(self, parent=None, filled_color="#64C864", background_color="#C8C8C8"):
        super().__init__(parent)
        self.progress = 0  # 进度百分比，0 到 100
        self.setMinimumWidth(10)  # 设置最小宽度
        self.setMinimumHeight(30)  # 设置最小高度
        self.filled_color = filled_color
        self.background_color = background_color

    def set_progress(self, progress):
        self.progress = progress
        self.update()  # 触发重绘

    def set_filled_color(self, color):
        self.filled_color = color
        self.update()

    def set_background_color(self, color):
        self.background_color = color
        self.update()

    def paintEvent(self, event):
        painter = QtGui.QPainter(self)
        # 开启反锯齿
        painter.setRenderHint(QtGui.QPainter.Antialiasing)
        # 绘制背景矩形
        rect = self.rect()
        painter.setBrush(QtGui.QColor(self.background_color))
        painter.setPen(QtCore.Qt.NoPen)
        painter.drawRoundedRect(rect, 5, 5)
        # 计算已填充部分
        filled_height = rect.height() * self.progress / 100
        filled_rect = QtCore.QRectF(
            rect.x(),
            rect.y() + rect.height() - filled_height,
            rect.width(),
            filled_height
        )
        # 绘制已填充部分
        painter.setBrush(QtGui.QColor(self.filled_color))
        painter.drawRoundedRect(filled_rect, 5, 5)

class ReminderDialog(QtWidgets.QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.reminder_type = None
        self.duration = None
        self.initUI()

    def initUI(self):
        self.setWindowTitle("设置提醒")
        layout = QtWidgets.QVBoxLayout()

        # 提醒类型选择（使用单选按钮）
        type_layout = QtWidgets.QHBoxLayout()
        type_label = QtWidgets.QLabel("提醒类型:")
        self.unlock_time_radio = QtWidgets.QRadioButton("解锁时间")
        self.app_time_radio = QtWidgets.QRadioButton("应用时间")
        self.countdown_radio = QtWidgets.QRadioButton("倒计时")
        self.unlock_time_radio.setChecked(True)  # 默认选中解锁时间
        type_layout.addWidget(type_label)
        type_layout.addWidget(self.unlock_time_radio)
        type_layout.addWidget(self.app_time_radio)
        type_layout.addWidget(self.countdown_radio)
        layout.addLayout(type_layout)

        # 时间输入
        duration_layout = QtWidgets.QHBoxLayout()
        duration_label = QtWidgets.QLabel("时间 (分钟):")
        self.duration_edit = QtWidgets.QLineEdit()
        duration_layout.addWidget(duration_label)
        duration_layout.addWidget(self.duration_edit)
        layout.addLayout(duration_layout)

        # 按钮
        button_box = QtWidgets.QDialogButtonBox(QtWidgets.QDialogButtonBox.Ok | QtWidgets.QDialogButtonBox.Cancel)
        button_box.accepted.connect(self.accept)
        button_box.rejected.connect(self.reject)
        layout.addWidget(button_box)

        self.setLayout(layout)

    def accept(self):
        try:
            duration_value = int(self.duration_edit.text())
            if duration_value <= 0:
                raise ValueError("时间必须是正数")
            self.duration = duration_value * 60  # 将分钟转换为秒
            if self.unlock_time_radio.isChecked():
                self.reminder_type = "unlock_time"
            elif self.app_time_radio.isChecked():
                self.reminder_type = "app_time"
            elif self.countdown_radio.isChecked():
                self.reminder_type = "countdown"
            super().accept()
        except ValueError:
            QtWidgets.QMessageBox.warning(self, "输入错误", "请输入有效的正数时间（分钟）")

class AppearanceSettingsDialog(QtWidgets.QDialog):
    def __init__(self, parent=None, config=None):
        super().__init__(parent)
        self.config = config or {}
        self.main_window = parent  # 引用主窗口
        self.initUI()
        self.connect_signals()

    def initUI(self):
        self.setWindowTitle("外观设置")
        layout = QtWidgets.QFormLayout()

        # 字体大小
        self.font_size_spin = QtWidgets.QSpinBox()
        self.font_size_spin.setRange(8, 48)
        self.font_size_spin.setValue(self.config.get('font_size', 16))
        layout.addRow("字体大小:", self.font_size_spin)

        # 字体颜色
        self.font_color_button = QtWidgets.QPushButton("选择颜色")
        self.font_color_display = QtWidgets.QLabel()
        self.font_color_display.setFixedSize(50, 20)
        self.font_color_display.setStyleSheet(f"background-color: {self.config.get('font_color', '#000000')};")
        font_color_layout = QtWidgets.QHBoxLayout()
        font_color_layout.addWidget(self.font_color_button)
        font_color_layout.addWidget(self.font_color_display)
        layout.addRow("字体颜色:", font_color_layout)
        self.font_color_button.clicked.connect(self.choose_font_color)

        # 窗口宽度
        self.window_width_spin = QtWidgets.QSpinBox()
        self.window_width_spin.setRange(100, 1000)
        self.window_width_spin.setValue(self.config.get('window_width', 200))
        layout.addRow("窗口宽度:", self.window_width_spin)

        # 窗口高度
        self.window_height_spin = QtWidgets.QSpinBox()
        self.window_height_spin.setRange(30, 500)  # 设置最低高度为30
        self.window_height_spin.setValue(self.config.get('window_height', 60))
        layout.addRow("窗口高度:", self.window_height_spin)

        # 进度条位置
        self.bar_position_group = QtWidgets.QButtonGroup()
        bar_position_layout = QtWidgets.QHBoxLayout()
        self.bar_left_radio = QtWidgets.QRadioButton("左侧")
        self.bar_right_radio = QtWidgets.QRadioButton("右侧")
        self.bar_position_group.addButton(self.bar_left_radio)
        self.bar_position_group.addButton(self.bar_right_radio)
        bar_position_layout.addWidget(self.bar_left_radio)
        bar_position_layout.addWidget(self.bar_right_radio)
        bar_position = self.config.get('bar_position', "左侧")
        if bar_position == "左侧":
            self.bar_left_radio.setChecked(True)
        else:
            self.bar_right_radio.setChecked(True)
        layout.addRow("进度条位置:", bar_position_layout)

        # 控件间距
        self.spacing_spin = QtWidgets.QSpinBox()
        self.spacing_spin.setRange(0, 20)
        self.spacing_spin.setValue(self.config.get('spacing', 2))
        layout.addRow("控件间距:", self.spacing_spin)

        # 进度条高度
        self.progress_bar_height_spin = QtWidgets.QSpinBox()
        self.progress_bar_height_spin.setRange(10, 200)
        self.progress_bar_height_spin.setValue(self.config.get('progress_bar_height', 40))
        layout.addRow("进度条高度:", self.progress_bar_height_spin)

        # 进度条填充颜色
        self.progress_filled_color_button = QtWidgets.QPushButton("选择填充颜色")
        self.progress_filled_color_display = QtWidgets.QLabel()
        self.progress_filled_color_display.setFixedSize(50, 20)
        self.progress_filled_color_display.setStyleSheet(f"background-color: {self.config.get('progress_bar_filled_color', '#64C864')};")
        progress_filled_color_layout = QtWidgets.QHBoxLayout()
        progress_filled_color_layout.addWidget(self.progress_filled_color_button)
        progress_filled_color_layout.addWidget(self.progress_filled_color_display)
        layout.addRow("进度条填充颜色:", progress_filled_color_layout)
        self.progress_filled_color_button.clicked.connect(self.choose_progress_filled_color)

        # 进度条背景颜色
        self.progress_background_color_button = QtWidgets.QPushButton("选择背景颜色")
        self.progress_background_color_display = QtWidgets.QLabel()
        self.progress_background_color_display.setFixedSize(50, 20)
        self.progress_background_color_display.setStyleSheet(f"background-color: {self.config.get('progress_bar_background_color', '#C8C8C8')};")
        progress_background_color_layout = QtWidgets.QHBoxLayout()
        progress_background_color_layout.addWidget(self.progress_background_color_button)
        progress_background_color_layout.addWidget(self.progress_background_color_display)
        layout.addRow("进度条背景颜色:", progress_background_color_layout)
        self.progress_background_color_button.clicked.connect(self.choose_progress_background_color)

        # 按钮
        button_box = QtWidgets.QDialogButtonBox(QtWidgets.QDialogButtonBox.Close)
        button_box.rejected.connect(self.reject)
        layout.addRow(button_box)

        self.setLayout(layout)

    def connect_signals(self):
        # 实时更新
        self.font_size_spin.valueChanged.connect(self.update_main_window)
        self.window_width_spin.valueChanged.connect(self.update_main_window)
        self.window_height_spin.valueChanged.connect(self.update_main_window)
        self.bar_position_group.buttonClicked.connect(self.update_main_window)
        self.spacing_spin.valueChanged.connect(self.update_main_window)
        self.progress_bar_height_spin.valueChanged.connect(self.update_main_window)

    def choose_font_color(self):
        color = QtWidgets.QColorDialog.getColor()
        if color.isValid():
            try:
                self.config['font_color'] = color.name()
                self.font_color_display.setStyleSheet(f"background-color: {color.name()};")
                self.update_main_window()
                # 重启程序以应用颜色更改
                self.main_window.save_config()
                restart_program()
            except Exception as e:
                QtWidgets.QMessageBox.warning(self, "颜色选择错误", f"无法设置颜色: {e}")

    def choose_progress_filled_color(self):
        color = QtWidgets.QColorDialog.getColor()
        if color.isValid():
            try:
                self.config['progress_bar_filled_color'] = color.name()
                self.progress_filled_color_display.setStyleSheet(f"background-color: {color.name()};")
                self.update_main_window()
                # 添加重启程序以应用颜色更改
                self.main_window.save_config()
                restart_program()
            except Exception as e:
                QtWidgets.QMessageBox.warning(self, "颜色选择错误", f"无法设置填充颜色: {e}")

    def choose_progress_background_color(self):
        color = QtWidgets.QColorDialog.getColor()
        if color.isValid():
            try:
                self.config['progress_bar_background_color'] = color.name()
                self.progress_background_color_display.setStyleSheet(f"background-color: {color.name()};")
                self.update_main_window()
                # 添加重启程序以应用颜色更改
                self.main_window.save_config()
                restart_program()
            except Exception as e:
                QtWidgets.QMessageBox.warning(self, "颜色选择错误", f"无法设置背景颜色: {e}")

    def update_main_window(self):
        # 更新配置
        try:
            self.config['font_size'] = self.font_size_spin.value()
            self.config['window_width'] = self.window_width_spin.value()
            self.config['window_height'] = self.window_height_spin.value()
            self.config['bar_position'] = "左侧" if self.bar_left_radio.isChecked() else "右侧"
            self.config['spacing'] = self.spacing_spin.value()
            self.config['progress_bar_height'] = self.progress_bar_height_spin.value()
            self.config['progress_bar_filled_color'] = self.config.get('progress_bar_filled_color', '#64C864')
            self.config['progress_bar_background_color'] = self.config.get('progress_bar_background_color', '#C8C8C8')
            self.config['font_color'] = self.config.get('font_color', '#000000')
            # 应用到主窗口
            self.main_window.config.update(self.config)
            self.main_window.apply_config()
        except Exception as e:
            QtWidgets.QMessageBox.warning(self, "应用设置错误", f"无法应用设置: {e}")

class TransparentWindow(QtWidgets.QWidget):
    def __init__(self):
        super().__init__()
        self.config = self.load_config()
        self.recent_apps = {}  # 存储最近切换的应用程序
        self.reminders = []  # 存储提醒对象
        self.is_paused = False  # 是否暂停计时
        self.is_fullscreen = False  # 是否处于全屏状态
        self.is_window_shown = True  # 窗口是否显示
        self.previous_position = None  # 记录窗口之前的位置
        self.initUI()
        # 应用配置
        self.apply_config()
        # 初始化 last_process_name 和 last_process_start_time
        self.last_process_name = get_active_process_name(self)
        self.last_process_start_time = get_current_time()
        # 启动定时器更新界面
        self.timer = QtCore.QTimer()
        self.timer.timeout.connect(self.update_time)
        self.timer.start(500)  # 每 500 毫秒更新一次

        # 启动置顶定时器，每 50 毫秒置顶一次
        self.raise_timer = QtCore.QTimer()
        self.raise_timer.timeout.connect(self.keep_on_top)
        self.raise_timer.start(50)  # 每 50 毫秒置顶一次

        # 启动线程定期更新 last_unlock_time
        threading.Thread(target=update_last_unlock_time, daemon=True).start()

        # 启动全屏检测定时器
        self.fullscreen_timer = QtCore.QTimer()
        self.fullscreen_timer.timeout.connect(self.check_fullscreen)
        self.fullscreen_timer.start(100)  # 每100ms检查一次

    def paintEvent(self, event):
        """
        重写 paintEvent 以绘制一个几乎完全透明的背景，
        这样窗口的所有区域都能拦截鼠标事件。
        """
        painter = QtGui.QPainter(self)
        # 设置组合模式为 Source，确保绘制的颜色覆盖所有像素
        painter.setCompositionMode(QtGui.QPainter.CompositionMode_Source)
        # 绘制一个几乎透明的背景（Alpha 值为1）
        painter.fillRect(self.rect(), QtGui.QColor(0, 0, 0, 1))

    def initUI(self):
        try:
            # 设置窗口无边框、置顶、工具窗口和背景透明
            self.setWindowFlags(QtCore.Qt.FramelessWindowHint | QtCore.Qt.WindowStaysOnTopHint | QtCore.Qt.Tool)
            self.setAttribute(QtCore.Qt.WA_TranslucentBackground)

            # 使窗口可拖动
            self.offset = None

            # 创建标签
            self.unlock_time_label = QtWidgets.QLabel("", self)
            self.app_time_label = QtWidgets.QLabel("", self)

            # 设置标签样式（字体颜色和大小）
            label_style = f"color: {self.config.get('font_color', '#000000')}; font-size: {self.config.get('font_size', 16)}px;"
            self.unlock_time_label.setStyleSheet(label_style)
            self.app_time_label.setStyleSheet(label_style)

            # 设置标签不拦截鼠标事件
            self.unlock_time_label.setAttribute(QtCore.Qt.WA_TransparentForMouseEvents)
            self.app_time_label.setAttribute(QtCore.Qt.WA_TransparentForMouseEvents)

            # 设置标签的最小高度，确保在窗口高度降低时能够正常显示
            self.unlock_time_label.setMinimumHeight(10)
            self.app_time_label.setMinimumHeight(10)

            # 创建进度条小部件
            self.progress_bar = ProgressBarWidget(
                self,
                filled_color=self.config.get('progress_bar_filled_color', '#64C864'),
                background_color=self.config.get('progress_bar_background_color', '#C8C8C8')
            )
            progress_bar_height = self.config.get('progress_bar_height', 40)
            self.progress_bar.setFixedSize(10, progress_bar_height)  # 调整尺寸

            # 布局设置
            self.layout = QtWidgets.QHBoxLayout()
            self.layout.setSpacing(self.config.get('spacing', 2))
            self.layout.setContentsMargins(0, 0, 0, 0)

            # 动态调整进度条位置
            self.update_layout()

            self.setLayout(self.layout)

            # 设置窗口大小和位置
            self.update_window_geometry()
        except Exception as e:
            QtWidgets.QMessageBox.warning(self, "初始化错误", f"初始化界面时发生错误: {e}")
    
    def show_about_dialog(self):
        """
        显示关于对话框，包含作者名称和 GitHub 地址
        """
        try:
            # 创建一个对话框
            dialog = QtWidgets.QDialog(self)
            dialog.setWindowTitle("关于")
            dialog.setFixedSize(300, 150)

            layout = QtWidgets.QVBoxLayout()

            # 添加作者名称
            author_label = QtWidgets.QLabel("作者：liaanj")
            author_label.setAlignment(QtCore.Qt.AlignCenter)
            layout.addWidget(author_label)

            # 添加 GitHub 地址，设置为可点击的链接
            github_label = QtWidgets.QLabel()
            github_label.setText('<a href="https://github.com/yourusername/yourproject">GitHub 地址：点击访问项目</a>')
            github_label.setAlignment(QtCore.Qt.AlignCenter)
            github_label.setOpenExternalLinks(True)  # 允许打开外部链接
            layout.addWidget(github_label)

            # 添加关闭按钮
            button_box = QtWidgets.QDialogButtonBox(QtWidgets.QDialogButtonBox.Close)
            button_box.rejected.connect(dialog.reject)
            layout.addWidget(button_box)

            dialog.setLayout(layout)
            dialog.exec()
        except Exception as e:
            QtWidgets.QMessageBox.warning(self, "关于对话框错误", f"无法显示关于对话框: {e}")

    def check_is_fullscreen(self):
        hwnd = win32gui.GetForegroundWindow()
        if hwnd == 0:
            return False
        # 获取窗口矩形
        rect = win32gui.GetWindowRect(hwnd)
        # 获取屏幕尺寸
        screen_rect = QtWidgets.QApplication.primaryScreen().geometry()
        # 检查窗口是否覆盖整个屏幕
        if rect == (screen_rect.left(), screen_rect.top(), screen_rect.right(), screen_rect.bottom()):
            return True
        else:
            return False

    def check_fullscreen(self):
        """
        检查当前前台窗口是否全屏，并更新状态
        """
        hwnd = win32gui.GetForegroundWindow()
        if hwnd:
            self_hwnd = self.effectiveWinId().__int__()
            if hwnd == self_hwnd:
                # 前台窗口是自身，忽略，不改变 is_fullscreen 状态
                return
            else:
                # 获取前台窗口所在屏幕
                monitor_info = win32api.GetMonitorInfo(win32api.MonitorFromWindow(hwnd))
                monitor_area = monitor_info['Monitor']
                work_area = monitor_info['Work']
                # 获取前台窗口大小
                rect = win32gui.GetWindowRect(hwnd)
                width = rect[2] - rect[0]
                height = rect[3] - rect[1]
                screen_width = monitor_area[2] - monitor_area[0]
                screen_height = monitor_area[3] - monitor_area[1]
                new_fullscreen_state = (width >= screen_width and height >= screen_height)
                # 排除桌面窗口
                window_class = win32gui.GetClassName(hwnd)
                desktop_classes = ["Progman", "WorkerW"]
                if window_class in desktop_classes:
                    new_fullscreen_state = False
                if new_fullscreen_state != self.is_fullscreen:
                    self.is_fullscreen = new_fullscreen_state
                    if self.is_fullscreen:
                        print("进入全屏模式")
                        self.on_enter_fullscreen()
                    else:
                        print("退出全屏模式")
                        self.on_exit_fullscreen()
        else:
            # 无前台窗口，可能性较小，忽略
            pass

    def is_foreground_fullscreen(self):
        hwnd = win32gui.GetForegroundWindow()
        if hwnd:
            # 获取自身窗口的实际句柄
            self_hwnd = self.effectiveWinId().__int__()
            # 忽略自身窗口
            if hwnd == self_hwnd:
                return False
            rect = win32gui.GetWindowRect(hwnd)
            width = rect[2] - rect[0]
            height = rect[3] - rect[1]
            screen_width = win32api.GetSystemMetrics(win32con.SM_CXSCREEN)
            screen_height = win32api.GetSystemMetrics(win32con.SM_CYSCREEN)
            if width == screen_width and height == screen_height:
                return True
        return False

    def on_enter_fullscreen(self):
        # 移动到记录的全屏位置
        pos = self.config.get('fullscreen_position', None)
        if pos is not None:
            self.move(pos['x'], pos['y'])
        # 移除贴边隐藏相关逻辑

    def on_exit_fullscreen(self):
        # 移动到记录的非全屏位置
        pos = self.config.get('non_fullscreen_position', None)
        if pos is not None:
            self.move(pos['x'], pos['y'])
        # 如果窗口被隐藏，确保它显示出来
        self.show()
        self.is_window_shown = True

    def update_layout(self):
        try:
            # 清除现有布局
            while self.layout.count():
                item = self.layout.takeAt(0)
                widget = item.widget()
                if widget is not None:
                    widget.setParent(None)

            # 更新标签样式
            label_style = f"color: {self.config.get('font_color', '#000000')}; font-size: {self.config.get('font_size', 16)}px;"
            self.unlock_time_label.setStyleSheet(label_style)
            self.app_time_label.setStyleSheet(label_style)

            # 根据配置添加控件
            if self.config.get('bar_position', "左侧") == "左侧":
                self.layout.addWidget(self.progress_bar)

            text_layout = QtWidgets.QVBoxLayout()
            text_layout.addWidget(self.unlock_time_label)
            text_layout.addWidget(self.app_time_label)
            text_layout.setSpacing(0)
            text_layout.setContentsMargins(0, 0, 0, 0)

            self.layout.addLayout(text_layout)

            if self.config.get('bar_position', "左侧") == "右侧":
                self.layout.addWidget(self.progress_bar)

            # 更新布局间距
            self.layout.setSpacing(self.config.get('spacing', 2))
        except Exception as e:
            QtWidgets.QMessageBox.warning(self, "布局更新错误", f"更新布局时发生错误: {e}")

    def update_window_geometry(self):
        try:
            window_width = self.config.get('window_width', 200)
            window_height = self.config.get('window_height', 60)
            x = self.config.get('window_x', None)
            y = self.config.get('window_y', None)

            # 更新窗口尺寸
            self.resize(window_width, window_height)

            if x is not None and y is not None:
                self.move(x, y)
            else:
                screen_rect = QtWidgets.QApplication.primaryScreen().availableGeometry()
                taskbar_height = 40  # 假设任务栏高度为 40px
                offset_from_right = 100  # 从屏幕右侧向左偏移 100 像素
                self.move(screen_rect.width() - window_width - offset_from_right,
                          screen_rect.height() - taskbar_height - window_height)
        except Exception as e:
            QtWidgets.QMessageBox.warning(self, "窗口几何错误", f"更新窗口几何时发生错误: {e}")

    def apply_config(self):
        try:
            # 更新布局
            self.update_layout()
            # 更新窗口尺寸，但保持当前位置
            self.update_window_geometry()

            # 更新进度条高度
            progress_bar_height = self.config.get('progress_bar_height', 40)
            self.progress_bar.setFixedHeight(progress_bar_height)

            # 更新进度条颜色
            filled_color = self.config.get('progress_bar_filled_color', '#64C864')
            background_color = self.config.get('progress_bar_background_color', '#C8C8C8')
            self.progress_bar.set_filled_color(filled_color)
            self.progress_bar.set_background_color(background_color)

            # 更新标签样式
            label_style = f"color: {self.config.get('font_color', '#000000')}; font-size: {self.config.get('font_size', 16)}px;"
            self.unlock_time_label.setStyleSheet(label_style)
            self.app_time_label.setStyleSheet(label_style)
        except Exception as e:
            QtWidgets.QMessageBox.warning(self, "应用配置错误", f"应用配置时发生错误: {e}")

    def load_config(self):
        if os.path.exists(CONFIG_FILE_PATH):
            try:
                with open(CONFIG_FILE_PATH, 'r', encoding='utf-8') as f:
                    config = json.load(f)
                return config
            except Exception as e:
                print(f"Error loading config: {e}")
                return {}
        else:
            return {}

    def save_config(self):
        try:
            # 在保存配置前，保存窗口的位置
            self.config['window_x'] = self.x()
            self.config['window_y'] = self.y()
            with open(CONFIG_FILE_PATH, 'w', encoding='utf-8') as f:
                json.dump(self.config, f, ensure_ascii=False, indent=4)
        except Exception as e:
            print(f"Error saving config: {e}")

    def mousePressEvent(self, event):
        """
        记录鼠标按下的位置
        """
        if event.button() == QtCore.Qt.MouseButton.LeftButton:
            self.offset = event.position().toPoint()
        elif event.button() == QtCore.Qt.MouseButton.RightButton:
            self.contextMenuEvent(event)

    def mouseMoveEvent(self, event):
        """
        拖动窗口
        """
        if self.offset is not None and event.buttons() == QtCore.Qt.MouseButton.LeftButton:
            self.move(event.globalPosition().toPoint() - self.offset)

    def mouseReleaseEvent(self, event):
        """
        释放鼠标时清除偏移
        """
        self.offset = None

    def moveEvent(self, event):
        """
        当窗口移动时，更新配置中的窗口位置
        """
        super().moveEvent(event)
        self.config['window_x'] = self.x()
        self.config['window_y'] = self.y()
        # 根据全屏状态记录位置
        if self.is_fullscreen:
            self.config['fullscreen_position'] = {'x': self.x(), 'y': self.y()}
        else:
            self.config['non_fullscreen_position'] = {'x': self.x(), 'y': self.y()}

    def contextMenuEvent(self, event):
        """
        右键菜单
        """
        try:
            menu = QtWidgets.QMenu(self)
            reset_time_action = menu.addAction("清除时间")
            set_reminder_action = menu.addAction("设置提醒")
            appearance_settings_action = menu.addAction("外观设置")
            pause_time_action = menu.addAction("暂停计时" if not self.is_paused else "继续计时")
            startup_action = menu.addAction("开机自启")
            about_action = menu.addAction("关于软件")
            exit_action = menu.addAction("退出应用")

            # 设置开机自启复选框状态
            is_startup = self.is_startup_enabled()
            startup_action.setCheckable(True)
            startup_action.setChecked(is_startup)

            # 计算菜单位置，避免被遮挡
            screen_rect = QtWidgets.QApplication.primaryScreen().availableGeometry()
            menu_x = event.globalPos().x()
            menu_y = event.globalPos().y()
            menu_height = menu.sizeHint().height()
            if menu_y + menu_height > screen_rect.height():
                menu_y = screen_rect.height() - menu_height

            action = menu.exec(QtCore.QPoint(menu_x, menu_y))
            if action == reset_time_action:
                self.reset_time()
            elif action == set_reminder_action:
                self.set_reminder()
            elif action == appearance_settings_action:
                self.open_appearance_settings()
            elif action == pause_time_action:
                self.toggle_pause()
            elif action == startup_action:
                if startup_action.isChecked():
                    self.enable_startup()
                else:
                    self.disable_startup()
            elif action == about_action:  # 处理“关于”菜单项的点击事件
                self.show_about_dialog()
            elif action == exit_action:
                self.close()
        except Exception as e:
            QtWidgets.QMessageBox.warning(self, "右键菜单错误", f"打开右键菜单时发生错误: {e}")

    def open_appearance_settings(self):
        """
        打开外观设置对话框
        """
        try:
            dialog = AppearanceSettingsDialog(self, self.config.copy())
            dialog.exec()
            # 配置已经在实时更新中保存，不需要在这里再保存
        except Exception as e:
            QtWidgets.QMessageBox.warning(self, "外观设置错误", f"打开外观设置时发生错误: {e}")

    def reset_time(self):
        """
        清除时间
        """
        try:
            # 重置 last_unlock_time
            with last_unlock_time_lock:
                global last_unlock_time
                last_unlock_time = get_current_time()
            # 重置应用时间
            self.last_process_start_time = get_current_time()
            self.last_process_name = get_active_process_name(self)
            # 清空提醒
            self.reminders.clear()
            self.progress_bar.set_progress(0)
        except Exception as e:
            QtWidgets.QMessageBox.warning(self, "重置时间错误", f"重置时间时发生错误: {e}")

    def set_reminder(self):
        try:
            dialog = ReminderDialog(self)
            if dialog.exec() == QtWidgets.QDialog.Accepted:
                reminder_type_map = {
                    "unlock_time": "unlock_time",
                    "app_time": "app_time",
                    "countdown": "countdown"
                }
                reminder_type = reminder_type_map.get(dialog.reminder_type)
                duration = datetime.timedelta(seconds=dialog.duration)
                # 获取当前已用时间
                current_time = get_current_time()

                if reminder_type == 'unlock_time':
                    with last_unlock_time_lock:
                        if last_unlock_time:
                            elapsed_time = current_time - last_unlock_time
                            start_time = last_unlock_time
                        else:
                            # 无法获取解锁时间，提前记录错误信息
                            error_message = "无法获取解锁时间"
                            start_time = None
                    if start_time is None:
                        QtWidgets.QMessageBox.warning(self, "设置错误", error_message)
                        return
                    if duration <= elapsed_time:
                        QtWidgets.QMessageBox.warning(self, "输入错误", "提醒时间必须大于当前已用的解锁时间")
                        return

                elif reminder_type == 'app_time':
                    if self.last_process_start_time:
                        elapsed_time = current_time - self.last_process_start_time
                        if duration <= elapsed_time:
                            QtWidgets.QMessageBox.warning(self, "输入错误", "提醒时间必须大于当前已用的应用时间")
                            return
                        start_time = self.last_process_start_time
                    else:
                        QtWidgets.QMessageBox.warning(self, "设置错误", "无法获取应用时间")
                        return

                elif reminder_type == 'countdown':
                    start_time = current_time

                # 创建提醒对象
                reminder = Reminder(reminder_type, duration, start_time)
                self.reminders.append(reminder)
        except Exception as e:
            QtWidgets.QMessageBox.warning(self, "设置提醒错误", f"设置提醒时发生错误: {e}")

    def toggle_pause(self):
        """
        暂停或继续计时
        """
        try:
            self.is_paused = not self.is_paused
            if self.is_paused:
                self.pause_start_time = get_current_time()
            else:
                pause_duration = get_current_time() - self.pause_start_time
                # 调整计时开始时间，补偿暂停的时间
                with last_unlock_time_lock:
                    global last_unlock_time
                    if last_unlock_time:
                        last_unlock_time += pause_duration
                if self.last_process_start_time:
                    self.last_process_start_time += pause_duration
                # 更新提醒的开始时间和目标时间
                for reminder in self.reminders:
                    reminder.start_time += pause_duration
                    reminder.target_time += pause_duration
        except Exception as e:
            QtWidgets.QMessageBox.warning(self, "暂停计时错误", f"暂停/继续计时时发生错误: {e}")

    def show_notification(self, reminder):
        """
        显示提醒通知
        """
        try:
            message_map = {
                'unlock_time': '解锁时间',
                'app_time': '应用时间',
                'countdown': '倒计时'
            }
            message = f"您的{message_map.get(reminder.reminder_type, '未知类型')}已达到设定时间！"
            QtWidgets.QMessageBox.information(self, "提醒", message)
        except Exception as e:
            QtWidgets.QMessageBox.warning(self, "通知错误", f"显示通知时发生错误: {e}")

    def update_time(self):
        try:
            if self.is_paused:
                # 计时暂停，不更新界面，仅保持进度条不动
                return

            # 获取当前本地时间，包含时区信息
            current_time = get_current_time()

            # 更新自上次解锁以来的时间
            with last_unlock_time_lock:
                local_last_unlock_time = last_unlock_time
            if local_last_unlock_time:
                since_unlock = current_time - local_last_unlock_time
                self.unlock_time_label.setText(f"解锁时间: {format_timedelta(since_unlock)}")
            else:
                self.unlock_time_label.setText("解锁时间: N/A")

            # 更新当前应用使用时间
            current_process_name = get_active_process_name(self)

            if current_process_name and current_process_name != self.last_process_name:
                # 活动应用程序发生变化
                switch_away_time = current_time  # 记录离开时间

                # 计算在上一个应用程序上花费的时间
                app_time = current_time - self.last_process_start_time

                # 将上一个应用程序的信息存储到 recent_apps
                self.recent_apps[self.last_process_name] = {
                    'last_start_time': self.last_process_start_time,
                    'accumulated_time': app_time,
                    'switch_away_time': switch_away_time
                }

                # 移除离开时间超过一分钟的应用程序
                to_remove = []
                for app_name, data in self.recent_apps.items():
                    time_since_switch = (current_time - data['switch_away_time']).total_seconds()
                    if time_since_switch > 60:
                        to_remove.append(app_name)
                for app_name in to_remove:
                    del self.recent_apps[app_name]

                # 检查当前应用程序是否在 recent_apps 中（即是否在一分钟内返回）
                if current_process_name in self.recent_apps:
                    # 恢复之前的应用程序计时
                    prev_data = self.recent_apps[current_process_name]
                    self.last_process_start_time = prev_data['last_start_time']
                    # 调整开始时间，补偿离开的时间
                    time_away = current_time - prev_data['switch_away_time']
                    self.last_process_start_time += time_away
                    # 从 recent_apps 中移除该应用程序
                    del self.recent_apps[current_process_name]
                else:
                    # 超过一分钟，重置计时
                    self.last_process_start_time = current_time

                self.last_process_name = current_process_name

            elif current_process_name is None:
                # 活动窗口为系统窗口或自身窗口，不做处理
                pass
            else:
                # 活动应用程序未发生变化，继续计时
                pass

            if self.last_process_name:
                app_uptime = current_time - self.last_process_start_time
                self.app_time_label.setText(f"应用时间: {format_timedelta(app_uptime)}")
            else:
                self.app_time_label.setText("应用时间: N/A")

            # 检查提醒
            if self.reminders:
                # 更新依赖于解锁时间或应用时间的提醒
                for reminder in self.reminders[:]:
                    if reminder.reminder_type == 'unlock_time':
                        with last_unlock_time_lock:
                            local_last_unlock_time = last_unlock_time
                        if local_last_unlock_time and local_last_unlock_time > reminder.start_time:
                            reminder.start_time = local_last_unlock_time
                            reminder.target_time = reminder.start_time + reminder.duration
                    elif reminder.reminder_type == 'app_time':
                        if self.last_process_start_time and self.last_process_start_time > reminder.start_time:
                            reminder.start_time = self.last_process_start_time
                            reminder.target_time = reminder.start_time + reminder.duration

                    time_remaining = (reminder.target_time - current_time).total_seconds()
                    total_duration = (reminder.target_time - reminder.start_time).total_seconds()
                    if total_duration > 0:
                        progress = max(0, min(100, (1 - time_remaining / total_duration) * 100))
                    else:
                        progress = 100
                    self.progress_bar.set_progress(progress)

                    # 检查是否有提醒到达
                    if reminder.target_time <= current_time:
                        # 提醒到达
                        self.show_notification(reminder)
                        # 删除已完成的提醒
                        self.reminders.remove(reminder)
            else:
                # 没有提醒，重置进度条
                self.progress_bar.set_progress(0)
        except Exception as e:
            QtWidgets.QMessageBox.warning(self, "更新时间错误", f"更新时间时发生错误: {e}")

    def keep_on_top(self):
        """
        将窗口置顶
        """
        try:
            self.raise_()
        except Exception as e:
            QtWidgets.QMessageBox.warning(self, "置顶错误", f"保持置顶时发生错误: {e}")

    def closeEvent(self, event):
        """
        窗口关闭事件
        """
        try:
            self.save_config()
            # 停止所有定时器
            self.timer.stop()
            self.raise_timer.stop()
            self.fullscreen_timer.stop()
            # self.mouse_timer.stop()
            # 释放共享内存
            shared_memory.detach()
            event.accept()
        except Exception as e:
            QtWidgets.QMessageBox.warning(self, "关闭错误", f"关闭窗口时发生错误: {e}")
            event.ignore()

    def is_startup_enabled(self):
        """
        检查是否设置了开机自启
        """
        try:
            key = winreg.OpenKey(winreg.HKEY_CURRENT_USER,
                                 r"Software\Microsoft\Windows\CurrentVersion\Run",
                                 0, winreg.KEY_READ)
            value, regtype = winreg.QueryValueEx(key, "MyTransparentApp")
            winreg.CloseKey(key)
            return True
        except FileNotFoundError:
            return False

    def enable_startup(self):
        """
        设置开机自启
        """
        try:
            key = winreg.OpenKey(winreg.HKEY_CURRENT_USER,
                                r"Software\Microsoft\Windows\CurrentVersion\Run",
                                0, winreg.KEY_SET_VALUE)
            if getattr(sys, 'frozen', False):
                # 如果程序是打包成exe的
                exe_path = sys.executable
            else:
                # 如果程序是以脚本形式运行的
                exe_path = os.path.abspath(sys.argv[0])
                # 如果是脚本，建议将其转换为可执行文件或使用完整路径
            # 添加双引号以处理路径中的空格
            winreg.SetValueEx(key, "MyTransparentApp", 0, winreg.REG_SZ, f'"{exe_path}"')
            winreg.CloseKey(key)
            QtWidgets.QMessageBox.information(self, "开机自启", "已启用开机自启。")
        except Exception as e:
            QtWidgets.QMessageBox.warning(self, "开机自启", f"设置开机自启失败: {e}")

    def disable_startup(self):
        """
        取消开机自启
        """
        try:
            key = winreg.OpenKey(winreg.HKEY_CURRENT_USER,
                                 r"Software\Microsoft\Windows\CurrentVersion\Run",
                                 0, winreg.KEY_SET_VALUE)
            winreg.DeleteValue(key, "MyTransparentApp")
            winreg.CloseKey(key)
            QtWidgets.QMessageBox.information(self, "开机自启", "已取消开机自启。")
        except FileNotFoundError:
            QtWidgets.QMessageBox.information(self, "开机自启", "开机自启未启用。")
        except Exception as e:
            QtWidgets.QMessageBox.warning(self, "开机自启", f"取消开机自启失败: {e}")

def main():
    global shared_memory
    # 防止重复启动
    shared_memory = QSharedMemory("MyTransparentAppUniqueKey")
    if not shared_memory.create(1):
        # 共享内存已存在，说明已有实例在运行
        app = QtWidgets.QApplication(sys.argv)
        QtWidgets.QMessageBox.warning(None, "程序已在运行", "程序已经在运行。")
        sys.exit()

    try:
        if not is_admin():
            if run_as_admin(sys.argv):
                sys.exit()
            else:
                QtWidgets.QMessageBox.warning(None, "管理员权限", "需要管理员权限才能运行此程序。")
                sys.exit()

        app = QtWidgets.QApplication(sys.argv)
        window = TransparentWindow()
        window.show()
        sys.exit(app.exec())
    except Exception as e:
        QtWidgets.QMessageBox.critical(None, "程序错误", f"程序发生未处理的错误: {e}")
        sys.exit(1)


# 初始化 last_unlock_time
last_unlock_time = get_last_unlock_time()
last_unlock_time_lock = threading.Lock()

if __name__ == "__main__":
    main()