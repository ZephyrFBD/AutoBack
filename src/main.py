# auto_periodic_backup_gui_final_v6.py
"""
最终版 v6（最终版本）
- 多进程可同时运行，只要监控不同目录
- 相同源目录不允许同时运行两个实例（通过 locks/<sha256(source)> + pid 检测）
- 其它功能见历史版本：快照备份、隐藏备份目录、托盘、时间轴、手动备份、单文件失败弹窗并跳过、全部恢复、日志文件、动态设置即时生效（支持小数分钟）
依赖: PyQt5, pywin32
pip install PyQt5 pywin32
"""
import sys
import os
import time
import json
import shutil
import threading
import hashlib
import atexit
from datetime import datetime, timedelta
import re
import traceback

from PyQt5 import QtWidgets, QtGui, QtCore

# Win32
try:
    import win32file, win32con, pywintypes, win32api, win32process
except Exception as e:
    raise RuntimeError("需要安装 pywin32: pip install pywin32") from e

# ---------------- CONFIG ----------------
APP_DIR = os.path.dirname(os.path.abspath(__file__))
LOCKS_DIR = os.path.join(APP_DIR, "locks")
CONFIG_FILE = os.path.join(APP_DIR, "backup_config.json")
LOG_FILE = os.path.join(APP_DIR, "backup.log")
TIMESTAMP_FMT = "%Y%m%d_%H%M%S"
INTERVAL_MINUTES_DEFAULT = 10.0
RETENTION_DAYS_DEFAULT = 30
TIME_DIR_RE = re.compile(r"^\d{8}_\d{6}$")
READ_CHUNK = 1024 * 1024
STILL_ACTIVE = 259  # GetExitCodeProcess returns 259 when process is still active on Windows
# ----------------------------------------

def now_ts():
    return datetime.now().strftime(TIMESTAMP_FMT)

def parse_ts_dirname(name):
    try:
        return datetime.strptime(name, TIMESTAMP_FMT)
    except Exception:
        return None

def load_config():
    try:
        if os.path.exists(CONFIG_FILE):
            with open(CONFIG_FILE, "r", encoding="utf-8") as f:
                return json.load(f)
    except Exception:
        pass
    return {}

def save_config(cfg):
    try:
        with open(CONFIG_FILE, "w", encoding="utf-8") as f:
            json.dump(cfg, f, indent=2, ensure_ascii=False)
    except Exception:
        pass

def ensure_hidden_dir(path):
    os.makedirs(path, exist_ok=True)
    if os.name == "nt":
        try:
            os.system(f'attrib +h "{path}"')
        except Exception:
            pass

# ---------------- process check ----------------
def is_pid_running(pid):
    """
    Windows-specific check using OpenProcess + GetExitCodeProcess.
    Returns True if process is running.
    """
    try:
        pid = int(pid)
        if pid <= 0:
            return False
        h = win32api.OpenProcess(win32con.PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
        code = win32process.GetExitCodeProcess(h)
        try:
            win32api.CloseHandle(h)
        except Exception:
            pass
        return code == STILL_ACTIVE
    except Exception:
        return False

# ---------------- lock utilities ----------------
def _source_lock_name(source_path):
    # canonicalize path (case-insensitive on Windows)
    norm = os.path.normcase(os.path.abspath(source_path))
    return hashlib.sha256(norm.encode("utf-8")).hexdigest()

def lock_dir_for_source(source_path):
    """
    Returns the lockdir path for given source path (not necessarily existing).
    """
    return os.path.join(LOCKS_DIR, _source_lock_name(source_path))

def acquire_lock_for_source(source_path, timeout=1.0):
    """
    Try to acquire lock for source path.
    If another live process holds the lock -> return (False, info_message)
    If stale lock (pid not running) -> remove and acquire.
    On success -> return (True, lockdir)
    """
    os.makedirs(LOCKS_DIR, exist_ok=True)
    lockdir = lock_dir_for_source(source_path)
    pidfile = os.path.join(lockdir, "pid")
    # Try create atomically
    try:
        os.mkdir(lockdir)
        # success: write pid
        with open(pidfile, "w", encoding="utf-8") as f:
            f.write(str(os.getpid()))
        return True, lockdir
    except FileExistsError:
        # lockdir exists; check pid inside
        try:
            if os.path.exists(pidfile):
                with open(pidfile, "r", encoding="utf-8") as f:
                    content = f.read().strip()
                try:
                    existing_pid = int(content)
                except Exception:
                    existing_pid = None
            else:
                existing_pid = None
        except Exception:
            existing_pid = None

        if existing_pid and is_pid_running(existing_pid):
            # live owner exists -> cannot acquire
            return False, f"已经有另一个备份进程 (PID={existing_pid}) 在监控该目录。请先停止它或选择不同目录。"
        else:
            # stale lock: remove and try again
            try:
                shutil.rmtree(lockdir)
            except Exception:
                # if cannot remove, fail
                return False, "发现旧锁但无法移除，请手动删除 locks 目录下对应文件夹后重试。"
            # attempt to create again
            try:
                os.mkdir(lockdir)
                with open(pidfile, "w", encoding="utf-8") as f:
                    f.write(str(os.getpid()))
                return True, lockdir
            except Exception as e:
                return False, f"尝试获取锁失败: {e}"
    except Exception as e:
        return False, f"获取锁时出错: {e}"

def release_lock_dir(lockdir):
    """
    Release a specific lockdir only if pid inside equals current pid (safety).
    If pid differs, do not remove.
    """
    try:
        pidfile = os.path.join(lockdir, "pid")
        if os.path.exists(pidfile):
            try:
                with open(pidfile, "r", encoding="utf-8") as f:
                    content = f.read().strip()
                existing_pid = int(content) if content else None
            except Exception:
                existing_pid = None
        else:
            existing_pid = None
        if existing_pid != os.getpid():
            # do not remove lock owned by another process
            return
        # remove
        try:
            if os.path.exists(lockdir):
                shutil.rmtree(lockdir)
        except Exception:
            pass
    except Exception:
        pass

def release_all_locks_for_current_pid():
    try:
        pid = os.getpid()
        if not os.path.isdir(LOCKS_DIR):
            return
        for name in os.listdir(LOCKS_DIR):
            lockdir = os.path.join(LOCKS_DIR, name)
            pidfile = os.path.join(lockdir, "pid")
            try:
                if os.path.exists(pidfile):
                    with open(pidfile, "r", encoding="utf-8") as f:
                        content = f.read().strip()
                    try:
                        existing_pid = int(content)
                    except Exception:
                        existing_pid = None
                else:
                    existing_pid = None
                if existing_pid == pid:
                    try:
                        shutil.rmtree(lockdir)
                    except Exception:
                        pass
            except Exception:
                pass
    except Exception:
        pass

# ensure clean up on exit
atexit.register(release_all_locks_for_current_pid)

# ---------------- Safe read (Win32) ----------------
def safe_copy_file(src_path, dest_path, logger=None):
    tmp = dest_path + ".tmp"
    try:
        os.makedirs(os.path.dirname(dest_path), exist_ok=True)
        handle = win32file.CreateFile(
            src_path,
            win32con.GENERIC_READ,
            win32con.FILE_SHARE_READ | win32con.FILE_SHARE_WRITE | win32con.FILE_SHARE_DELETE,
            None,
            win32con.OPEN_EXISTING,
            win32con.FILE_ATTRIBUTE_NORMAL,
            None
        )
        with open(tmp, "wb") as out:
            while True:
                hr, data = win32file.ReadFile(handle, READ_CHUNK)
                if not data:
                    break
                out.write(data)
        try:
            handle.Close()
        except Exception:
            pass
        try:
            shutil.copystat(src_path, tmp)
        except Exception:
            pass
        try:
            if os.path.exists(dest_path):
                os.replace(tmp, dest_path)
            else:
                os.rename(tmp, dest_path)
        except Exception:
            shutil.copy2(tmp, dest_path)
            try:
                os.remove(tmp)
            except Exception:
                pass
        return True
    except pywintypes.error as e:
        if logger:
            logger(f"读取被占用文件: {src_path} -> {e}")
        try:
            if os.path.exists(tmp):
                os.remove(tmp)
        except:
            pass
        return False
    except Exception as e:
        if logger:
            logger(f"备份文件出错: {src_path} -> {e}")
        try:
            if os.path.exists(tmp):
                os.remove(tmp)
        except:
            pass
        return False

# ---------------- Backup Worker ----------------
class BackupWorker(threading.Thread):
    def __init__(self, source_dir, backup_dir, window, interval_minutes=INTERVAL_MINUTES_DEFAULT, retention_days=RETENTION_DAYS_DEFAULT):
        super().__init__(daemon=True)
        self.source_dir = os.path.abspath(source_dir)
        self.backup_dir = os.path.abspath(backup_dir)
        self.window = window
        self._lock = threading.Lock()
        self._interval_seconds = float(interval_minutes) * 60.0
        self._retention_days = int(retention_days)
        self._stop_event = threading.Event()

    def stop(self):
        self._stop_event.set()

    def update_interval_minutes(self, minutes):
        try:
            with self._lock:
                self._interval_seconds = max(0.1, float(minutes)) * 60.0
            self.log(f"备份间隔已更新为 {minutes} 分钟（即时生效）")
        except Exception as e:
            try:
                self.window.error_signal.emit("更新失败", f"更新备份间隔出错: {e}")
            except Exception:
                pass

    def update_retention_days(self, days):
        try:
            with self._lock:
                self._retention_days = max(1, int(days))
            self.log(f"保留天数已更新为 {days} 天（即时生效）")
        except Exception as e:
            try:
                self.window.error_signal.emit("更新失败", f"更新保留天数出错: {e}")
            except Exception:
                pass

    def _get_interval_seconds(self):
        with self._lock:
            return self._interval_seconds

    def _get_retention_days(self):
        with self._lock:
            return self._retention_days

    def log(self, msg):
        ts = datetime.now().strftime("%H:%M:%S")
        self.window.log_signal.emit(f"[{ts}] {msg}")

    def run_snapshot(self):
        ts = now_ts()
        snap_root = os.path.join(self.backup_dir, ts)
        try:
            os.makedirs(snap_root, exist_ok=True)
        except Exception as e:
            try:
                self.window.error_signal.emit("创建快照失败", f"无法创建快照目录 {snap_root}: {e}")
            except Exception:
                pass
            return

        self.log("开始一次快照备份...")
        files_copied = 0
        try:
            for root, dirs, files in os.walk(self.source_dir):
                abs_root = os.path.abspath(root)
                if os.path.abspath(self.backup_dir).startswith(os.path.abspath(self.source_dir)) and abs_root.startswith(os.path.abspath(self.backup_dir)):
                    continue
                rel_dir = os.path.relpath(root, self.source_dir)
                dest_dir = snap_root if rel_dir == "." else os.path.join(snap_root, rel_dir)
                try:
                    os.makedirs(dest_dir, exist_ok=True)
                except Exception as e:
                    self.log(f"无法创建目录 {dest_dir}: {e}")
                    continue
                for d in dirs:
                    try:
                        os.makedirs(os.path.join(dest_dir, d), exist_ok=True)
                    except Exception:
                        pass
                for f in files:
                    src_path = os.path.join(root, f)
                    dest_path = os.path.join(dest_dir, f)
                    ok = safe_copy_file(src_path, dest_path, logger=self.log)
                    if ok:
                        files_copied += 1
                    else:
                        # 弹窗并继续
                        try:
                            self.window.error_signal.emit("文件读取失败", f"无法读取并备份文件：\n{src_path}\n（已跳过此文件，备份将继续）")
                        except Exception:
                            pass
            self.log(f"快照完成: {files_copied} 个文件 -> {snap_root}")
        except Exception as e:
            tb = traceback.format_exc()
            try:
                self.window.error_signal.emit("快照失败", f"{e}\n\n{tb}")
            except Exception:
                pass

    def cleanup_old_snapshots(self):
        retention_days = self._get_retention_days()
        cutoff = datetime.now() - timedelta(days=retention_days)
        removed = 0
        try:
            if not os.path.isdir(self.backup_dir):
                return
            for name in os.listdir(self.backup_dir):
                path = os.path.join(self.backup_dir, name)
                if not os.path.isdir(path):
                    continue
                if not TIME_DIR_RE.match(name):
                    continue
                ts = parse_ts_dirname(name)
                if not ts:
                    continue
                if ts < cutoff:
                    try:
                        shutil.rmtree(path)
                        removed += 1
                    except Exception as e:
                        self.log(f"删除旧快照失败: {path} -> {e}")
            if removed:
                self.log(f"已删除 {removed} 个超过 {retention_days} 天的旧快照")
        except Exception as e:
            try:
                self.window.error_signal.emit("清理失败", f"清理旧快照时发生错误: {e}")
            except Exception:
                pass

    def run(self):
        try:
            ensure_hidden_dir(self.backup_dir)
        except Exception as e:
            try:
                self.window.error_signal.emit("创建备份目录失败", f"无法创建或隐藏备份目录 {self.backup_dir}: {e}")
            except Exception:
                pass
            return

        while not self._stop_event.is_set():
            try:
                self.run_snapshot()
                self.cleanup_old_snapshots()
            except Exception as e:
                tb = traceback.format_exc()
                try:
                    self.window.error_signal.emit("备份线程异常", f"{e}\n\n{tb}")
                except Exception:
                    pass
            interval = self._get_interval_seconds()
            if interval <= 0:
                interval = 0.1
            end_time = time.monotonic() + float(interval)
            while time.monotonic() < end_time and not self._stop_event.is_set():
                time.sleep(0.5)

# ---------------- Timeline Viewer ----------------
class TimelineViewer(QtWidgets.QWidget):
    def __init__(self, backup_dir, source_dir, main_window=None):
        super().__init__()
        self.backup_dir = backup_dir
        self.source_dir = source_dir
        self.main_window = main_window
        self.setWindowTitle("备份回溯 - 时间轴")
        self.resize(900, 600)
        self.timeline = {}
        self.timestamps = []

        self.slider = QtWidgets.QSlider(QtCore.Qt.Horizontal)
        self.slider.setMinimum(0)
        self.slider.setMaximum(0)
        self.slider.valueChanged.connect(self.on_slider_changed)
        self.label_time = QtWidgets.QLabel("时间点: -")
        self.list_files = QtWidgets.QListWidget()
        self.list_files.setSelectionMode(QtWidgets.QAbstractItemView.ExtendedSelection)

        btn_restore = QtWidgets.QPushButton("恢复选中文件到源目录")
        btn_restore_all = QtWidgets.QPushButton("全部恢复（恢复此快照并删除源中新建文件）")
        btn_export = QtWidgets.QPushButton("另存为...")
        btn_refresh = QtWidgets.QPushButton("刷新")

        btn_restore.clicked.connect(self.restore_selected)
        btn_restore_all.clicked.connect(self.restore_all_confirm)
        btn_export.clicked.connect(self.export_selected)
        btn_refresh.clicked.connect(self.refresh)

        layout = QtWidgets.QVBoxLayout(self)
        layout.addWidget(self.slider)
        layout.addWidget(self.label_time)
        layout.addWidget(self.list_files)
        h = QtWidgets.QHBoxLayout()
        h.addWidget(btn_restore)
        h.addWidget(btn_restore_all)
        h.addWidget(btn_export)
        h.addWidget(btn_refresh)
        layout.addLayout(h)

        self.refresh()

    def log(self, text):
        if self.main_window:
            try:
                self.main_window.log_signal.emit(text)
            except Exception:
                pass

    def error(self, title, msg):
        if self.main_window:
            try:
                self.main_window.error_signal.emit(title, msg)
            except Exception:
                pass
        else:
            QtWidgets.QMessageBox.critical(self, title, msg)

    def refresh(self):
        self.timeline.clear()
        if not os.path.exists(self.backup_dir):
            self.slider.setMinimum(0); self.slider.setMaximum(0)
            self.label_time.setText("未发现备份")
            self.list_files.clear()
            return
        try:
            names = [n for n in os.listdir(self.backup_dir) if os.path.isdir(os.path.join(self.backup_dir, n)) and TIME_DIR_RE.match(n)]
            ts_pairs = []
            for n in names:
                ts = parse_ts_dirname(n)
                if ts:
                    ts_pairs.append((ts, os.path.join(self.backup_dir, n)))
            ts_pairs.sort()
            for ts, path in ts_pairs:
                files = []
                for root, _, files_in in os.walk(path):
                    for f in files_in:
                        full = os.path.join(root, f)
                        rel = os.path.relpath(full, path)
                        files.append(rel)
                self.timeline[ts] = sorted(files)
            self.timestamps = sorted(self.timeline.keys())
            if not self.timestamps:
                self.slider.setMinimum(0); self.slider.setMaximum(0); self.slider.setValue(0)
                self.label_time.setText("未发现任何备份快照")
                self.list_files.clear()
                return
            self.slider.setMinimum(0)
            self.slider.setMaximum(max(0, len(self.timestamps) - 1))
            self.slider.setValue(len(self.timestamps) - 1)
            self.show_time_index(len(self.timestamps) - 1)
        except Exception as e:
            self.error("时间轴错误", f"读取备份快照时出错：{e}")

    def on_slider_changed(self, idx):
        self.show_time_index(idx)

    def show_time_index(self, idx):
        if not self.timestamps:
            return
        ts = self.timestamps[idx]
        files = self.timeline.get(ts, [])
        self.label_time.setText(f"时间点: {ts.strftime('%Y-%m-%d %H:%M:%S')} （{len(files)} 个文件）")
        self.list_files.clear()
        for rel in files:
            item = QtWidgets.QListWidgetItem(rel)
            self.list_files.addItem(item)

    def restore_selected(self):
        items = self.list_files.selectedItems()
        if not items:
            QtWidgets.QMessageBox.warning(self, "提示", "请先选择要恢复的文件。")
            return
        ok = QtWidgets.QMessageBox.question(self, "确认", f"将恢复 {len(items)} 个文件到源目录（可能覆盖），继续？")
        if ok != QtWidgets.QMessageBox.Yes:
            return
        idx = self.slider.value()
        ts = self.timestamps[idx]
        snap_dir = os.path.join(self.backup_dir, ts.strftime(TIMESTAMP_FMT))

        def worker():
            errors = []
            for item in items:
                rel = item.text()
                src = os.path.join(snap_dir, rel)
                dest = os.path.join(self.source_dir, rel)
                try:
                    os.makedirs(os.path.dirname(dest), exist_ok=True)
                    shutil.copy2(src, dest)
                    self.log(f"[{datetime.now().strftime('%H:%M:%S')}] 恢复: {rel}")
                except Exception as e:
                    errors.append(f"{src} -> {e}")
            if errors:
                self.error("恢复失败", "部分文件恢复失败：\n" + "\n".join(errors))
            else:
                QtWidgets.QMessageBox.information(self, "完成", "已恢复选中文件。")
        threading.Thread(target=worker, daemon=True).start()

    def export_selected(self):
        items = self.list_files.selectedItems()
        if not items:
            QtWidgets.QMessageBox.warning(self, "提示", "请先选择要导出的文件。")
            return
        dest_dir = QtWidgets.QFileDialog.getExistingDirectory(self, "选择导出目标目录")
        if not dest_dir:
            return
        idx = self.slider.value()
        ts = self.timestamps[idx]
        snap_dir = os.path.join(self.backup_dir, ts.strftime(TIMESTAMP_FMT))

        def worker():
            errors = []
            for item in items:
                rel = item.text()
                src = os.path.join(snap_dir, rel)
                dest = os.path.join(dest_dir, rel)
                try:
                    os.makedirs(os.path.dirname(dest), exist_ok=True)
                    shutil.copy2(src, dest)
                except Exception as e:
                    errors.append(f"{src} -> {e}")
            if errors:
                self.error("导出失败", "部分文件导出失败：\n" + "\n".join(errors))
            else:
                QtWidgets.QMessageBox.information(self, "完成", "已导出选中文件。")
        threading.Thread(target=worker, daemon=True).start()

    def restore_all_confirm(self):
        items_count = len(self.timeline.get(self.timestamps[self.slider.value()], [])) if self.timestamps else 0
        reply = QtWidgets.QMessageBox.question(
            self,
            "全部恢复确认",
            "【警告】全部恢复会把源目录恢复为选中快照的完整状态，"
            "这会删除源目录中不在快照中的文件/文件夹（不可逆）。\n\n"
            f"该快照包含 {items_count} 个文件。\n\n是否继续？",
            QtWidgets.QMessageBox.Yes | QtWidgets.QMessageBox.No,
            QtWidgets.QMessageBox.No
        )
        if reply != QtWidgets.QMessageBox.Yes:
            return
        idx = self.slider.value()
        ts = self.timestamps[idx]
        snap_dir = os.path.join(self.backup_dir, ts.strftime(TIMESTAMP_FMT))
        threading.Thread(target=self._do_full_restore, args=(snap_dir,), daemon=True).start()

    def _do_full_restore(self, snap_dir):
        self.log(f"[{datetime.now().strftime('%H:%M:%S')}] 开始全量恢复 -> {snap_dir}")
        errors = []
        snapshot_files = set()
        snapshot_dirs = set()
        for root, dirs, files in os.walk(snap_dir):
            rel_root = os.path.relpath(root, snap_dir)
            if rel_root == ".":
                rel_root = ""
            snapshot_dirs.add(rel_root)
            for f in files:
                rel_path = os.path.normpath(os.path.join(rel_root, f)).lstrip(os.sep)
                snapshot_files.add(rel_path)
                src = os.path.join(root, f)
                dest = os.path.join(self.source_dir, rel_path)
                try:
                    os.makedirs(os.path.dirname(dest), exist_ok=True)
                    shutil.copy2(src, dest)
                except Exception as e:
                    errors.append(f"复制失败: {src} -> {e}")

        try:
            backup_abs = os.path.abspath(self.main_window.edit_backup.text().strip()) if self.main_window and self.main_window.edit_backup.text().strip() else None
        except Exception:
            backup_abs = None

        for root, dirs, files in os.walk(self.source_dir):
            abs_root = os.path.abspath(root)
            if backup_abs and abs_root.startswith(backup_abs):
                continue
            rel_root = os.path.relpath(root, self.source_dir)
            if rel_root == ".":
                rel_root = ""
            for f in files:
                rel_path = os.path.normpath(os.path.join(rel_root, f)).lstrip(os.sep)
                if rel_path not in snapshot_files:
                    fp = os.path.join(root, f)
                    try:
                        os.remove(fp)
                        self.log(f"[{datetime.now().strftime('%H:%M:%S')}] 删除文件: {rel_path}")
                    except Exception as e:
                        errors.append(f"删除文件失败: {fp} -> {e}")

        for root, dirs, files in os.walk(self.source_dir, topdown=False):
            abs_root = os.path.abspath(root)
            if backup_abs and abs_root.startswith(backup_abs):
                continue
            rel_root = os.path.relpath(root, self.source_dir)
            if rel_root == ".":
                rel_root = ""
            if rel_root not in snapshot_dirs:
                try:
                    if not os.listdir(root):
                        os.rmdir(root)
                        self.log(f"[{datetime.now().strftime('%H:%M:%S')}] 删除空目录: {rel_root}")
                except Exception as e:
                    errors.append(f"删除目录失败: {root} -> {e}")

        if errors:
            self.error("全量恢复完成（有错误）", "全量恢复完成，但存在如下错误：\n" + "\n".join(errors))
        else:
            if self.main_window:
                QtWidgets.QMessageBox.information(self.main_window, "完成", "全量恢复已完成。")
            else:
                QtWidgets.QMessageBox.information(self, "完成", "全量恢复已完成。")
        self.log(f"[{datetime.now().strftime('%H:%M:%S')}] 全量恢复任务完成")

# ---------------- Main Window & Tray ----------------
class MainWindow(QtWidgets.QWidget):
    log_signal = QtCore.pyqtSignal(str)
    error_signal = QtCore.pyqtSignal(str, str)

    def __init__(self):
        super().__init__()
        self.setWindowTitle("自动周期快照备份 (v6)")
        self.resize(980, 680)

        cfg = load_config()
        self.source_dir = cfg.get("source", "")
        self.backup_dir = cfg.get("backup", "")
        interval = cfg.get("interval", INTERVAL_MINUTES_DEFAULT)
        retention = cfg.get("retention", RETENTION_DAYS_DEFAULT)

        # UI widgets
        self.edit_source = QtWidgets.QLineEdit(self.source_dir)
        self.btn_browse_source = QtWidgets.QPushButton("选择源文件夹")
        self.edit_backup = QtWidgets.QLineEdit(self.backup_dir)
        self.btn_browse_backup = QtWidgets.QPushButton("选择备份文件夹 (留空则在源目录创建 .backup_versions)")

        self.spin_interval = QtWidgets.QDoubleSpinBox()
        self.spin_interval.setMinimum(0.1)
        self.spin_interval.setMaximum(24*60)
        self.spin_interval.setDecimals(2)
        self.spin_interval.setSingleStep(0.5)
        try:
            self.spin_interval.setValue(float(interval))
        except Exception:
            self.spin_interval.setValue(float(INTERVAL_MINUTES_DEFAULT))

        self.spin_retention = QtWidgets.QSpinBox()
        self.spin_retention.setMinimum(1)
        self.spin_retention.setMaximum(3650)
        self.spin_retention.setValue(int(retention))

        self.btn_start = QtWidgets.QPushButton("开始备份")
        self.btn_stop = QtWidgets.QPushButton("停止备份")
        self.btn_manual = QtWidgets.QPushButton("手动备份（立即）")
        self.btn_hide = QtWidgets.QPushButton("后台运行（最小化到托盘）")
        self.btn_open_backup = QtWidgets.QPushButton("打开备份文件夹")
        self.btn_open_timeline = QtWidgets.QPushButton("打开回溯时间轴")
        self.btn_export_log = QtWidgets.QPushButton("导出日志")

        self.text_log = QtWidgets.QTextEdit(readOnly=True)

        # Layout
        form = QtWidgets.QGridLayout()
        form.addWidget(QtWidgets.QLabel("源文件夹:"), 0, 0)
        form.addWidget(self.edit_source, 0, 1)
        form.addWidget(self.btn_browse_source, 0, 2)
        form.addWidget(QtWidgets.QLabel("备份文件夹:"), 1, 0)
        form.addWidget(self.edit_backup, 1, 1)
        form.addWidget(self.btn_browse_backup, 1, 2)
        form.addWidget(QtWidgets.QLabel("备份间隔 (分钟):"), 2, 0)
        form.addWidget(self.spin_interval, 2, 1)
        form.addWidget(QtWidgets.QLabel("保留天数:"), 3, 0)
        form.addWidget(self.spin_retention, 3, 1)

        btn_h = QtWidgets.QHBoxLayout()
        btn_h.addWidget(self.btn_start)
        btn_h.addWidget(self.btn_stop)
        btn_h.addWidget(self.btn_manual)
        btn_h.addWidget(self.btn_hide)
        btn_h.addWidget(self.btn_open_backup)
        btn_h.addWidget(self.btn_open_timeline)
        btn_h.addWidget(self.btn_export_log)

        main_layout = QtWidgets.QVBoxLayout(self)
        main_layout.addLayout(form)
        main_layout.addLayout(btn_h)
        main_layout.addWidget(QtWidgets.QLabel("日志 (同时写入 backup.log):"))
        main_layout.addWidget(self.text_log)

        # connect signals
        self.btn_browse_source.clicked.connect(self.browse_source)
        self.btn_browse_backup.clicked.connect(self.browse_backup)
        self.btn_start.clicked.connect(lambda: self.start_backup(auto=False))
        self.btn_stop.clicked.connect(self.stop_backup)
        self.btn_manual.clicked.connect(self.manual_backup)
        self.btn_hide.clicked.connect(self.hide_to_tray)
        self.btn_open_backup.clicked.connect(self.open_backup_folder)
        self.btn_open_timeline.clicked.connect(self.open_timeline)
        self.btn_export_log.clicked.connect(self.export_log)

        self.spin_interval.valueChanged.connect(self.on_interval_changed)
        self.spin_retention.valueChanged.connect(self.on_retention_changed)

        # tray
        icon = self.style().standardIcon(QtWidgets.QStyle.SP_DriveHDIcon)
        self.tray_icon = QtWidgets.QSystemTrayIcon(icon)
        menu = QtWidgets.QMenu()
        open_action = menu.addAction("打开窗口")
        exit_action = menu.addAction("退出")
        open_action.triggered.connect(self.show_window)
        exit_action.triggered.connect(self.quit_app)
        self.tray_icon.setContextMenu(menu)
        self.tray_icon.activated.connect(self.on_tray_activated)
        self.tray_icon.setToolTip("自动周期快照备份")
        self.tray_icon.show()

        # signals
        self.log_signal.connect(self.append_log)
        self.error_signal.connect(self.show_error_dialog)

        # state
        self.worker = None
        self.timeline_window = None
        self.current_lockdir = None

        # log file management
        self._log_lock = threading.Lock()
        self._load_log_file_to_ui()

        # load config & auto-start
        self.load_config_to_ui()
        if self.edit_source.text().strip():
            QtCore.QTimer.singleShot(700, lambda: self.start_backup(auto=True))

    # --------------- lock helpers in instance ---------------
    def _acquire_lock(self, source):
        ok, result = acquire_lock_for_source(source)
        if ok:
            self.current_lockdir = result
            return True, ""
        else:
            return False, result

    def _release_lock(self):
        if self.current_lockdir:
            try:
                release_lock_dir(self.current_lockdir)
            except Exception:
                pass
            self.current_lockdir = None

    # --------------- log utilities ---------------
    def _write_log_line(self, line):
        try:
            with self._log_lock:
                with open(LOG_FILE, "a", encoding="utf-8") as f:
                    f.write(line + "\n")
        except Exception:
            pass

    def _load_log_file_to_ui(self):
        try:
            if os.path.exists(LOG_FILE):
                with open(LOG_FILE, "r", encoding="utf-8") as f:
                    content = f.read()
                if content:
                    self.text_log.setPlainText(content)
        except Exception:
            pass

    # --------------- UI callbacks ---------------
    def browse_source(self):
        d = QtWidgets.QFileDialog.getExistingDirectory(self, "选择源文件夹")
        if d:
            self.edit_source.setText(d)

    def browse_backup(self):
        d = QtWidgets.QFileDialog.getExistingDirectory(self, "选择备份文件夹")
        if d:
            self.edit_backup.setText(d)

    def append_log(self, text):
        try:
            self.text_log.append(text)
            self._write_log_line(text)
        except Exception:
            pass

    def show_error_dialog(self, title, message):
        try:
            QtWidgets.QMessageBox.critical(self, title, message)
            self.append_log(f"[{datetime.now().strftime('%H:%M:%S')}] ❗ {title}: {message}")
        except Exception:
            pass

    def start_backup(self, auto=False):
        source = self.edit_source.text().strip()
        backup = self.edit_backup.text().strip()
        interval = float(self.spin_interval.value())
        retention = int(self.spin_retention.value())

        if not source:
            if not auto:
                QtWidgets.QMessageBox.warning(self, "提示", "请先选择源文件夹")
            return
        if not os.path.isdir(source):
            if not auto:
                QtWidgets.QMessageBox.warning(self, "提示", "源文件夹不存在")
            return

        # if there's a running worker that monitors different directory -> require stop first
        if self.worker and getattr(self.worker, "is_alive", lambda: False)():
            if os.path.abspath(source) != os.path.abspath(self.worker.source_dir):
                QtWidgets.QMessageBox.warning(self, "警告", "当前已有运行中的备份线程，它监控不同目录。请先停止它，然后再启动监控不同目录。")
                return

        if not backup:
            backup = os.path.join(source, ".backup_versions")
            try:
                ensure_hidden_dir(backup)
            except Exception as e:
                self.error_signal.emit("创建备份目录失败", f"无法创建或隐藏备份目录 {backup}: {e}")
                return
            self.edit_backup.setText(backup)

        cfg = {"source": source, "backup": backup, "interval": float(interval), "retention": int(retention)}
        save_config(cfg)

        # Acquire cross-process lock before starting worker
        if not (self.current_lockdir and os.path.abspath(source) == os.path.abspath(self.source_dir)):
            ok, info = self._acquire_lock(source)
            if not ok:
                # cannot acquire lock
                QtWidgets.QMessageBox.critical(self, "锁冲突", info)
                return

        # start or update worker
        if self.worker and getattr(self.worker, "is_alive", lambda: False)():
            try:
                self.worker.update_interval_minutes(interval)
                self.worker.update_retention_days(retention)
                self.append_log(f"[{datetime.now().strftime('%H:%M:%S')}] 备份线程已在运行，已更新设置")
                if not auto:
                    QtWidgets.QMessageBox.information(self, "提示", "备份线程已在运行，已更新设置")
                if auto:
                    self.hide()
            except Exception as e:
                self.error_signal.emit("更新运行中线程失败", str(e))
            return

        try:
            self.worker = BackupWorker(source, backup, self, interval_minutes=interval, retention_days=retention)
            self.worker.start()
            self.source_dir = source
            self.backup_dir = backup
            self.append_log(f"[{datetime.now().strftime('%H:%M:%S')}] 🟢 已启动后台备份（每 {interval} 分钟）")
            if auto:
                self.hide()
        except Exception as e:
            tb = traceback.format_exc()
            self.error_signal.emit("启动备份失败", f"{e}\n\n{tb}")
            # release lock in case we created it
            self._release_lock()
            self.worker = None

    def stop_backup(self):
        if self.worker:
            try:
                self.worker.stop()
                self.append_log(f"[{datetime.now().strftime('%H:%M:%S')}] 🔴 停止备份请求已发送")
            except Exception as e:
                self.error_signal.emit("停止失败", str(e))
            self.worker = None
            # release cross-process lock
            self._release_lock()
        else:
            self.append_log("备份线程未在运行")

    def manual_backup(self):
        source = self.edit_source.text().strip()
        backup = self.edit_backup.text().strip()
        if not source:
            QtWidgets.QMessageBox.warning(self, "提示", "请先选择源文件夹")
            return

        if not backup:
            backup = os.path.join(source, ".backup_versions")
            try:
                ensure_hidden_dir(backup)
            except Exception as e:
                self.error_signal.emit("创建备份目录失败", f"无法创建或隐藏备份目录 {backup}: {e}")
                return
            self.edit_backup.setText(backup)

        # If worker is running and monitors same source, use its snapshot directly
        def worker_snapshot_with_lock():
            # If current process already holds lock for this source, just run snapshot
            held_here = (self.current_lockdir is not None and os.path.abspath(source) == os.path.abspath(self.source_dir))
            temp_lockdir = None
            acquired_temp = False
            if not held_here:
                ok, result = acquire_lock_for_source(source)
                if not ok:
                    QtWidgets.QMessageBox.critical(self, "锁冲突", result)
                    return
                temp_lockdir = result
                acquired_temp = True
            try:
                if self.worker and getattr(self.worker, "is_alive", lambda: False)() and os.path.abspath(source) == os.path.abspath(self.worker.source_dir):
                    # reuse worker
                    try:
                        self.worker.run_snapshot()
                        self.worker.cleanup_old_snapshots()
                    except Exception as e:
                        tb = traceback.format_exc()
                        self.error_signal.emit("手动备份失败", f"{e}\n\n{tb}")
                else:
                    # create temporary worker to snapshot once
                    tmp = BackupWorker(source, backup, self, interval_minutes=float(self.spin_interval.value()), retention_days=int(self.spin_retention.value()))
                    try:
                        ensure_hidden_dir(backup)
                    except Exception as e:
                        self.error_signal.emit("创建备份目录失败", f"无法创建或隐藏备份目录 {backup}: {e}")
                        return
                    try:
                        tmp.run_snapshot()
                        tmp.cleanup_old_snapshots()
                    except Exception as e:
                        tb = traceback.format_exc()
                        self.error_signal.emit("手动备份失败", f"{e}\n\n{tb}")
            finally:
                if acquired_temp and temp_lockdir:
                    # release temp lock
                    release_lock_dir(temp_lockdir)

        threading.Thread(target=worker_snapshot_with_lock, daemon=True).start()
        self.append_log(f"[{datetime.now().strftime('%H:%M:%S')}] 手动备份已触发（后台执行）")

    def hide_to_tray(self):
        self.hide()
        self.append_log(f"[{datetime.now().strftime('%H:%M:%S')}] 📥 已切换到后台运行（托盘）")

    def open_backup_folder(self):
        backup = self.edit_backup.text().strip()
        if not backup:
            QtWidgets.QMessageBox.warning(self, "提示", "备份目录未设置")
            return
        if not os.path.exists(backup):
            QtWidgets.QMessageBox.warning(self, "提示", "备份目录不存在")
            return
        os.startfile(backup)

    def open_timeline(self):
        backup = self.edit_backup.text().strip()
        source = self.edit_source.text().strip()
        if not backup or not os.path.exists(backup):
            QtWidgets.QMessageBox.warning(self, "提示", "请先设置并运行一次备份以生成快照目录")
            return
        if self.timeline_window is None:
            self.timeline_window = TimelineViewer(backup, source, main_window=self)
            self.timeline_window.setAttribute(QtCore.Qt.WA_DeleteOnClose)
            self.timeline_window.destroyed.connect(lambda: setattr(self, "timeline_window", None))
            self.timeline_window.main_window = self
            self.timeline_window.show()
        else:
            self.timeline_window.raise_()
            self.timeline_window.activateWindow()

    def export_log(self):
        if not os.path.exists(LOG_FILE):
            QtWidgets.QMessageBox.information(self, "导出日志", "日志文件不存在（尚未产生任何日志）")
            return
        dest, _ = QtWidgets.QFileDialog.getSaveFileName(self, "导出日志为", os.path.join(os.path.expanduser("~"), "backup.log"), "Log files (*.log);;All files (*.*)")
        if not dest:
            return
        try:
            shutil.copy2(LOG_FILE, dest)
            QtWidgets.QMessageBox.information(self, "导出日志", f"日志已导出到:\n{dest}")
        except Exception as e:
            QtWidgets.QMessageBox.critical(self, "导出失败", f"导出日志失败: {e}")

    def show_window(self):
        self.showNormal()
        self.activateWindow()

    def on_tray_activated(self, reason):
        if reason == QtWidgets.QSystemTrayIcon.Trigger:
            self.show_window()

    def quit_app(self):
        if self.worker:
            try:
                self.worker.stop()
            except Exception:
                pass
        # release any lock owned by this process
        self._release_lock()
        QtWidgets.QApplication.quit()

    def load_config_to_ui(self):
        try:
            cfg = load_config()
            src = cfg.get("source", "")
            bk = cfg.get("backup", "")
            interval = cfg.get("interval", INTERVAL_MINUTES_DEFAULT)
            retention = cfg.get("retention", RETENTION_DAYS_DEFAULT)
            self.edit_source.setText(src)
            self.edit_backup.setText(bk)
            try:
                self.spin_interval.setValue(float(interval))
            except Exception:
                self.spin_interval.setValue(float(INTERVAL_MINUTES_DEFAULT))
            try:
                self.spin_retention.setValue(int(retention))
            except Exception:
                self.spin_retention.setValue(int(RETENTION_DAYS_DEFAULT))
        except Exception as e:
            try:
                self.error_signal.emit("加载配置失败", str(e))
            except Exception:
                pass

    def on_interval_changed(self, value):
        cfg = load_config()
        cfg["interval"] = float(value)
        cfg["source"] = self.edit_source.text().strip()
        cfg["backup"] = self.edit_backup.text().strip()
        cfg["retention"] = int(self.spin_retention.value())
        save_config(cfg)
        self.append_log(f"[{datetime.now().strftime('%H:%M:%S')}] ⚙️ 间隔设置已改为 {value} 分钟")
        if self.worker and getattr(self.worker, "is_alive", lambda: False)():
            try:
                self.worker.update_interval_minutes(value)
            except Exception as e:
                self.error_signal.emit("更新间隔失败", str(e))

    def on_retention_changed(self, value):
        cfg = load_config()
        cfg["retention"] = int(value)
        cfg["source"] = self.edit_source.text().strip()
        cfg["backup"] = self.edit_backup.text().strip()
        cfg["interval"] = float(self.spin_interval.value())
        save_config(cfg)
        self.append_log(f"[{datetime.now().strftime('%H:%M:%S')}] ⚙️ 保留天数已改为 {value} 天")
        if self.worker and getattr(self.worker, "is_alive", lambda: False)():
            try:
                self.worker.update_retention_days(value)
            except Exception as e:
                self.error_signal.emit("更新保留天数失败", str(e))

# ---------------- Program entry ----------------
def main():
    app = QtWidgets.QApplication(sys.argv)
    win = MainWindow()
    win.show()
    sys.exit(app.exec_())

if __name__ == "__main__":
    main()
