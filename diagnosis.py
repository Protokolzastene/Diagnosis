
import argparse
import os
import platform
import re
import sqlite3
import statistics
import subprocess
import sys
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class SystemSample:
    ts: float
    mem_total: int          # bytes
    mem_used: int            # bytes
    mem_percent: float
    swap_total: int          # bytes
    swap_used: int            # bytes
    cpu_percent: float


@dataclass
class ProcSample:
    pid: int
    name: str
    rss: int                  # bytes
    cpu_percent: float


@dataclass
class LeakCandidate:
    pid: int
    name: str
    growth_mb_per_hour: float
    current_rss_mb: float
    duration_minutes: float
    confidence: float


def human_mb(num_bytes: float) -> float:
    return num_bytes / (1024 * 1024)



class BaseSampler:
    """Common state for delta-based CPU% calculations."""

    def __init__(self):
        self._prev_cpu_total = None
        self._prev_cpu_idle = None
        self._prev_proc_times = {}
        self.num_cpus = os.cpu_count() or 1

    def sample_system(self) -> SystemSample:
        raise NotImplementedError

    def sample_processes(self) -> list:
        raise NotImplementedError


class LinuxSampler(BaseSampler):
    def __init__(self):
        super().__init__()
        try:
            self.clk_tck = os.sysconf("SC_CLK_TCK")
        except (AttributeError, ValueError):
            self.clk_tck = 100

    def _read_meminfo(self):
        info = {}
        try:
            with open("/proc/meminfo") as f:
                for line in f:
                    parts = line.split(":")
                    if len(parts) != 2:
                        continue
                    key = parts[0].strip()
                    val = parts[1].strip().split()[0]  # value in kB
                    info[key] = int(val) * 1024
        except OSError:
            pass
        return info

    def sample_system(self) -> SystemSample:
        info = self._read_meminfo()
        mem_total = info.get("MemTotal", 0)
        mem_available = info.get(
            "MemAvailable",
            info.get("MemFree", 0) + info.get("Buffers", 0) + info.get("Cached", 0),
            )
        mem_used = max(mem_total - mem_available, 0)
        mem_percent = (mem_used / mem_total * 100) if mem_total else 0.0
        swap_total = info.get("SwapTotal", 0)
        swap_free = info.get("SwapFree", 0)
        swap_used = max(swap_total - swap_free, 0)

        cpu_percent = 0.0
        try:
            with open("/proc/stat") as f:
                line = f.readline()
            fields = [int(x) for x in line.split()[1:]]
            idle = fields[3] + (fields[4] if len(fields) > 4 else 0)
            total = sum(fields)
            if self._prev_cpu_total is not None:
                dt_total = total - self._prev_cpu_total
                dt_idle = idle - self._prev_cpu_idle
                if dt_total > 0:
                    cpu_percent = max(0.0, min(100.0, (1 - dt_idle / dt_total) * 100))
            self._prev_cpu_total, self._prev_cpu_idle = total, idle
        except OSError:
            pass

        return SystemSample(
            ts=time.time(),
            mem_total=mem_total,
            mem_used=mem_used,
            mem_percent=mem_percent,
            swap_total=swap_total,
            swap_used=swap_used,
            cpu_percent=cpu_percent,
        )

    def sample_processes(self) -> list:
        now = time.time()
        results = []
        seen_pids = set()
        try:
            pids = [p for p in os.listdir("/proc") if p.isdigit()]
        except OSError:
            return results

        for pid_s in pids:
            pid = int(pid_s)
            base = f"/proc/{pid_s}"
            try:
                with open(f"{base}/comm") as f:
                    name = f.read().strip()
            except OSError:
                continue

            rss = 0
            try:
                with open(f"{base}/status") as f:
                    for line in f:
                        if line.startswith("VmRSS:"):
                            rss = int(line.split()[1]) * 1024
                            break
            except OSError:
                continue

            cpu_percent = 0.0
            try:
                with open(f"{base}/stat") as f:
                    stat_line = f.read()
                rest = stat_line[stat_line.rfind(")") + 2:].split()
                utime = int(rest[11])
                stime = int(rest[12])
                cpu_seconds = (utime + stime) / self.clk_tck
                prev = self._prev_proc_times.get(pid)
                if prev is not None:
                    prev_cpu, prev_ts = prev
                    dt_wall = now - prev_ts
                    if dt_wall > 0:
                        cpu_percent = max(0.0, (cpu_seconds - prev_cpu) / dt_wall * 100)
                self._prev_proc_times[pid] = (cpu_seconds, now)
            except (OSError, IndexError, ValueError):
                pass

            seen_pids.add(pid)
            results.append(ProcSample(pid=pid, name=name, rss=rss, cpu_percent=cpu_percent))


        for pid in list(self._prev_proc_times.keys()):
            if pid not in seen_pids:
                del self._prev_proc_times[pid]

        return results


class WindowsSampler(BaseSampler):
    def sample_system(self) -> SystemSample:
        import ctypes

        class MEMORYSTATUSEX(ctypes.Structure):
            _fields_ = [
                ("dwLength", ctypes.c_ulong),
                ("dwMemoryLoad", ctypes.c_ulong),
                ("ullTotalPhys", ctypes.c_ulonglong),
                ("ullAvailPhys", ctypes.c_ulonglong),
                ("ullTotalPageFile", ctypes.c_ulonglong),
                ("ullAvailPageFile", ctypes.c_ulonglong),
                ("ullTotalVirtual", ctypes.c_ulonglong),
                ("ullAvailVirtual", ctypes.c_ulonglong),
                ("sullAvailExtendedVirtual", ctypes.c_ulonglong),
            ]

        stat = MEMORYSTATUSEX()
        stat.dwLength = ctypes.sizeof(MEMORYSTATUSEX)
        ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(stat))
        mem_total = stat.ullTotalPhys
        mem_used = mem_total - stat.ullAvailPhys
        mem_percent = stat.dwMemoryLoad
        swap_total = stat.ullTotalPageFile
        swap_used = swap_total - stat.ullAvailPageFile

        cpu_percent = 0.0
        try:
            out = subprocess.check_output(
                ["wmic", "cpu", "get", "loadpercentage"], text=True, stderr=subprocess.DEVNULL
            )
            nums = re.findall(r"\d+", out)
            if nums:
                cpu_percent = float(nums[0])
        except Exception:
            pass

        return SystemSample(
            ts=time.time(),
            mem_total=mem_total,
            mem_used=mem_used,
            mem_percent=mem_percent,
            swap_total=swap_total,
            swap_used=swap_used,
            cpu_percent=cpu_percent,
        )

    def sample_processes(self) -> list:
        results = []
        try:
            out = subprocess.check_output(
                [
                    "wmic", "path", "Win32_PerfFormattedData_PerfProc_Process",
                    "get", "IDProcess,Name,PercentProcessorTime,WorkingSetPrivate",
                    "/format:csv",
                ],
                text=True, stderr=subprocess.DEVNULL,
            )
        except Exception:
            return results

        lines = [l for l in out.splitlines() if l.strip()]
        if not lines:
            return results
        header = lines[0].split(",")
        try:
            idx_name = header.index("Name")
            idx_pid = header.index("IDProcess")
            idx_cpu = header.index("PercentProcessorTime")
            idx_ws = header.index("WorkingSetPrivate")
        except ValueError:
            return results

        for line in lines[1:]:
            cols = line.split(",")
            if len(cols) <= max(idx_name, idx_pid, idx_cpu, idx_ws):
                continue
            name = cols[idx_name]
            if name in ("_Total", "Idle", ""):
                continue
            try:
                pid = int(cols[idx_pid])
                cpu = float(cols[idx_cpu])
                ws = int(cols[idx_ws])
            except ValueError:
                continue
            results.append(ProcSample(pid=pid, name=name, rss=ws, cpu_percent=cpu / max(self.num_cpus, 1)))
        return results


class MacSampler(BaseSampler):
    def sample_system(self) -> SystemSample:
        mem_total = 0
        try:
            out = subprocess.check_output(["sysctl", "-n", "hw.memsize"], text=True)
            mem_total = int(out.strip())
        except Exception:
            pass

        page_size = 4096
        pages_free = pages_active = pages_inactive = pages_wired = pages_speculative = 0
        try:
            out = subprocess.check_output(["vm_stat"], text=True)
            for line in out.splitlines():
                if "page size of" in line:
                    m = re.search(r"(\d+) bytes", line)
                    if m:
                        page_size = int(m.group(1))
                elif ":" in line:
                    key, val = line.split(":", 1)
                    val = val.strip().rstrip(".")
                    if not val.isdigit():
                        continue
                    val = int(val)
                    if key.strip() == "Pages free":
                        pages_free = val
                    elif key.strip() == "Pages active":
                        pages_active = val
                    elif key.strip() == "Pages inactive":
                        pages_inactive = val
                    elif key.strip() == "Pages wired down":
                        pages_wired = val
                    elif key.strip() == "Pages speculative":
                        pages_speculative = val
        except Exception:
            pass

        mem_used = (pages_active + pages_wired + pages_inactive) * page_size
        mem_percent = (mem_used / mem_total * 100) if mem_total else 0.0

        cpu_percent = 0.0
        try:
            out = subprocess.check_output(["ps", "-A", "-o", "%cpu"], text=True)
            vals = [float(x) for x in out.splitlines()[1:] if x.strip()]
            cpu_percent = min(100.0, sum(vals) / max(self.num_cpus, 1))
        except Exception:
            pass

        return SystemSample(
            ts=time.time(), mem_total=mem_total, mem_used=mem_used, mem_percent=mem_percent,
            swap_total=0, swap_used=0, cpu_percent=cpu_percent,
        )

    def sample_processes(self) -> list:
        results = []
        try:
            out = subprocess.check_output(
                ["ps", "-axo", "pid,comm,%cpu,rss"], text=True
            )
        except Exception:
            return results
        for line in out.splitlines()[1:]:
            parts = line.split(None, 3)
            if len(parts) < 4:
                continue
            try:
                pid = int(parts[0])
                cpu = float(parts[2])
                rss = int(parts[3]) * 1024
            except ValueError:
                continue
            name = parts[1].rsplit("/", 1)[-1]
            results.append(ProcSample(pid=pid, name=name, rss=rss, cpu_percent=cpu))
        return results


def get_sampler() -> BaseSampler:
    system = platform.system()
    if system == "Linux":
        return LinuxSampler()
    if system == "Windows":
        return WindowsSampler()
    if system == "Darwin":
        return MacSampler()
    raise RuntimeError(f"Unsupported platform: {system}")



class HistoryDB:
    def __init__(self, path: str, retention_hours: float):
        self.path = path
        self.retention_hours = retention_hours
        self._lock = threading.Lock()
        self.conn = sqlite3.connect(path, check_same_thread=False)
        self._init_schema()

    def _init_schema(self):
        with self._lock, self.conn:
            self.conn.execute(
                """CREATE TABLE IF NOT EXISTS system_samples (
                                                                 ts REAL PRIMARY KEY,
                                                                 mem_total INTEGER, mem_used INTEGER, mem_percent REAL,
                                                                 swap_total INTEGER, swap_used INTEGER, cpu_percent REAL
                   )"""
            )
            self.conn.execute(
                """CREATE TABLE IF NOT EXISTS process_samples (
                                                                  ts REAL, pid INTEGER, name TEXT, rss INTEGER, cpu_percent REAL
                   )"""
            )
            self.conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_proc_pid_ts ON process_samples(pid, ts)"
            )
            self.conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_proc_ts ON process_samples(ts)"
            )

    def insert_system(self, s: SystemSample):
        with self._lock, self.conn:
            self.conn.execute(
                "INSERT OR REPLACE INTO system_samples VALUES (?,?,?,?,?,?,?)",
                (s.ts, s.mem_total, s.mem_used, s.mem_percent, s.swap_total, s.swap_used, s.cpu_percent),
            )

    def insert_processes(self, ts: float, procs: list):
        rows = [(ts, p.pid, p.name, p.rss, p.cpu_percent) for p in procs]
        with self._lock, self.conn:
            self.conn.executemany(
                "INSERT INTO process_samples VALUES (?,?,?,?,?)", rows
            )

    def prune(self):
        cutoff = time.time() - self.retention_hours * 3600
        with self._lock, self.conn:
            self.conn.execute("VACUUM")

    def get_system_history(self, since_ts: float):
        with self._lock:
            cur = self.conn.execute(
                "SELECT ts, mem_total, mem_used, mem_percent, swap_total, swap_used, cpu_percent "
                "FROM system_samples WHERE ts >= ? ORDER BY ts", (since_ts,)
            )
            return [SystemSample(*row) for row in cur.fetchall()]

    def get_peaks(self, since_ts: float):
        with self._lock:
            cur = self.conn.execute(
                "SELECT ts, mem_used, mem_percent FROM system_samples "
                "WHERE ts >= ? ORDER BY mem_percent DESC LIMIT 1", (since_ts,)
            )
            peak_mem = cur.fetchone()
            cur = self.conn.execute(
                "SELECT ts, cpu_percent FROM system_samples "
                "WHERE ts >= ? ORDER BY cpu_percent DESC LIMIT 1", (since_ts,)
            )
            peak_cpu = cur.fetchone()
        return peak_mem, peak_cpu

    def get_recent_pids(self, since_ts: float, min_points: int = 5):
        with self._lock:
            cur = self.conn.execute(
                "SELECT pid, COUNT(*) c, MAX(name) FROM process_samples "
                "WHERE ts >= ? GROUP BY pid HAVING c >= ?", (since_ts, min_points)
            )
            return [(row[0], row[2]) for row in cur.fetchall()]

    def get_process_history(self, pid: int, since_ts: float):
        with self._lock:
            cur = self.conn.execute(
                "SELECT ts, rss FROM process_samples WHERE pid=? AND ts >= ? ORDER BY ts",
                (pid, since_ts),
            )
            return cur.fetchall()

    def close(self):
        with self._lock:
            self.conn.close()



def _linreg(xs, ys):
    n = len(xs)
    if n < 2:
        return 0.0, 0.0
    mean_x = statistics.fmean(xs)
    mean_y = statistics.fmean(ys)
    sxy = sum((x - mean_x) * (y - mean_y) for x, y in zip(xs, ys))
    sxx = sum((x - mean_x) ** 2 for x in xs)
    syy = sum((y - mean_y) ** 2 for y in ys)
    if sxx == 0 or syy == 0:
        return 0.0, 0.0
    slope = sxy / sxx
    r = sxy / (sxx ** 0.5 * syy ** 0.5)
    return slope, r


def detect_leaks(db: HistoryDB, since_ts: float, min_points=6, min_duration_s=600,
                 growth_threshold_mb_per_hour=5.0, min_confidence=0.6):
    candidates = []
    for pid, name in db.get_recent_pids(since_ts, min_points=min_points):
        history = db.get_process_history(pid, since_ts)
        if len(history) < min_points:
            continue
        t0 = history[0][0]
        duration = history[-1][0] - t0
        if duration < min_duration_s:
            continue
        xs = [h[0] - t0 for h in history]
        ys = [h[1] for h in history]
        slope, r = _linreg(xs, ys)  # bytes/sec, correlation
        growth_mb_per_hour = slope * 3600 / (1024 * 1024)
        if growth_mb_per_hour >= growth_threshold_mb_per_hour and r >= min_confidence:
            candidates.append(LeakCandidate(
                pid=pid, name=name,
                growth_mb_per_hour=growth_mb_per_hour,
                current_rss_mb=human_mb(ys[-1]),
                duration_minutes=duration / 60,
                confidence=r,
            ))
    candidates.sort(key=lambda c: c.growth_mb_per_hour, reverse=True)
    return candidates



class Monitor:
    def __init__(self, interval: float, retention_hours: float, db_path: str):
        self.interval = interval
        self.sampler = get_sampler()
        self.db = HistoryDB(db_path, retention_hours)
        self._stop = threading.Event()
        self._pause = threading.Event()
        self.latest_system = None
        self.latest_processes = []
        self.start_time = time.time()
        self._thread = None

    def start(self):
        self._thread = threading.Thread(target=self._loop, daemon=True)
        self._thread.start()

    def _loop(self):
        self.sampler.sample_system()
        self.sampler.sample_processes()
        self._stop.wait(min(1.0, self.interval))
        last_prune = 0.0
        while not self._stop.is_set():
            if not self._pause.is_set():
                ts = time.time()
                sys_sample = self.sampler.sample_system()
                procs = self.sampler.sample_processes()
                self.latest_system = sys_sample
                self.latest_processes = procs
                try:
                    self.db.insert_system(sys_sample)
                    self.db.insert_processes(ts, procs)
                except sqlite3.Error:
                    pass
                if ts - last_prune > 300:
                    self.db.prune()
                    last_prune = ts
            self._stop.wait(self.interval)

    def pause(self):
        self._pause.set()

    def resume(self):
        self._pause.clear()

    def stop(self):
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=2)
        self.db.close()



def run_cli(monitor: Monitor, top_n: int, retention_hours: float, leak_threshold: float):
    try:
        while True:
            time.sleep(monitor.interval)
            sys_s = monitor.latest_system
            procs = sorted(monitor.latest_processes, key=lambda p: p.rss, reverse=True)[:top_n]
            since_ts = time.time() - retention_hours * 3600
            peak_mem, peak_cpu = monitor.db.get_peaks(since_ts)
            leaks = detect_leaks(monitor.db, since_ts, growth_threshold_mb_per_hour=leak_threshold)

            print("\033[H\033[2J", end="", flush=True)
            print("=" * 78)
            print(" DIAGNOSTIC TASK MANAGER (CLI)  -  Ctrl+C to quit")
            print("=" * 78)
            if sys_s:
                print(f" CPU: {sys_s.cpu_percent:5.1f}%   "
                      f"Memory: {sys_s.mem_percent:5.1f}%  "
                      f"({human_mb(sys_s.mem_used):,.0f} / {human_mb(sys_s.mem_total):,.0f} MB)   "
                      f"Swap used: {human_mb(sys_s.swap_used):,.0f} MB")
            if peak_mem:
                print(f" Peak memory (last {retention_hours:g}h): {peak_mem[2]:.1f}% "
                      f"at {time.strftime('%H:%M:%S', time.localtime(peak_mem[0]))}")
            if peak_cpu:
                print(f" Peak CPU    (last {retention_hours:g}h): {peak_cpu[1]:.1f}% "
                      f"at {time.strftime('%H:%M:%S', time.localtime(peak_cpu[0]))}")
            print("-" * 78)
            print(f" {'PID':>7}  {'NAME':<24} {'CPU%':>7} {'RSS(MB)':>10}")
            for p in procs:
                print(f" {p.pid:>7}  {p.name[:24]:<24} {p.cpu_percent:7.1f} {human_mb(p.rss):10.1f}")
            print("-" * 78)
            if leaks:
                print(" POSSIBLE MEMORY LEAKS (sustained RSS growth):")
                for c in leaks[:10]:
                    print(f"   PID {c.pid:<7} {c.name:<20} "
                          f"+{c.growth_mb_per_hour:6.2f} MB/h   "
                          f"now={c.current_rss_mb:8.1f} MB   "
                          f"watched={c.duration_minutes:5.1f} min   "
                          f"confidence={c.confidence:.2f}")
            else:
                print(" No sustained memory-leak candidates detected yet.")
            print("=" * 78)
            sys.stdout.flush ()
    except KeyboardInterrupt:
        print("\nStopping...")



def run_gui(monitor: Monitor, retention_hours: float, leak_threshold: float):
    import tkinter as tk
    from tkinter import ttk, filedialog, messagebox

    root = tk.Tk()
    root.title("Diagnostic Task Manager")
    root.geometry("980x640")

    state = {"sort_col": "rss", "sort_rev": True, "leak_threshold": leak_threshold}

    notebook = ttk.Notebook(root)
    notebook.pack(fill="both", expand=True)


    live_tab = ttk.Frame(notebook)
    notebook.add(live_tab, text="Live Processes")

    top_bar = ttk.Frame(live_tab)
    top_bar.pack(fill="x", padx=6, pady=4)
    cpu_lbl = ttk.Label(top_bar, text="CPU: --%", font=("TkDefaultFont", 11, "bold"))
    cpu_lbl.pack(side="left", padx=8)
    mem_lbl = ttk.Label(top_bar, text="Memory: --%", font=("TkDefaultFont", 11, "bold"))
    mem_lbl.pack(side="left", padx=8)
    swap_lbl = ttk.Label(top_bar, text="Swap: --")
    swap_lbl.pack(side="left", padx=8)

    pause_btn_text = tk.StringVar(value="Pause Sampling")

    def toggle_pause():
        if pause_btn_text.get() == "Pause Sampling":
            monitor.pause()
            pause_btn_text.set("Resume Sampling")
        else:
            monitor.resume()
            pause_btn_text.set("Pause Sampling")

    ttk.Button(top_bar, textvariable=pause_btn_text, command=toggle_pause).pack(side="right", padx=4)

    cols = ("pid", "name", "cpu", "rss")
    tree = ttk.Treeview(live_tab, columns=cols, show="headings")
    headers = {"pid": "PID", "name": "Name", "cpu": "CPU %", "rss": "Memory (MB)"}
    for c in cols:
        tree.heading(c, text=headers[c], command=lambda c=c: set_sort(c))
        tree.column(c, width=150 if c == "name" else 100, anchor="center" if c != "name" else "w")
    tree.pack(fill="both", expand=True, padx=6, pady=4)

    def set_sort(col):
        if state["sort_col"] == col:
            state["sort_rev"] = not state["sort_rev"]
        else:
            state["sort_col"] = col
            state["sort_rev"] = True


    hist_tab = ttk.Frame(notebook)
    notebook.add(hist_tab, text=f"History ({retention_hours:g}h)")

    peak_lbl = ttk.Label(hist_tab, text="Peaks: --")
    peak_lbl.pack(anchor="w", padx=8, pady=4)

    mem_canvas = tk.Canvas(hist_tab, bg="white", height=220)
    mem_canvas.pack(fill="x", padx=8, pady=4)
    ttk.Label(hist_tab, text="Memory % over time").pack(anchor="w", padx=8)

    cpu_canvas = tk.Canvas(hist_tab, bg="white", height=220)
    cpu_canvas.pack(fill="x", padx=8, pady=4)
    ttk.Label(hist_tab, text="CPU % over time").pack(anchor="w", padx=8)

    def draw_chart(canvas, series, color, y_max=100.0):
        canvas.delete("all")
        canvas.update_idletasks()
        w = max(canvas.winfo_width(), 400)
        h = max(canvas.winfo_height(), 200)
        pad = 30
        canvas.create_line(pad, h - pad, w - 10, h - pad)  # x-axis
        canvas.create_line(pad, 10, pad, h - pad)          # y-axis
        for frac in (0, 0.25, 0.5, 0.75, 1.0):
            y = h - pad - frac * (h - pad - 10)
            canvas.create_line(pad, y, w - 10, y, fill="#eeeeee")
            canvas.create_text(5, y, text=f"{frac *y_max:.0f}", anchor="w", font=("TkDefaultFont", 7))
        if len(series) < 2:
            canvas.create_text(w / 2, h / 2, text="Collecting data...", fill="gray")
            return

        max_points = 300
        if len(series) > max_points:
            step = len(series) / max_points
            sampled = [series[int(i * step)] for i in range(max_points)]
        else:
            sampled = series
        t0 = sampled[0][0]
        t1 = sampled[-1][0]
        span = max(t1 - t0, 1)
        points = []
        peak_val, peak_pt = -1, None
        for ts, val in sampled:
            x = pad + (ts - t0) / span * (w - pad - 10)
            y = h - pad - min(val, y_max) / y_max * (h - pad - 10)
            points.append((x, y))
            if val > peak_val:
                peak_val, peak_pt = val, (x, y)
        for i in range(len(points) - 1):
            canvas.create_line(*points[i], *points[i + 1], fill=color, width=2)
        if peak_pt:
            canvas.create_oval(peak_pt[0] - 3, peak_pt[1] - 3, peak_pt[0] + 3, peak_pt[1] + 3, fill="red")
            canvas.create_text(peak_pt[0], peak_pt[1] - 10, text=f"peak {peak_val:.1f}", fill="red",
                               font=("TkDefaultFont", 7))

    leak_tab = ttk.Frame(notebook)
    notebook.add(leak_tab, text="Memory Leak Watch")

    ctrl_bar = ttk.Frame(leak_tab)
    ctrl_bar.pack(fill="x", padx=6, pady=4)
    ttk.Label(ctrl_bar, text="Growth threshold (MB/hour):").pack(side="left")
    thresh_var = tk.DoubleVar(value=leak_threshold)
    ttk.Spinbox(ctrl_bar, from_=0.5, to=100, increment=0.5, textvariable=thresh_var, width=6).pack(side="left", padx=4)

    leak_cols = ("pid", "name", "growth", "rss", "watched", "conf")
    leak_headers = {"pid": "PID", "name": "Name", "growth": "MB/hour",
                    "rss": "Current RSS (MB)", "watched": "Watched (min)", "conf": "Confidence"}
    leak_tree = ttk.Treeview(leak_tab, columns=leak_cols, show="headings")
    for c in leak_cols:
        leak_tree.heading(c, text=leak_headers[c])
        leak_tree.column(c, width=140, anchor="center")
    leak_tree.pack(fill="both", expand=True, padx=6, pady=4)

    def export_report():
        since_ts = time.time() - retention_hours * 3600
        leaks = detect_leaks(monitor.db, since_ts, growth_threshold_mb_per_hour=thresh_var.get())
        peak_mem, peak_cpu = monitor.db.get_peaks(since_ts)
        path = filedialog.asksaveasfilename(defaultextension=".txt", initialfile="diagnostic_report.txt")
        if not path:
            return
        with open(path, "w") as f:
            f.write("Diagnostic Task Manager Report\n")
            f.write(f"Generated: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"Retention window: {retention_hours:g} hours\n\n")
            if peak_mem:
                f.write \
                    (f"Peak memory: {peak_mem[2]:.1f}% at {time.strftime('%H:%M:%S', time.localtime(peak_mem[0]))}\n")
            if peak_cpu:
                f.write(f"Peak CPU: {peak_cpu[1]:.1f}% at {time.strftime('%H:%M:%S', time.localtime(peak_cpu[0]))}\n")
            f.write("\nMemory leak candidates:\n")
            if not leaks:
                f.write("  None detected.\n")
            for c in leaks:
                f.write(f"  PID {c.pid} ({c.name}): +{c.growth_mb_per_hour:.2f} MB/h, "
                        f"now {c.current_rss_mb:.1f} MB, watched {c.duration_minutes:.1f} min, "
                        f"confidence {c.confidence:.2f}\n")
        messagebox.showinfo("Export complete", f"Report saved to:\n{path}")

    ttk.Button(ctrl_bar, text="Export Report...", command=export_report).pack(side="right", padx=4)

    status_lbl = ttk.Label(root, text="", anchor="w")
    status_lbl.pack(fill="x", side="bottom", padx=6, pady=2)

    def refresh():
        sys_s = monitor.latest_system
        if sys_s:
            cpu_lbl.config(text=f"CPU: {sys_s.cpu_percent:.1f}%")
            mem_lbl.config(text=f"Memory: {sys_s.mem_percent:.1f}% "
                                f"({human_mb(sys_s.mem_used):,.0f}/{human_mb(sys_s.mem_total):,.0f} MB)")
            swap_lbl.config(text=f"Swap: {human_mb(sys_s.swap_used):,.0f} MB used")

        procs = list(monitor.latest_processes)
        key = state["sort_col"]
        procs.sort(key=lambda p: getattr(p, key if key != "rss" else "rss"), reverse=state["sort_rev"])
        tree.delete(*tree.get_children())
        for p in procs[:200]:
            tree.insert("", "end", values=(p.pid, p.name, f"{p.cpu_percent:.1f}", f"{human_mb(p.rss):.1f}"))

        since_ts = time.time() - retention_hours * 3600
        history = monitor.db.get_system_history(since_ts)
        mem_series = [(s.ts, s.mem_percent) for s in history]
        cpu_series = [(s.ts, s.cpu_percent) for s in history]
        draw_chart(mem_canvas, mem_series, "#2b7de9", y_max=100.0)
        draw_chart(cpu_canvas, cpu_series, "#e9622b", y_max=100.0)

        peak_mem, peak_cpu = monitor.db.get_peaks(since_ts)
        parts = []
        if peak_mem:
            parts.append(f"Peak memory {peak_mem[2]:.1f}% at {time.strftime('%H:%M:%S', time.localtime(peak_mem[0]))}")
        if peak_cpu:
            parts.append(f"Peak CPU {peak_cpu[1]:.1f}% at {time.strftime('%H:%M:%S', time.localtime(peak_cpu[0]))}")
        peak_lbl.config(text="  |  ".join(parts) if parts else "Peaks: collecting data...")

        leaks = detect_leaks(monitor.db, since_ts, growth_threshold_mb_per_hour=thresh_var.get())
        leak_tree.delete(*leak_tree.get_children())
        for c in leaks:
            leak_tree.insert("", "end", values=(
                c.pid, c.name, f"{c.growth_mb_per_hour:.2f}", f"{c.current_rss_mb:.1f}",
                f"{c.duration_minutes:.1f}", f"{c.confidence:.2f}",
            ))

        uptime_min = (time.time() - monitor.start_time) / 60
        status_lbl.config(
            text=f"Sampling every {monitor.interval:g}s   |   DB: {monitor.db.path}   |   "
                 f"Retention: {retention_hours:g}h   |   Monitor uptime: {uptime_min:.1f} min"
        )
        root.after(500, refresh)

    def on_close():
        monitor.stop()
        root.destroy()

    root.protocol("WM_DELETE_WINDOW", on_close)
    root.after(1500, refresh)
    root.mainloop()


def main():
    if os.name == 'nt':
        import ctypes
        kernel32 = ctypes.windll.kernel32
        kernel32.SetConsoleMode(kernel32.GetStdHandle(-11), 7)
    parser = argparse.ArgumentParser(description="Diagnostic Task Manager (stdlib only)")
    parser.add_argument("--interval", type=float, default=0.5, help="Sampling interval in seconds (default 5)")
    parser.add_argument("--retention", type=float, default=24.0, help="History retention in hours (default 24)")
    parser.add_argument("--db", type=str, default=None, help="Path to SQLite history file")
    parser.add_argument("--cli", action="store_true", help="Run in terminal mode instead of GUI")
    parser.add_argument("--top", type=int, default=15, help="CLI mode: number of processes to show")
    parser.add_argument("--leak-threshold", type=float, default=5.0,
                        help="Flag a process as a leak candidate above this growth rate in MB/hour (default 5)")
    args = parser.parse_args()

    db_path = args.db or str(Path.home() / ".task_manager_diagnostic" / "history.db")
    Path(db_path).parent.mkdir(parents=True, exist_ok=True)

    monitor = Monitor(interval=args.interval, retention_hours=args.retention, db_path=db_path)
    monitor.start()

    use_cli = args.cli
    if not use_cli:
        try:
            import tkinter
        except ImportError:
            print("tkinter is not available on this system - falling back to --cli mode.")
            use_cli = True

    try:
        if use_cli:
            run_cli(monitor, top_n=args.top, retention_hours=args.retention, leak_threshold=args.leak_threshold)
        else:
            run_gui(monitor, retention_hours=args.retention, leak_threshold=args.leak_threshold)
    finally:
        monitor.stop()


if __name__ == "__main__":
    main()

