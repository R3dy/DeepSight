#!/usr/bin/env python3
"""System Dashboard Server — multi-host collector for DeepSight."""

import os
import glob
import time
import threading
import psutil
from flask import Flask, jsonify, send_from_directory, request, g

import auth

# ── API v2 Blueprint ──
try:
    from routes.v2 import v2_bp, log_api_audit, _flush_audit_buffer, _ensure_audit_table_lazy
    _v2_available = True
except ImportError as e:
    print(f"[server] WARNING: v2 routes not available: {e}", flush=True)
    _v2_available = False
    v2_bp = None  # type: ignore

# ── Flask-SocketIO (optional) ──
try:
    from flask_socketio import SocketIO

    _socketio_available = True
except ImportError:
    _socketio_available = False
    SocketIO = None  # type: ignore

# ── React frontend feature flag ──
_REACT_FRONTEND_ENABLED = os.environ.get("REACT_FRONTEND_ENABLED", "").lower() in ("1", "true", "yes")

app = Flask(__name__, static_folder="static", static_url_path="")

# ── Register API v2 Blueprint ──
if _v2_available and v2_bp is not None:
    app.register_blueprint(v2_bp)
    print("[server] Registered /api/v2/ blueprint", flush=True)

# ── Initialize SocketIO if available ──
if _socketio_available:
    socketio = SocketIO(app, cors_allowed_origins="*", async_mode="eventlet")

    # ── SocketIO event handlers ──
    @socketio.on('connect')
    def handle_connect():
        """Emit a 'connected' event back to the client on successful connection."""
        from flask import request as sio_request
        socketio.emit('connected', {'user': 'server'}, to=sio_request.sid)

    @socketio.on('disconnect')
    def handle_disconnect():
        """Handle client disconnect (no-op logging placeholder)."""
        pass

else:
    socketio = None

# ── Shared secret for agent auth ──
SHARED_SECRET = os.environ.get("DASHBOARD_SECRET", "sysdash-agent-key-2026")

# ── Host storage: {host_id: {last_seen, stats, status}} ──
HOSTS = {}
HOSTS_LOCK = threading.Lock()
STALE_SECONDS = 15  # mark stale after 15s without report

# ── Performance caches ──
_NETWORK_CACHE = {"data": None, "ts": 0}
_NETWORK_CACHE_TTL = 5  # seconds
_PROCESS_CACHE = {}  # pid -> {data, ts}
_PROCESS_CACHE_TTL = 3  # seconds

# ── Self-hostname ──
SELF_HOST = os.uname().nodename


def compute_memory_stats(mem):
    """Compute memory stats with kernel reserved broken out separately."""
    buf = getattr(mem, "buffers", 0)
    cached = getattr(mem, "cached", 0)
    total = mem.total
    free = mem.free

    # Read kernel-reserved from /proc/meminfo
    kernel_gb = 0.1
    try:
        with open("/proc/meminfo") as f:
            mi = {}
            for line in f:
                parts = line.split(":")
                if len(parts) == 2:
                    try:
                        mi[parts[0].strip()] = int(parts[1].strip().split()[0])
                    except ValueError:
                        pass
        kr_kb = (mi.get("SUnreclaim", 0) + mi.get("KernelStack", 0)
                 + mi.get("PageTables", 0))
        # Include non-reclaimable slab overhead
        slab_overhead = mi.get("Slab", 0) - mi.get("SReclaimable", 0) - mi.get("SUnreclaim", 0)
        if slab_overhead > 0:
            kr_kb += slab_overhead
        kernel_gb = round(kr_kb * 1024 / 1024**3, 2)
        if kernel_gb < 0.05:
            kernel_gb = 0.1
    except Exception:
        kernel_gb = 0.1

    total_gb = round(total / 1024**3, 1)
    # Hard used (user space only) = total - free - cached - buffers - kernel
    hard_used_gb = round((total - free - buf - cached) / 1024**3, 1) - kernel_gb
    if hard_used_gb < 0:
        hard_used_gb = 0.1

    return {
        "total": total, "available": mem.available, "used": mem.used,
        "free": free, "buffers": buf, "cached": cached,
        "percent": mem.percent,
        "total_gb": total_gb,
        "used_gb": round(mem.used / 1024**3, 1),
        "available_gb": round(mem.available / 1024**3, 1),
        "free_gb": round(free / 1024**3, 1),
        "cached_gb": round(cached / 1024**3, 1),
        "buffers_gb": round(buf / 1024**3, 1),
        "hard_used_gb": round(hard_used_gb, 1),
        "hard_used_pct": round(hard_used_gb / total_gb * 100, 1) if total_gb > 0 else 0,
        "kernel_reserved_gb": kernel_gb,
        "kernel_reserved_pct": round(kernel_gb / total_gb * 100, 1) if total_gb > 0 else 0,
    }


def collect_local_stats():
    """Collect stats from localhost — same shape agents report."""
    mem = psutil.virtual_memory()
    swap = psutil.swap_memory()

    cpu_total = psutil.cpu_percent(interval=0.1)
    cpu_cores = psutil.cpu_percent(interval=None, percpu=True)
    cpu_freq = psutil.cpu_freq()
    load = os.getloadavg()

    ram_procs = []
    cpu_procs = []
    for proc in psutil.process_iter(["pid", "name", "memory_info"]):
        try:
            info = proc.info
            rss = info["memory_info"].rss
            cpu = info.get("cpu_percent", 0) or 0
            if rss > 2 * 1024 * 1024 or cpu > 0.1:
                entry = {
                    "pid": info["pid"],
                    "name": info["name"],
                    "memory": rss,
                    "memory_mb": round(rss / (1024 * 1024), 1),
                    "memory_gb": round(rss / (1024**3), 2),
                    "ram_percent": round(rss / mem.total * 100, 2),
                    "cpu_percent": round(cpu, 1),
                }
                if rss > 2 * 1024 * 1024:
                    ram_procs.append(entry)
                if cpu > 0.05:
                    cpu_procs.append(entry)
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue

    ram_procs.sort(key=lambda x: x["memory"], reverse=True)
    cpu_procs.sort(key=lambda x: x["cpu_percent"], reverse=True)

    def aggregate(procs, top_n, by_field):
        top = procs[:top_n]
        rest = procs[top_n:]
        if rest:
            total = sum(p[by_field] for p in rest)
            total_pct = (
                round(total / mem.total * 100, 2)
                if by_field == "memory" else round(total, 1))
            top.append(
                {
                    "pid": 0,
                    "name": f"other ({len(rest)} processes)",
                    "memory": total if by_field == "memory" else 0,
                    "memory_mb": total_pct if by_field == "memory" else 0,
                    "memory_gb": round(total / (1024**3), 2) if by_field == "memory" else 0,
                    "ram_percent": total_pct if by_field == "memory" else 0,
                    "cpu_percent": round(total, 1) if by_field == "cpu_percent" else 0,
                }
            )
        return top

    ram_procs = aggregate(ram_procs, 15, "memory")
    cpu_procs = aggregate(cpu_procs, 15, "cpu_percent")

    # GPU
    gpu = {
        "name": "unknown", "usage": 0, "vram_used": 0, "vram_total": 0,
        "vram_used_gb": 0, "vram_total_gb": 0, "gtt_used": 0, "gtt_used_gb": 0,
    }
    for card in sorted(glob.glob("/sys/class/drm/card*/device")):
        try:
            vf = os.path.join(card, "mem_info_vram_total")
            if os.path.exists(vf):
                with open(os.path.join(card, "gpu_busy_percent")) as f:
                    gpu["usage"] = int(f.read().strip())
                with open(os.path.join(card, "mem_info_vram_used")) as f:
                    gpu["vram_used"] = int(f.read().strip())
                with open(vf) as f:
                    gpu["vram_total"] = int(f.read().strip())
                gtf = os.path.join(card, "mem_info_gtt_used")
                if os.path.exists(gtf):
                    with open(gtf) as f:
                        gpu["gtt_used"] = int(f.read().strip())
                gpu["vram_used_gb"] = round(gpu["vram_used"] / 1024**3, 1)
                gpu["vram_total_gb"] = round(gpu["vram_total"] / 1024**3, 1)
                gpu["gtt_used_gb"] = round(gpu["gtt_used"] / 1024**3, 1)
                # try to get GPU name
                with open(os.path.join(card, "../uevent")) as f:
                    for line in f:
                        if "DRIVER=" in line:
                            driver = line.strip().split("=")[1]
                            if driver == "amdgpu":
                                gpu["name"] = "AMD Radeon (amdgpu)"
                break
        except Exception:
            pass

    # Disks
    disks = []
    for part in psutil.disk_partitions():
        if part.device.startswith("/dev/loop") or part.device.startswith("tmp"):
            continue
        try:
            usage = psutil.disk_usage(part.mountpoint)
            disks.append(
                {
                    "device": part.device,
                    "mountpoint": part.mountpoint,
                    "fstype": part.fstype,
                    "total": usage.total,
                    "used": usage.used,
                    "free": usage.free,
                    "percent": usage.percent,
                    "total_gb": round(usage.total / 1024**3, 1),
                    "used_gb": round(usage.used / 1024**3, 1),
                    "free_gb": round(usage.free / 1024**3, 1),
                }
            )
        except PermissionError:
            pass

    return {
        "memory": compute_memory_stats(mem),
        "swap": {
            "total": swap.total, "used": swap.used, "free": swap.free,
            "percent": swap.percent, "total_gb": round(swap.total / (1024**3), 1),
            "used_gb": round(swap.used / (1024**3), 1),
        },
        "cpu": {
            "percent": round(cpu_total or 0, 1),
            "cores": [round(c, 1) for c in (cpu_cores or [])],
            "core_count_logical": len(cpu_cores or []),
            "core_count_physical": psutil.cpu_count(logical=False),
            "freq_current": cpu_freq.current if cpu_freq else 0,
            "freq_max": cpu_freq.max if cpu_freq else 0,
            "load_1m": round(load[0], 2),
            "load_5m": round(load[1], 2),
            "load_15m": round(load[2], 2),
        },
        "gpu": gpu,
        "disks": disks,
        "ram_processes": ram_procs,
        "cpu_processes": cpu_procs,
    }


def prune_stale_hosts():
    """Remove hosts that haven't reported recently."""
    now = time.time()
    with HOSTS_LOCK:
        stale = [
            h for h, d in HOSTS.items()
            if h != SELF_HOST and now - d["last_seen"] > 60
        ]
        for h in stale:
            del HOSTS[h]


# ═══════════════════════════════════════════
# Deep Data Collectors (expanded views)
# ═══════════════════════════════════════════

def _read_lines(path):
    try:
        with open(path) as f:
            return f.read().strip()
    except Exception:
        return ""


def _read_int(path, default=0):
    try:
        return int(_read_lines(path))
    except Exception:
        return default


def collect_meminfo_deep():
    """Full /proc/meminfo parsing for RAM deep dive."""
    fields = {}
    try:
        with open("/proc/meminfo") as f:
            for line in f:
                parts = line.split(":")
                if len(parts) == 2:
                    key = parts[0].strip()
                    val = parts[1].strip().split()[0]
                    try:
                        fields[key] = int(val)
                    except ValueError:
                        fields[key] = val
    except Exception:
        pass

    def kb_to_gb(v):
        return round(v * 1024 / 1024**3, 2) if v else 0

    return {
        "active": kb_to_gb(fields.get("Active", 0)),
        "inactive": kb_to_gb(fields.get("Inactive", 0)),
        "anon_pages": kb_to_gb(fields.get("AnonPages", 0)),
        "mapped": kb_to_gb(fields.get("Mapped", 0)),
        "shmem": kb_to_gb(fields.get("Shmem", 0)),
        "slab_reclaimable": kb_to_gb(fields.get("SReclaimable", 0)),
        "slab_unreclaimable": kb_to_gb(fields.get("SUnreclaim", 0)),
        "kernel_stack": kb_to_gb(fields.get("KernelStack", 0)),
        "page_tables": kb_to_gb(fields.get("PageTables", 0)),
        "commit_limit": kb_to_gb(fields.get("CommitLimit", 0)),
        "committed_as": kb_to_gb(fields.get("Committed_AS", 0)),
        "hugepages_total": fields.get("HugePages_Total", 0),
        "hugepages_free": fields.get("HugePages_Free", 0),
        "hugepages_size": fields.get("Hugepagesize", "0 kB"),
        "dirty": kb_to_gb(fields.get("Dirty", 0)),
        "writeback": kb_to_gb(fields.get("Writeback", 0)),
    }


def collect_memory_pressure():
    """Read /proc/pressure/memory for PSI metrics."""
    try:
        out = _read_lines("/proc/pressure/memory")
        result = {}
        for part in out.split():
            if "=" in part:
                k, v = part.split("=")
                result[k] = float(v)
        return {
            "some_avg10": result.get("avg10", 0),
            "some_avg60": result.get("avg60", 0),
            "some_avg300": result.get("avg300", 0),
        }
    except Exception:
        return {"some_avg10": 0, "some_avg60": 0, "some_avg300": 0}


def collect_swappiness():
    try:
        return int(_read_lines("/proc/sys/vm/swappiness"))
    except Exception:
        return 60


def collect_cpu_stat_deep():
    """Parse /proc/stat for CPU time breakdown (all cores aggregate)."""
    try:
        with open("/proc/stat") as f:
            line = f.readline()
        parts = line.split()
        vals = [int(x) for x in parts[1:9]]  # user nice system idle iowait irq softirq steal
        total = sum(vals)
        # user nice system idle iowait irq softirq steal
        return {
            "user_pct": round(vals[0] / total * 100, 1) if total else 0,
            "nice_pct": round(vals[1] / total * 100, 1) if total else 0,
            "system_pct": round(vals[2] / total * 100, 1) if total else 0,
            "idle_pct": round(vals[3] / total * 100, 1) if total else 0,
            "iowait_pct": round(vals[4] / total * 100, 1) if total else 0,
            "irq_pct": round(vals[5] / total * 100, 1) if total else 0,
            "softirq_pct": round(vals[6] / total * 100, 1) if total else 0,
            "steal_pct": round(vals[7] / total * 100, 1) if total else 0,
        }
    except Exception:
        return {}


_CTXT_PREV = {"ctxt": 0, "ts": 0}
_BTIME = 0


def collect_context_switches():
    """Context switches per second (delta)."""
    global _CTXT_PREV, _BTIME
    try:
        ctxt = 0
        with open("/proc/stat") as f:
            for line in f:
                if line.startswith("ctxt "):
                    ctxt = int(line.split()[1])
                if line.startswith("btime "):
                    _BTIME = int(line.split()[1])
        now = time.time()
        delta = 0
        if _CTXT_PREV["ctxt"] > 0 and (now - _CTXT_PREV["ts"]) > 0.5:
            delta = (ctxt - _CTXT_PREV["ctxt"]) / (now - _CTXT_PREV["ts"])
        _CTXT_PREV = {"ctxt": ctxt, "ts": now}
        return {"per_sec": round(delta), "total": ctxt, "boot_time": _BTIME}
    except Exception:
        return {"per_sec": 0, "total": 0, "boot_time": 0}


def collect_cpu_temp():
    """Read CPU temperature from hwmon."""
    for root, dirs, files in os.walk("/sys/class/hwmon"):
        for d in dirs:
            continue
        # Find temp input
        for i in range(1, 5):
            label_file = os.path.join(root, f"temp{i}_label")
            input_file = os.path.join(root, f"temp{i}_input")
            try:
                if os.path.exists(input_file):
                    label = _read_lines(label_file) if os.path.exists(label_file) else ""
                    temp = int(_read_lines(input_file)) / 1000.0
                    if ("core" in label.lower() or "tctl" in label.lower()
                            or "package" in label.lower()):
                        return {"label": label, "temp_c": round(temp, 1)}
            except Exception:
                pass
        break  # only first hwmon dir
    # Try /sys/class/thermal
    for tz in glob.glob("/sys/class/thermal/thermal_zone*/temp"):
        try:
            temp = int(_read_lines(tz)) / 1000.0
            ttype = _read_lines(tz.replace("temp", "type"))
            return {"label": ttype, "temp_c": round(temp, 1)}
        except Exception:
            pass
    return {"label": "n/a", "temp_c": 0}


def collect_process_deep(top_n=5):
    """Get PSS/USS for top memory processes via smaps_rollup."""
    procs = []
    for proc in psutil.process_iter(["pid", "name", "memory_info",
                                     "cpu_times", "num_threads",
                                     "status", "username"]):
        try:
            info = proc.info
            rss = info["memory_info"].rss
            if rss < 5 * 1024 * 1024:
                continue
            pss = 0
            uss = 0
            swap_pss = 0
            # Try smaps_rollup for PSS
            try:
                with open(f"/proc/{info['pid']}/smaps_rollup") as f:
                    for line in f:
                        if line.startswith("Pss:"):
                            pss = int(line.split()[1]) * 1024
                        elif line.startswith("Private_Clean:") or line.startswith("Private_Dirty:"):
                            uss += int(line.split()[1]) * 1024
            except Exception:
                pass

            ctimes = info.get("cpu_times")
            procs.append({
                "pid": info["pid"],
                "name": info["name"],
                "user": info.get("username", ""),
                "status": info.get("status", ""),
                "threads": info.get("num_threads", 0),
                "rss_mb": round(rss / 1024**2, 1),
                "pss_mb": round(pss / 1024**2, 1) if pss else None,
                "uss_mb": round(uss / 1024**2, 1) if uss else None,
                "swap_pss_mb": round(swap_pss / 1024**2, 1) if swap_pss else 0,
                "cpu_percent": round(info.get("cpu_percent", 0) or 0, 1),
                "cpu_user_s": round(ctimes.user, 1) if ctimes else 0,
                "cpu_system_s": round(ctimes.system, 1) if ctimes else 0,
            })
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue

    procs.sort(key=lambda x: x["rss_mb"], reverse=True)
    return procs[:top_n * 3]  # return more than we'll show


def collect_disk_io():
    """Get disk I/O stats via psutil."""
    result = {}
    try:
        io = psutil.disk_io_counters(perdisk=True)
        if io:
            for disk, stats in io.items():
                # Skip loop and ram devices
                if disk.startswith("loop") or disk.startswith("ram"):
                    continue
                result[disk] = {
                    "read_bytes": stats.read_bytes,
                    "write_bytes": stats.write_bytes,
                    "read_count": stats.read_count,
                    "write_count": stats.write_count,
                    "read_gb": round(stats.read_bytes / 1024**3, 1),
                    "write_gb": round(stats.write_bytes / 1024**3, 1),
                    "read_time_ms": getattr(stats, "read_time", 0),
                    "write_time_ms": getattr(stats, "write_time", 0),
                    "busy_time_ms": getattr(stats, "busy_time", 0),
                }
    except Exception:
        pass
    return result


# Cache for disk IO delta calculation
_DISK_IO_PREV = {}


def collect_disk_io_delta():
    """Disk I/O per second (delta from previous call)."""
    global _DISK_IO_PREV
    now = time.time()
    current = collect_disk_io()
    result = {}

    for disk, cur in current.items():
        prev = _DISK_IO_PREV.get(disk)
        if prev and (now - prev["ts"]) > 0.5:
            dt = now - prev["ts"]
            result[disk] = {
                "read_kbps": round((cur["read_bytes"] - prev["read_bytes"]) / dt / 1024, 1),
                "write_kbps": round((cur["write_bytes"] - prev["write_bytes"]) / dt / 1024, 1),
                "read_iops": round((cur["read_count"] - prev["read_count"]) / dt, 1),
                "write_iops": round((cur["write_count"] - prev["write_count"]) / dt, 1),
                "util_pct": 0,  # would need io_ticks delta for real utilization
                "read_total_gb": cur["read_gb"],
                "write_total_gb": cur["write_gb"],
            }
        else:
            result[disk] = {
                "read_kbps": 0, "write_kbps": 0,
                "read_iops": 0, "write_iops": 0, "util_pct": 0,
                "read_total_gb": cur["read_gb"],
                "write_total_gb": cur["write_gb"],
            }

    _DISK_IO_PREV = {k: {**v, "ts": now} for k, v in current.items()}
    return result


def collect_inode_usage():
    """Get inode usage for each mount."""
    result = []
    for part in psutil.disk_partitions():
        if part.device.startswith("/dev/loop"):
            continue
        try:
            st = os.statvfs(part.mountpoint)
            total = st.f_files
            free = st.f_ffree
            used = total - free
            result.append({
                "mountpoint": part.mountpoint,
                "inode_total": total,
                "inode_used": used,
                "inode_free": free,
                "inode_pct": round(used / total * 100, 1) if total > 0 else 0,
            })
        except Exception:
            pass
    return result


def collect_gpu_deep():
    """Enhanced GPU stats: temp, clocks, power from sysfs."""
    gpu = {
        "name": "none", "usage": 0, "vram_used_gb": 0, "vram_total_gb": 0,
        "temp_c": 0, "power_w": 0, "sclk_mhz": 0, "mclk_mhz": 0,
    }
    for card in sorted(glob.glob("/sys/class/drm/card*/device")):
        try:
            vf = os.path.join(card, "mem_info_vram_total")
            if not os.path.exists(vf):
                continue
            gpu["usage"] = _read_int(os.path.join(card, "gpu_busy_percent"))
            gpu["vram_used_gb"] = round(
                _read_int(os.path.join(card, "mem_info_vram_used")) / 1024**3, 1)
            gpu["vram_total_gb"] = round(_read_int(vf) / 1024**3, 1)

            # Temp
            for hwmon in glob.glob(os.path.join(card, "hwmon/hwmon*/temp1_input")):
                gpu["temp_c"] = round(_read_int(hwmon) / 1000.0, 1)
            # Power
            for pw in glob.glob(os.path.join(card, "hwmon/hwmon*/power1_average")):
                gpu["power_w"] = round(_read_int(pw) / 1_000_000.0, 1)
            # Clocks (try pp_dpm_sclk)
            for clk in glob.glob(os.path.join(card, "pp_dpm_sclk")):
                try:
                    lines = _read_lines(clk).strip().split("\n")
                    for line in lines:
                        if "*" in line:
                            gpu["sclk_mhz"] = int(
                                line.split(":")[1].strip()
                                .replace("Mhz", "").replace("*", "").strip() or 0)
                except Exception:
                    pass
            for clk in glob.glob(os.path.join(card, "pp_dpm_mclk")):
                try:
                    lines = _read_lines(clk).strip().split("\n")
                    for line in lines:
                        if "*" in line:
                            gpu["mclk_mhz"] = int(
                                line.split(":")[1].strip()
                                .replace("Mhz", "").replace("*", "").strip() or 0)
                except Exception:
                    pass

            # Name — read the device uevent directly
            try:
                uevent_path = os.path.join(card, "uevent")
                if os.path.exists(uevent_path):
                    with open(uevent_path) as f:
                        content = f.read()
                    if "DRIVER=amdgpu" in content:
                        gpu["name"] = "AMD Radeon 680M"
                    elif "DRIVER=i915" in content:
                        gpu["name"] = "Intel (i915)"
                    elif "DRIVER=nouveau" in content:
                        gpu["name"] = "NVIDIA (nouveau)"
                # Try to get model from PCI ID
                for line in content.split("\n"):
                    if "PCI_ID=1002:" in line:
                        dev_id = line.split(":")[-1].strip()
                        gpu["name"] = f"AMD Radeon ({dev_id})"
            except Exception:
                pass
            break
        except Exception:
            pass
    return gpu


def collect_deep_data():
    """Collect all deep-dive data. Called alongside stats when detail=true."""
    return {
        "meminfo": collect_meminfo_deep(),
        "memory_pressure": collect_memory_pressure(),
        "swappiness": collect_swappiness(),
        "cpu_stat": collect_cpu_stat_deep(),
        "context_switches": collect_context_switches(),
        "cpu_temp": collect_cpu_temp(),
        "deep_processes": collect_process_deep(top_n=12),
        "disk_io": collect_disk_io_delta(),
        "inode_usage": collect_inode_usage(),
        "gpu_deep": collect_gpu_deep(),
    }


def collect_network_stats():
    """Collect TCP/UDP connections, interface stats, and DNS info."""
    result = {
        "tcp_connections": [],
        "udp_listeners": [],
        "interfaces": [],
        "dns": {"queries": 0, "cache_size": 0},
        "summary": {"tcp_established": 0, "tcp_listen": 0, "udp_listeners": 0},
    }

    # Build inode→pid map from /proc/*/fd
    inode_to_pid = {}
    for pid_dir in glob.glob("/proc/[0-9]*"):
        pid = os.path.basename(pid_dir)
        fd_dir = os.path.join(pid_dir, "fd")
        if not os.path.isdir(fd_dir):
            continue
        try:
            for fd in os.listdir(fd_dir):
                link = os.readlink(os.path.join(fd_dir, fd))
                if "socket:" in link:
                    inode = link.split("[")[-1].rstrip("]")
                    if inode.isdigit():
                        inode_to_pid[inode] = int(pid)
        except Exception:
            pass

    def get_process_name(pid):
        try:
            with open(f"/proc/{pid}/comm") as f:
                return f.read().strip()
        except Exception:
            return "?"

    # Parse /proc/net/tcp
    def parse_tcp(path, v6=False):
        conns = []
        try:
            with open(path) as f:
                lines = f.readlines()[1:]  # skip header
            for line in lines:
                parts = line.split()
                if len(parts) < 12:
                    continue
                local = parts[1]
                remote = parts[2]
                state_hex = parts[3]
                inode = parts[9]

                def decode_addr(hex_addr):
                    ip_hex = hex_addr.split(":")[0]
                    port_hex = hex_addr.split(":")[1]
                    if v6:
                        # IPv6 addresses are in 4 groups of 4 hex chars
                        chunks = [ip_hex[i:i+8] for i in range(0, 32, 8)]
                        # Convert each chunk from hex
                        ip = ":".join(
                            ":".join(str(int(chunks[j][k:k+4], 16)) for k in range(0, 8, 4))
                            for j in range(4)
                        )
                    else:
                        ip_int = int(ip_hex, 16)
                        ip = ".".join(str((ip_int >> (8 * i)) & 0xFF) for i in range(3, -1, -1))
                    port = int(port_hex, 16)
                    return ip, port

                local_ip, local_port = decode_addr(local)
                remote_ip, remote_port = decode_addr(remote)

                state_map = {
                    "01": "ESTABLISHED", "02": "SYN_SENT", "03": "SYN_RECV",
                    "04": "FIN_WAIT1", "05": "FIN_WAIT2", "06": "TIME_WAIT",
                    "07": "CLOSE", "08": "CLOSE_WAIT", "09": "LAST_ACK",
                    "0A": "LISTEN", "0B": "CLOSING",
                }
                state = state_map.get(state_hex, state_hex)
                pid = inode_to_pid.get(inode)
                conns.append({
                    "local_addr": local_ip,
                    "local_port": local_port,
                    "remote_addr": remote_ip,
                    "remote_port": remote_port,
                    "state": state,
                    "pid": pid,
                    "process": get_process_name(pid) if pid else None,
                    "inode": inode,
                })

                if state == "ESTABLISHED":
                    result["summary"]["tcp_established"] += 1
                elif state == "LISTEN":
                    result["summary"]["tcp_listen"] += 1
        except Exception:
            pass
        return conns

    result["tcp_connections"] = parse_tcp("/proc/net/tcp") + parse_tcp("/proc/net/tcp6", v6=True)

    # Parse /proc/net/udp
    def parse_udp(path, v6=False):
        conns = []
        try:
            with open(path) as f:
                lines = f.readlines()[1:]
            for line in lines:
                parts = line.split()
                if len(parts) < 11:
                    continue
                local = parts[1]
                inode = parts[9]
                local_ip, local_port = decode_addr_tcp(local, v6)
                pid = inode_to_pid.get(inode)
                conns.append({
                    "local_addr": local_ip,
                    "local_port": local_port,
                    "pid": pid,
                    "process": get_process_name(pid) if pid else None,
                    "inode": inode,
                })
                result["summary"]["udp_listeners"] += 1
        except Exception:
            pass
        return conns

    def decode_addr_tcp(hex_addr, v6=False):
        ip_hex = hex_addr.split(":")[0]
        port_hex = hex_addr.split(":")[1]
        if v6:
            chunks = [ip_hex[i:i+8] for i in range(0, 32, 8)]
            ip = ":".join(
                ":".join(str(int(chunks[j][k:k+4], 16)) for k in range(0, 8, 4))
                for j in range(4)
            )
        else:
            ip_int = int(ip_hex, 16)
            ip = ".".join(str((ip_int >> (8 * i)) & 0xFF) for i in range(3, -1, -1))
        return ip, int(port_hex, 16)

    result["udp_listeners"] = parse_udp("/proc/net/udp") + parse_udp("/proc/net/udp6", v6=True)

    # Interface stats from /proc/net/dev
    try:
        with open("/proc/net/dev") as f:
            lines = f.readlines()[2:]
        for line in lines:
            if ":" not in line:
                continue
            iface = line.split(":")[0].strip()
            stats = line.split(":")[1].split()
            if len(stats) >= 10:
                result["interfaces"].append({
                    "name": iface,
                    "rx_bytes": int(stats[0]),
                    "rx_packets": int(stats[1]),
                    "tx_bytes": int(stats[8]),
                    "tx_packets": int(stats[9]),
                    "rx_gb": round(int(stats[0]) / 1024**3, 2),
                    "tx_gb": round(int(stats[8]) / 1024**3, 2),
                })
    except Exception:
        pass

    # DNS stats (systemd-resolved)
    try:
        import subprocess
        out = subprocess.check_output(
            ["resolvectl", "statistics"], stderr=subprocess.DEVNULL, text=True
        )
        for line in out.split("\n"):
            if "Current Cache Size" in line:
                result["dns"]["cache_size"] = int(line.split(":")[1].strip())
            if "Total Queries" in line or "Transactions" in line:
                parts = line.split(":")
                if len(parts) > 1:
                    try:
                        result["dns"]["queries"] = int(parts[1].strip())
                    except Exception:
                        pass
    except Exception:
        pass

    # Sort connections
    result["tcp_connections"].sort(
        key=lambda c: (0 if c["state"] == "LISTEN" else 1 if c["state"] == "ESTABLISHED" else 2)
    )

    return result


def collect_process_detail(pid):
    """Deep forensic detail for a single process."""
    proc_dir = f"/proc/{pid}"
    detail = {"pid": pid, "found": False}

    try:
        # Status
        with open(f"{proc_dir}/status") as f:
            status = {}
            for line in f:
                if ":" in line:
                    k, v = line.split(":", 1)
                    status[k.strip()] = v.strip()
        detail["name"] = status.get("Name", "?")
        detail["state"] = status.get("State", "?")
        detail["threads"] = int(status.get("Threads", 0))
        detail["user"] = (
            status.get("Uid", "\t").split("\t")[0] if "Uid" in status else "?"
        )
        # Try to resolve UID to name
        try:
            import pwd
            detail["user"] = pwd.getpwuid(int(detail["user"])).pw_name
        except Exception:
            pass
        detail["vm_size_mb"] = round(int(status.get("VmSize", "0 kB").split()[0]) / 1024, 1)
        detail["vm_rss_mb"] = round(int(status.get("VmRSS", "0 kB").split()[0]) / 1024, 1)
        detail["vm_data_mb"] = round(int(status.get("VmData", "0 kB").split()[0]) / 1024, 1)
        detail["vm_stk_mb"] = round(int(status.get("VmStk", "0 kB").split()[0]) / 1024, 1)
        detail["vm_exe_mb"] = round(int(status.get("VmExe", "0 kB").split()[0]) / 1024, 1)
        detail["vm_lib_mb"] = round(int(status.get("VmLib", "0 kB").split()[0]) / 1024, 1)
        detail["vm_swap_mb"] = round(int(status.get("VmSwap", "0 kB").split()[0]) / 1024, 1)
        detail["voluntary_ctxt_switches"] = int(status.get("voluntary_ctxt_switches", 0))
        detail["nonvoluntary_ctxt_switches"] = int(status.get("nonvoluntary_ctxt_switches", 0))

        # Command line
        with open(f"{proc_dir}/cmdline", "rb") as f:
            raw = f.read()
            args = [a.decode("utf-8", errors="replace") for a in raw.split(b"\x00") if a]
        detail["cmdline"] = " ".join(args) if args else f"[{detail['name']}]"
        detail["argv"] = args

        # Environment (selected keys)
        env_vars = {}
        try:
            with open(f"{proc_dir}/environ", "rb") as f:
                raw = f.read()
                for item in raw.split(b"\x00"):
                    if not item:
                        continue
                    s = item.decode("utf-8", errors="replace")
                    if "=" in s:
                        k, v = s.split("=", 1)
                        if any(interesting in k.upper() for interesting in
                               ["PATH", "HOME", "USER", "HOST", "LANG", "DISPLAY",
                                "SHELL", "PWD", "TERM", "LOGNAME", "DBUS", "XDG"]):
                            env_vars[k] = v[:200]
        except Exception:
            pass
        detail["environ"] = env_vars

        # Open file descriptors
        fd_count = 0
        fd_samples = []
        fd_dir = f"{proc_dir}/fd"
        if os.path.isdir(fd_dir):
            try:
                fds = os.listdir(fd_dir)
                fd_count = len(fds)
                # Sample first 10
                for fd_name in sorted(fds, key=lambda x: int(x) if x.isdigit() else 0)[:10]:
                    try:
                        link = os.readlink(os.path.join(fd_dir, fd_name))
                        fd_samples.append({"fd": fd_name, "target": link[:100]})
                    except Exception:
                        pass
            except Exception:
                pass
        detail["fd_count"] = fd_count
        detail["fd_samples"] = fd_samples

        # Child processes
        children = []
        try:
            with open(f"{proc_dir}/task/{pid}/children") as f:
                children = [int(x) for x in f.read().strip().split()]
        except Exception:
            pass
        detail["children"] = children
        detail["child_count"] = len(children)
        # Get child names
        child_names = []
        for cpid in children[:10]:
            try:
                with open(f"/proc/{cpid}/comm") as f:
                    child_names.append({"pid": cpid, "name": f.read().strip()})
            except Exception:
                pass
        detail["child_details"] = child_names

        # Network connections for this process
        proc_conns = []
        try:
            inode_set = set()
            for fd_name in os.listdir(fd_dir):
                try:
                    link = os.readlink(os.path.join(fd_dir, fd_name))
                    if "socket:" in link:
                        inode_set.add(link.split("[")[-1].rstrip("]"))
                except Exception:
                    pass
            if inode_set:
                for path in ["/proc/net/tcp", "/proc/net/tcp6", "/proc/net/udp", "/proc/net/udp6"]:
                    try:
                        with open(path) as f:
                            for line in f.readlines()[1:]:
                                parts = line.split()
                                if len(parts) < 10:
                                    continue
                                if parts[9] in inode_set:
                                    local_hex = parts[1]
                                    remote_hex = parts[2]
                                    state_hex = parts[3] if "tcp" in path else "07"
                                    # Decode IP:port with proper hex parsing
                                    ip_int = int(local_hex.split(":")[0], 16)
                                    lip2 = ".".join(
                                        str((ip_int >> (8 * i)) & 0xFF)
                                        for i in range(3, -1, -1))
                                    lport = int(local_hex.split(":")[1], 16)
                                    rip_int = int(remote_hex.split(":")[0], 16)
                                    rip2 = ".".join(
                                        str((rip_int >> (8 * i)) & 0xFF)
                                        for i in range(3, -1, -1))
                                    rport = int(remote_hex.split(":")[1], 16)
                                    smap = {
                                        "01": "ESTABLISHED", "02": "SYN_SENT",
                                        "03": "SYN_RECV", "04": "FIN_WAIT1",
                                        "05": "FIN_WAIT2", "06": "TIME_WAIT",
                                        "07": "CLOSE", "08": "CLOSE_WAIT",
                                        "09": "LAST_ACK", "0A": "LISTEN",
                                        "0B": "CLOSING",
                                    }
                                    state = smap.get(state_hex, state_hex)
                                    proc_conns.append({
                                        "proto": "tcp" if "tcp" in path else "udp",
                                        "local": f"{lip2}:{lport}",
                                        "remote": f"{rip2}:{rport}" if rip2 != "0.0.0.0" else "*",
                                        "state": state if "tcp" in path else "UDP",
                                    })
                    except Exception:
                        pass
        except Exception:
            pass
        detail["network_connections"] = proc_conns[:15]

        # CPU times from psutil if available
        try:
            proc = psutil.Process(pid)
            ct = proc.cpu_times()
            detail["cpu_user_s"] = round(ct.user, 1)
            detail["cpu_system_s"] = round(ct.system, 1)
            detail["cpu_percent"] = round(proc.cpu_percent(), 1)
            detail["create_time"] = proc.create_time()
        except Exception:
            detail["cpu_user_s"] = 0
            detail["cpu_system_s"] = 0
            detail["cpu_percent"] = 0

        detail["found"] = True
    except (FileNotFoundError, ProcessLookupError):
        detail["error"] = "process not found"
    except PermissionError:
        detail["error"] = "permission denied"
    except Exception as e:
        detail["error"] = str(e)[:200]

    return detail


def collect_users():
    """Logged-in users with session details and current activity."""
    users = []
    try:
        for u in psutil.users():
            proc_info = ""
            try:
                # Find the user's shell/foreground process
                for proc in psutil.process_iter(["pid", "username", "name", "cmdline", "terminal"]):
                    if (proc.info.get("terminal") == u.terminal
                            and proc.info.get("username") == u.name):
                        args = proc.info.get("cmdline") or []
                        proc_info = " ".join(args) if args else proc.info.get("name", "")
                        break
            except Exception:
                pass
            users.append({
                "name": u.name,
                "terminal": u.terminal or "?",
                "host": u.host or "local",
                "started": u.started,
                "idle_seconds": round(time.time() - u.started, 0) if u.started else 0,
                "current_process": proc_info[:120] if proc_info else "",
            })
    except Exception:
        pass

    # Also try `w` command for richer info
    try:
        import subprocess
        out = subprocess.check_output(["w", "-h", "-i"], text=True, timeout=3)
        w_users = []
        for line in out.strip().split("\n"):
            parts = line.split()
            if len(parts) >= 8:
                w_users.append({
                    "name": parts[0],
                    "terminal": parts[1],
                    "from_ip": parts[2] if ":" in parts[2] or "." in parts[2] else "",
                    "login_time": " ".join(parts[3:5]) if len(parts) > 4 else "",
                    "idle": parts[5] if len(parts) > 5 else "",
                    "what": " ".join(parts[7:]) if len(parts) > 7 else "",
                })
        if w_users:
            users = w_users  # richer data from `w`
    except Exception:
        pass
    return users


def collect_outbound_http():
    """Outbound connections to HTTP/HTTPS ports using ss (no root required for owned)."""
    http_ports = {80, 443, 8080, 8443, 3000, 8000, 8888, 9090}
    outbound = []

    # Use ss -tnp for reliable process mapping (no /proc/pid/fd permission issues)
    import subprocess
    try:
        out = subprocess.check_output(
            ["ss", "-tnp", "state", "established"],
            text=True, timeout=5, stderr=subprocess.DEVNULL
        )
        for line in out.strip().split("\n")[1:]:  # skip header
            parts = line.split()
            if len(parts) < 4:
                continue
            # Parse remote port from peer address (index 3 for 4-field lines, 3 for 5-field)
            remote = parts[3] if len(parts) > 3 else ""
            if ":" not in remote:
                continue
            remote_port_str = remote.split(":")[-1]
            try:
                remote_port = int(remote_port_str)
            except ValueError:
                continue
            if remote_port not in http_ports:
                continue

            remote_ip = ":".join(remote.split(":")[:-1])
            local = parts[2] if len(parts) > 2 else ""
            local_ip = local.split(":")[0] if ":" in local else local

            # Skip localhost
            if remote_ip in ("127.0.0.1", "0.0.0.0", "::1", "[::1]", "*"):
                continue

            # Parse process info from last field: users:(("proc",pid,fd))
            process = "?"
            pid = None
            proc_field = parts[-1] if parts else ""
            if "users:" in proc_field:
                try:
                    inner = proc_field.split("users:(")[1].rstrip(")")
                    chunks = [c.strip() for c in inner.split("),(")]
                    for chunk in chunks:
                        chunk = chunk.strip("()")
                        elems = [e.strip('"') for e in chunk.split(",")]
                        if len(elems) >= 2:
                            process = elems[0]
                            for e in elems[1:]:
                                if "=" in e:
                                    k, v = e.split("=", 1)
                                    if k.strip() == "pid":
                                        try:
                                            pid = int(v.strip())
                                        except ValueError:
                                            pass
                                        break
                            break
                except Exception:
                    pass
            else:
                # No process info (kernel sockets or permission denied)
                continue  # skip connections we can't identify at all

            # Reverse DNS
            hostname = ""
            try:
                import socket
                hostname = socket.gethostbyaddr(remote_ip)[0]
            except Exception:
                hostname = remote_ip

            proto = "https" if remote_port in (443, 8443) else "http"
            url_hint = f"{proto}://{hostname if hostname != remote_ip else remote_ip}"
            if remote_port not in (80, 443):
                url_hint += f":{remote_port}"

            outbound.append({
                "process": process,
                "pid": pid,
                "local": local_ip,
                "remote_ip": remote_ip,
                "remote_host": hostname if hostname != remote_ip else "",
                "remote_port": remote_port,
                "proto": proto,
                "url_hint": url_hint,
            })
    except Exception:
        pass

    outbound.sort(key=lambda x: (x["process"] or "z"))
    return outbound


# ═══════════════════════════════════════════
# Routes
# ═══════════════════════════════════════════

@app.route("/")
def index():
    """Serve the frontend: React app if feature flag is set, otherwise legacy SPA."""
    if _REACT_FRONTEND_ENABLED:
        dist_index = os.path.join(app.static_folder, "dist", "index.html")
        if os.path.isfile(dist_index):
            return send_from_directory(os.path.join(app.static_folder, "dist"), "index.html")
    return send_from_directory("static", "index.html")


@app.route("/assets/<path:filename>")
def react_assets(filename):
    """Serve React build assets when feature flag is enabled."""
    if _REACT_FRONTEND_ENABLED:
        return send_from_directory(os.path.join(app.static_folder, "dist", "assets"), filename)
    return "Not Found", 404


@app.route("/docs/")
@app.route("/docs/<path:filename>")
def docs(filename="index.html"):
    return send_from_directory("static/docs", filename)


@app.route("/add-host")
def add_host_page():
    return send_from_directory("static", "add-host.html")


@app.route("/api/stats")
@auth.require_auth
def api_stats():
    host = request.args.get("host", SELF_HOST)

    # Local host — collect live
    if host == SELF_HOST:
        stats = collect_local_stats()
        with HOSTS_LOCK:
            HOSTS[SELF_HOST] = {
                "last_seen": time.time(),
                "stats": stats,
                "status": "online",
            }
        result = {"host": SELF_HOST, "timestamp": time.time(), **stats}
        if request.args.get("detail") == "true":
            result["deep"] = collect_deep_data()

        # Emit host_stats via SocketIO for real-time frontend updates
        if _socketio_available and socketio is not None:
            try:
                # Emit a compact version (without deep data) to keep events lean
                socketio.emit('host_stats', {
                    "host": SELF_HOST,
                    "timestamp": time.time(),
                    "memory": stats.get("memory", {}),
                    "cpu": stats.get("cpu", {}),
                    "gpu": stats.get("gpu", {}),
                    "disks": stats.get("disks", []),
                })
            except Exception:
                pass  # best-effort; don't break the HTTP response

        return jsonify(result)

    # Remote host — return cached
    with HOSTS_LOCK:
        entry = HOSTS.get(host)

    if not entry:
        return jsonify({"error": "host not found", "host": host}), 404

    now = time.time()
    if now - entry["last_seen"] > STALE_SECONDS:
        entry["status"] = "stale"

    return jsonify({"host": host, "timestamp": time.time(), **entry["stats"]})


@app.route("/api/report", methods=["POST"])
@auth.require_agent_auth
def api_report():
    data = request.get_json(force=True)
    if not data:
        return jsonify({"error": "invalid json"}), 400

    host = data.get("host", "unknown")
    # Don't allow overwriting localhost with agent reports
    if host == SELF_HOST:
        return jsonify({"error": "host name conflicts with collector"}), 409

    stats = {k: v for k, v in data.items() if k not in ("host", "secret", "timestamp")}

    with HOSTS_LOCK:
        HOSTS[host] = {
            "last_seen": time.time(),
            "stats": stats,
            "status": "online",
        }

    # Emit host_stats via SocketIO for real-time frontend updates
    if _socketio_available and socketio is not None:
        try:
            socketio.emit('host_stats', {
                "host": host,
                "timestamp": time.time(),
                "memory": stats.get("memory", {}),
                "cpu": stats.get("cpu", {}),
                "gpu": stats.get("gpu", {}),
                "disks": stats.get("disks", []),
            })
        except Exception:
            pass  # best-effort

    return jsonify({"status": "ok", "host": host})


@app.route("/api/hosts")
@auth.require_auth
def api_hosts():
    prune_stale_hosts()
    now = time.time()

    # Ensure localhost is always present
    with HOSTS_LOCK:
        if SELF_HOST not in HOSTS:
            # Collect a snapshot
            stats = collect_local_stats()
            HOSTS[SELF_HOST] = {
                "last_seen": now,
                "stats": stats,
                "status": "online",
            }

        hosts = {}
        for h, entry in HOSTS.items():
            status = entry.get("status", "online")
            if h != SELF_HOST and now - entry["last_seen"] > STALE_SECONDS:
                status = "stale"
            hosts[h] = {
                "last_seen": entry["last_seen"],
                "status": status,
            }

    return jsonify({"hosts": hosts, "current": SELF_HOST})


@app.route("/api/summary")
@auth.require_auth
def api_summary():
    """Return compact summary for all hosts — used by overview grid."""
    prune_stale_hosts()
    now = time.time()

    # Ensure localhost
    with HOSTS_LOCK:
        if SELF_HOST not in HOSTS:
            stats = collect_local_stats()
            HOSTS[SELF_HOST] = {
                "last_seen": now,
                "stats": stats,
                "status": "online",
            }
        # Collect fresh local stats
        stats = collect_local_stats()
        HOSTS[SELF_HOST] = {
            "last_seen": now,
            "stats": stats,
            "status": "online",
        }

        summaries = {}
        for host, entry in HOSTS.items():
            s = entry.get("stats", {})
            mem = s.get("memory", {})
            cpu = s.get("cpu", {})
            gpu = s.get("gpu", {})
            disks = s.get("disks", [])
            swap = s.get("swap", {})

            status = entry.get("status", "online")
            if host != SELF_HOST and now - entry["last_seen"] > STALE_SECONDS:
                status = "stale"

            # Find root disk
            root_disk = None
            for d in disks:
                if d.get("mountpoint") == "/":
                    root_disk = d
                    break
            if not root_disk and disks:
                root_disk = disks[0]

            summaries[host] = {
                "status": status,
                "last_seen": entry["last_seen"],
                "ram_total_gb": mem.get("total_gb", 0),
                "ram_percent": mem.get("percent", 0),
                "ram_used_gb": mem.get("used_gb", 0),
                "ram_available_gb": mem.get("available_gb", 0),
                "swap_used_gb": swap.get("used_gb", 0),
                "cpu_percent": cpu.get("percent", 0),
                "cpu_cores": cpu.get("core_count_logical", 0),
                "cpu_load": cpu.get("load_1m", 0),
                "cpu_freq": cpu.get("freq_current", 0),
                "gpu_name": gpu.get("name", "none"),
                "gpu_usage": gpu.get("usage", 0),
                "gpu_vram_used_gb": gpu.get("vram_used_gb", 0),
                "gpu_vram_total_gb": gpu.get("vram_total_gb", 0),
                "disk_percent": root_disk["percent"] if root_disk else 0,
                "disk_used_gb": root_disk["used_gb"] if root_disk else 0,
                "disk_total_gb": root_disk["total_gb"] if root_disk else 0,
                "disk_count": len(disks),
            }

    return jsonify({"hosts": summaries, "current": SELF_HOST})


@app.route("/api/cluster")
@auth.require_auth
def api_cluster():
    """Return full stats for all hosts — used by cluster overview."""
    prune_stale_hosts()
    now = time.time()

    with HOSTS_LOCK:
        # Collect fresh local stats
        stats = collect_local_stats()
        HOSTS[SELF_HOST] = {
            "last_seen": now,
            "stats": stats,
            "status": "online",
        }

        hosts_data = {}
        for host, entry in HOSTS.items():
            s = entry.get("stats", {})
            status = entry.get("status", "online")
            if host != SELF_HOST and now - entry["last_seen"] > STALE_SECONDS:
                status = "stale"

            hosts_data[host] = {
                "status": status,
                "last_seen": entry["last_seen"],
                "memory": s.get("memory", {}),
                "swap": s.get("swap", {}),
                "cpu": s.get("cpu", {}),
                "gpu": s.get("gpu", {}),
                "disks": s.get("disks", []),
                "ram_processes": s.get("ram_processes", []),
                "cpu_processes": s.get("cpu_processes", []),
            }

    # Build cross-host top processes
    all_ram = []
    all_cpu = []
    for host, data in hosts_data.items():
        for p in data.get("ram_processes", []):
            all_ram.append({**p, "host": host})
        for p in data.get("cpu_processes", []):
            all_cpu.append({**p, "host": host})

    all_ram.sort(key=lambda x: x.get("memory", 0), reverse=True)
    all_cpu.sort(key=lambda x: x.get("cpu_percent", 0), reverse=True)

    return jsonify({
        "hosts": hosts_data,
        "current": SELF_HOST,
        "cluster_top_ram": all_ram[:20],
        "cluster_top_cpu": all_cpu[:20],
    })


@app.route("/api/process/<int:pid>")
@auth.require_auth
def api_process_detail(pid):
    """Deep forensic detail for a single process (cached)."""
    now = time.time()
    cache_key = str(pid)
    if cache_key in _PROCESS_CACHE:
        entry = _PROCESS_CACHE[cache_key]
        if (now - entry["ts"]) < _PROCESS_CACHE_TTL:
            return jsonify(entry["data"])
    detail = collect_process_detail(pid)
    _PROCESS_CACHE[cache_key] = {"data": detail, "ts": now}
    return jsonify(detail)


@app.route("/api/network")
@auth.require_auth
def api_network():
    """Return network stats for localhost (cached)."""
    global _NETWORK_CACHE
    now = time.time()
    if _NETWORK_CACHE["data"] and (now - _NETWORK_CACHE["ts"]) < _NETWORK_CACHE_TTL:
        return jsonify(_NETWORK_CACHE["data"])
    data = collect_network_stats()
    data["outbound_http"] = collect_outbound_http()
    _NETWORK_CACHE = {"data": data, "ts": now}
    return jsonify(data)


@app.route("/api/users")
@auth.require_auth
def api_users():
    """Return logged-in users and current activity."""
    return jsonify({"users": collect_users()})


@app.route("/install.sh")
def install_script():
    """Serve the agent install script with embedded secret and collector URL."""
    collector_url = "https://your-server.your-tailnet.ts.net:8451"
    script = f"""#!/usr/bin/env bash
# ── System Dashboard Agent Installer ──
# Run: curl -sSL {collector_url}/install.sh | sudo bash
#
# NOTE: DeepSight 0.4.0+ requires API key authentication.
# After installing the agent, login to the dashboard and create an API key:
#   1. Navigate to Settings → API Keys
#   2. Create an API key with 'agent' scope
#   3. Update /opt/sysdash-agent/config.json with the api_key field

set -e

COLLECTOR_URL="{collector_url}"
INSTALL_DIR="/opt/sysdash-agent"
SERVICE_NAME="sysdash-agent"

echo "═══ System Dashboard Agent Installer ═══"
echo ""
echo "Collector: $COLLECTOR_URL"
echo "Install dir: $INSTALL_DIR"
echo ""

# Check root
if [ "$EUID" -ne 0 ]; then
    echo "❌ Please run as root: sudo bash"
    exit 1
fi

# Check Python
PYTHON=""
for py in python3 python; do
    if command -v $py &>/dev/null; then
        PYTHON=$py
        break
    fi
done
if [ -z "$PYTHON" ]; then
    echo "❌ Python 3 not found. Install it first."
    exit 1
fi
echo "✓ Python: $($PYTHON --version)"

# Create install dir
mkdir -p "$INSTALL_DIR"

# Download agent script
echo "→ Downloading agent..."
curl -sSL "$COLLECTOR_URL/agent.py" -o "$INSTALL_DIR/agent.py"
chmod +x "$INSTALL_DIR/agent.py"

# Try to install psutil for richer stats
echo "→ Installing psutil (optional)..."
$PYTHON -m pip install psutil --break-system-packages --quiet 2>/dev/null || \
$PYTHON -m pip install psutil --quiet 2>/dev/null || \
echo "⚠ psutil not available — agent will use basic /proc polling"

# Write config
cat > "$INSTALL_DIR/config.json" << EOFCFG
{{
    "collector_url": "$COLLECTOR_URL",
    "host": "$(hostname)",
    "interval": 2,
    "api_key": "YOUR_API_KEY_HERE"
}}
EOFCFG

echo ""
echo "⚠  IMPORTANT: You must set the api_key in $INSTALL_DIR/config.json"
echo "   Login to the DeepSight dashboard, go to Settings → API Keys,"
echo "   create a key with 'agent' scope, and copy it here."
echo ""

# Create systemd service
cat > "/etc/systemd/system/$SERVICE_NAME.service" << EOFSVC
[Unit]
Description=System Dashboard Agent
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=$PYTHON $INSTALL_DIR/agent.py
WorkingDirectory=$INSTALL_DIR
Restart=always
RestartSec=5
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOFSVC

systemctl daemon-reload
systemctl enable "$SERVICE_NAME"
systemctl start "$SERVICE_NAME"

sleep 2
if systemctl is-active --quiet "$SERVICE_NAME"; then
    echo ""
    echo "✅ Agent installed and running!"
    echo "   Service: systemctl status $SERVICE_NAME"
    echo "   Logs:    journalctl -u $SERVICE_NAME -f"
    echo "   Config:  $INSTALL_DIR/config.json"
    echo ""
    echo "⚠  Don't forget to set the API key in config.json!"
    echo "→ Check your dashboard for '$(hostname)'"
else
    echo "❌ Agent failed to start. Check logs:"
    echo "   journalctl -u $SERVICE_NAME -n 20"
    exit 1
fi
"""
    return script, 200, {"Content-Type": "text/plain; charset=utf-8"}


@app.route("/agent.py")
def agent_script():
    """Serve the agent Python script."""
    return send_from_directory("static", "agent.py")


# ═══════════════════════════════════════════
# DeepSight SIEM Detection Routes
# ═══════════════════════════════════════════

try:
    import detection
    DETECTION_AVAILABLE = True
except ImportError as e:
    print(f"[server] WARNING: detection module not available: {e}", flush=True)
    DETECTION_AVAILABLE = False

# Wire up SocketIO for real-time alert emission
if DETECTION_AVAILABLE and _socketio_available and socketio is not None:
    detection.set_socketio(socketio)
    print("[server] SocketIO wired to detection engine for real-time alerts", flush=True)


@app.route("/api/alerts")
@auth.require_auth
def api_alerts():
    """Return recent alerts with optional filters."""
    if not DETECTION_AVAILABLE:
        return jsonify({"error": "detection engine not available"}), 503
    severity = request.args.get("severity")
    acknowledged_str = request.args.get("acknowledged")
    acknowledged = None
    if acknowledged_str is not None:
        acknowledged = acknowledged_str.lower() == "true"
    alerts = detection.get_alerts(severity=severity, acknowledged=acknowledged)
    return jsonify({"alerts": alerts, "count": len(alerts)})


@app.route("/api/beaconing")
@auth.require_auth
def api_beaconing():
    """Return active beaconing detections."""
    if not DETECTION_AVAILABLE:
        return jsonify({"error": "detection engine not available"}), 503
    return jsonify({"beaconing": detection.get_beaconing()})


@app.route("/api/auth-events")
@auth.require_auth
def api_auth_events():
    """Return recent auth events with optional type filter."""
    if not DETECTION_AVAILABLE:
        return jsonify({"error": "detection engine not available"}), 503
    event_type = request.args.get("type")
    return jsonify({"events": detection.get_auth_events(event_type=event_type)})


@app.route("/api/file-events")
@auth.require_auth
def api_file_events():
    """Return recent file integrity events."""
    if not DETECTION_AVAILABLE:
        return jsonify({"error": "detection engine not available"}), 503
    return jsonify({"events": detection.get_file_events()})


@app.route("/api/security-summary")
@auth.require_auth
def api_security_summary():
    """Aggregated security summary."""
    if not DETECTION_AVAILABLE:
        return jsonify({"error": "detection engine not available"}), 503
    return jsonify(detection.get_security_summary())


@app.route("/api/alerts/acknowledge", methods=["POST"])
@auth.require_auth
def api_acknowledge_alert():
    """Mark an alert as acknowledged."""
    if not DETECTION_AVAILABLE:
        return jsonify({"error": "detection engine not available"}), 503
    data = request.get_json(silent=True) or {}
    alert_id = data.get("id")
    if not alert_id:
        return jsonify({"error": "missing alert id"}), 400
    ok = detection.acknowledge_alert(int(alert_id))
    return jsonify({"status": "ok" if ok else "not found", "id": alert_id})


@app.route("/api/alert-stats")
@auth.require_auth
def api_alert_stats():
    """Alert counts by severity and category for the last 24h."""
    if not DETECTION_AVAILABLE:
        return jsonify({"error": "detection engine not available"}), 503
    hours = request.args.get("hours", 24, type=int)
    return jsonify(detection.get_alert_stats(hours=hours))


@app.route("/api/security-dashboards")
@auth.require_auth
def api_security_dashboards():
    """Return aggregated data for 6 Chart.js security dashboard panels."""
    if not DETECTION_AVAILABLE:
        return jsonify({"error": "detection engine not available"}), 503
    hours = request.args.get("hours", 24, type=int)
    data = detection.get_dashboard_data(hours=hours)

    # ── Agent Health (from HOSTS data) ──
    with HOSTS_LOCK:
        hosts = dict(HOSTS)
    online = sum(1 for h in hosts.values() if h.get("status") == "online")
    stale = sum(1 for h in hosts.values() if h.get("status") == "stale")
    offline = sum(1 for h in hosts.values() if h.get("status") == "offline")
    unknown = max(0, len(hosts) - online - stale - offline)
    data["agent_health"] = {
        "labels": ["Online", "Stale", "Offline", "Unknown"],
        "counts": [online, stale, offline, unknown],
        "total_hosts": len(hosts),
        "host_names": [h for h in hosts.keys()],
    }

    return jsonify(data)


@app.route("/api/attack-coverage")
@auth.require_auth
def api_attack_coverage():
    """Return MITRE ATT&CK coverage data: all tactics/techniques, coverage
    status, rule mappings, and gap analysis recommendations."""
    if not DETECTION_AVAILABLE:
        return jsonify({"error": "detection engine not available"}), 503
    return jsonify(detection.get_attack_coverage())


@app.route("/api/syslog-events")
@auth.require_auth
def api_syslog_events():
    """Return recent syslog events with optional host/facility filters."""
    if not DETECTION_AVAILABLE:
        return jsonify({"error": "detection engine not available"}), 503
    host = request.args.get("host")
    facility = request.args.get("facility")
    limit = request.args.get("limit", 100, type=int)
    events = detection.get_syslog_events(host=host, facility=facility, limit=limit)
    hosts = detection.get_syslog_hosts()
    facilities = detection.get_syslog_facilities()
    return jsonify({
        "events": events,
        "count": len(events),
        "hosts": hosts,
        "facilities": facilities,
    })


@app.route("/api/syslog-hosts")
@auth.require_auth
def api_syslog_hosts():
    """Return distinct syslog hosts."""
    if not DETECTION_AVAILABLE:
        return jsonify({"error": "detection engine not available"}), 503
    return jsonify({"hosts": detection.get_syslog_hosts()})


@app.route("/api/threat-intel")
@auth.require_auth
def api_threat_intel():
    """Return threat intelligence feed status and observed IPs."""
    if not DETECTION_AVAILABLE:
        return jsonify({"error": "detection engine not available"}), 503
    try:
        if not getattr(detection, "HAS_THREAT_INTEL", False):
            return jsonify({"error": "threat intel module not available"}), 503
        import threat_intel
        status = threat_intel.get_threat_intel_status()
        return jsonify(status)
    except ImportError:
        return jsonify({"error": "threat intel module not available"}), 503


@app.route("/api/search")
@auth.require_auth
def api_search():
    """
    Advanced search across all event types, processes, and network connections.

    Query syntax:
      category:intrusion  severity:high  host:open-claw01  source:ssh
      type:alert|auth|fim|beaconing|dns|process|network
      after:2026-05-20  before:2026-05-22  limit:100

    Returns: {results: [...], total: int, query_parsed: dict}
    """
    if not DETECTION_AVAILABLE:
        return jsonify({"error": "detection engine not available"}), 503

    query = request.args.get("q", "").strip()
    if not query:
        return jsonify({
            "results": [], "total": 0, "query_parsed": {},
            "hint": "Provide a search query with ?q=...",
        })

    results = detection.search_events(query)
    return jsonify(results)


# ═══════════════════════════════════════════
# UEBA Anomaly Detection Endpoints
# ═══════════════════════════════════════════

@app.route("/api/anomalies")
@auth.require_auth
def api_anomalies():
    """Return recent UEBA anomalies with optional host/metric filters."""
    if not DETECTION_AVAILABLE:
        return jsonify({"error": "detection engine not available"}), 503
    host = request.args.get("host")
    limit = max(request.args.get("limit", 100, type=int), 1)
    hours = max(request.args.get("hours", 24, type=int), 1)
    engine = detection.get_baseline_engine()
    anomalies = engine.get_anomalies(host=host, limit=limit, hours=hours)

    # Build severity counts for summary badge
    sev_counts = {"low": 0, "medium": 0, "high": 0, "critical": 0}
    for a in anomalies:
        s = a.get("severity", "low")
        if s in sev_counts:
            sev_counts[s] += 1

    return jsonify({
        "anomalies": anomalies,
        "count": len(anomalies),
        "severity_counts": sev_counts,
    })


@app.route("/api/baselines")
@auth.require_auth
def api_baselines():
    """Return current baseline state for all hosts/metrics."""
    if not DETECTION_AVAILABLE:
        return jsonify({"error": "detection engine not available"}), 503
    host = request.args.get("host")
    engine = detection.get_baseline_engine()
    baselines = engine.get_baselines(host=host)

    # Count learning vs active
    learning = sum(1 for b in baselines if b.get("is_learning"))
    active = len(baselines) - learning

    return jsonify({
        "baselines": baselines,
        "count": len(baselines),
        "learning": learning,
        "active": active,
        "config": {
            "window_seconds": detection.BASELINE_WINDOW_SECONDS,
            "learning_samples": detection.BASELINE_LEARNING_SAMPLES,
            "default_threshold": detection.BASELINE_Z_THRESHOLD,
        },
    })


# ═══════════════════════════════════════════
# Correlation Engine Endpoints
# ═══════════════════════════════════════════


@app.route("/api/correlation/matches")
@auth.require_auth
def api_correlation_matches():
    """Return active and completed attack chain matches."""
    if not DETECTION_AVAILABLE:
        return jsonify({"error": "detection engine not available"}), 503

    host = request.args.get("host")
    chain_id = request.args.get("chain_id")

    engine = detection.get_correlation_engine()
    active = engine.get_active_chains(host=host if host else None)
    completed = engine.get_completed_chains(host=host if host else None)

    # Filter by chain_id if requested
    if chain_id:
        active = [a for a in active if a["chain_id"] == chain_id]
        completed = [c for c in completed if c["chain_id"] == chain_id]

    return jsonify({"active": active, "completed": completed})


# ═══════════════════════════════════════════
# Authentication API Endpoints
# ═══════════════════════════════════════════


@app.route("/api/auth/login", methods=["POST"])
def api_auth_login():
    """Authenticate user and return a session token."""
    data = request.get_json(silent=True) or {}
    username = (data.get("username") or "").strip()
    password = data.get("password") or ""

    ip = auth._get_client_ip()

    # Rate limit check
    if not auth.check_rate_limit(ip=ip):
        auth.log_audit(
            event_type="rate_limit_hit",
            username=username or None,
            ip_address=ip,
            user_agent=request.headers.get("User-Agent", ""),
            details="Rate limit exceeded for login endpoint",
        )
        return jsonify({
            "error": "rate_limited",
            "reason": "Too many login attempts. Try again in 60 seconds.",
        }), 429

    if not username or not password:
        return jsonify({
            "error": "invalid_request",
            "reason": "Username and password required",
        }), 400

    user = auth.verify_user(username, password)
    if not user:
        auth.record_failure(ip=ip)
        auth.log_audit(
            event_type="login_failure",
            username=username,
            ip_address=ip,
            user_agent=request.headers.get("User-Agent", ""),
            details="Invalid credentials",
        )
        return jsonify({"error": "unauthorized", "reason": "Invalid credentials"}), 401

    # Create session token
    token_info = auth.create_token(user["id"], token_type="session", scope="full")

    auth.log_audit(
        event_type="login_success",
        username=user["username"],
        user_id=user["id"],
        token_id=token_info["token_id"],
        ip_address=ip,
        user_agent=request.headers.get("User-Agent", ""),
    )

    return jsonify({
        "token": token_info["token"],
        "expires_at": token_info["expires_at"],
        "user": {
            "id": user["id"],
            "username": user["username"],
            "is_admin": user["is_admin"],
        },
    })


@app.route("/api/auth/logout", methods=["POST"])
@auth.require_auth
def api_auth_logout():
    """Revoke the current session token."""
    token = auth._extract_bearer_token()
    if token:
        auth.revoke_token(token)
        auth.log_audit(
            event_type="logout",
            username=g.current_user.get("username"),
            user_id=g.current_user.get("user_id"),
            token_id=g.current_user.get("token_id"),
            ip_address=auth._get_client_ip(),
            user_agent=request.headers.get("User-Agent", ""),
        )
    return jsonify({"status": "ok"})


@app.route("/api/auth/status")
@auth.require_auth
def api_auth_status():
    """Return current user info and token status."""
    return jsonify({
        "user": {
            "id": g.current_user["user_id"],
            "username": g.current_user["username"],
            "is_admin": g.current_user["is_admin"],
        },
        "token_expires": g.current_user.get("expires_at"),
        "scope": g.current_user.get("scope"),
    })


@app.route("/api/auth/api-keys", methods=["POST"])
@auth.require_auth
def api_auth_create_api_key():
    """Create a new API key. Requires authentication."""
    data = request.get_json(silent=True) or {}
    scope = data.get("scope", "read-only")
    ttl_days = data.get("ttl_days")
    name = data.get("name")

    # Validate scope
    valid_scopes = ["read-only", "full", "agent"]
    if scope not in valid_scopes:
        return jsonify({"error": "invalid_scope", "valid_scopes": valid_scopes}), 400

    try:
        key_info = auth.create_api_key(
            g.current_user["user_id"],
            scope=scope,
            ttl_days=ttl_days,
            name=name,
        )
    except ValueError as e:
        return jsonify({"error": str(e)}), 400

    auth.log_audit(
        event_type="api_key_created",
        username=g.current_user["username"],
        user_id=g.current_user["user_id"],
        ip_address=auth._get_client_ip(),
        user_agent=request.headers.get("User-Agent", ""),
        details=f"Created API key scope={scope} name={name}",
    )

    return jsonify({
        "api_key": key_info["api_key"],
        "id": key_info["id"],
        "scope": key_info["scope"],
        "expires_at": key_info["expires_at"],
    }), 201


@app.route("/api/auth/api-keys", methods=["GET"])
@auth.require_auth
def api_auth_list_api_keys():
    """List API keys for the current user."""
    keys = auth.list_api_keys(g.current_user["user_id"])
    return jsonify({"api_keys": keys})


@app.route("/api/auth/api-keys/<int:key_id>", methods=["DELETE"])
@auth.require_auth
def api_auth_revoke_api_key(key_id):
    """Revoke an API key by its ID."""
    ok = auth.revoke_api_key(key_id)
    if not ok:
        return jsonify({"error": "not found"}), 404

    auth.log_audit(
        event_type="api_key_revoked",
        username=g.current_user["username"],
        user_id=g.current_user["user_id"],
        api_key_id=key_id,
        ip_address=auth._get_client_ip(),
        user_agent=request.headers.get("User-Agent", ""),
    )
    return jsonify({"status": "revoked", "id": key_id})


@app.route("/api/auth/audit")
@auth.require_auth
def api_auth_audit():
    """Return recent authentication audit events."""
    limit = request.args.get("limit", 50, type=int)
    event_type = request.args.get("type")
    events = auth.get_audit_events(limit=limit, event_type=event_type)
    return jsonify({"events": events, "count": len(events)})


# ── Start detection collectors in background ──
_starup_detection_done = False
_starup_detection_lock = threading.Lock()


def _start_detection_if_not_running():
    global _starup_detection_done
    with _starup_detection_lock:
        if _starup_detection_done:
            return
        if DETECTION_AVAILABLE:
            detection.start_collectors()
        _starup_detection_done = True


@app.before_request
def _ensure_detection_started():
    """Lazy-start detection collectors on first request."""
    _start_detection_if_not_running()


# ═══════════════════════════════════════════
# V2 Auth Guard (before_request)
# ═══════════════════════════════════════════

@app.before_request
def _v2_auth_guard():
    """Ensure all /api/v2/* requests are authenticated.

    All requests to /api/v2/ paths (except health) require a valid Bearer token.
    This runs before routing, so even non-existent v2 paths return 401 rather
    than 404, preventing endpoint enumeration.

    Individual routes may additionally apply @auth.require_auth for documentation.
    """
    if not request.path.startswith("/api/v2/"):
        return None

    # Health endpoint is public
    if request.path == "/api/v2/health" or request.path.startswith("/api/v2/docs"):
        return None

    # INSECURE_NO_AUTH escape hatch
    if auth.INSECURE_NO_AUTH:
        g.current_user = {
            "user_id": 0,
            "username": "insecure-mode",
            "is_admin": True,
            "scope": "full",
            "token_type": "insecure",
        }
        return None

    token = auth._extract_bearer_token()
    if not token:
        return jsonify({"error": "unauthorized", "reason": "missing token"}), 401

    user = auth.validate_token(token)
    if user is None:
        # Could be expired or invalid
        return jsonify({"error": "unauthorized", "reason": "invalid or expired token"}), 401

    g.current_user = user
    return None


# ═══════════════════════════════════════════
# Security Headers Middleware
# ═══════════════════════════════════════════

@app.after_request
def add_security_headers(response):
    """Add security-related HTTP headers to every response."""
    # HSTS (only in production with HTTPS)
    if not app.config.get("TESTING"):
        response.headers["Strict-Transport-Security"] = (
            "max-age=31536000; includeSubDomains"
        )
    # Prevent MIME type sniffing
    response.headers["X-Content-Type-Options"] = "nosniff"
    # Prevent clickjacking
    response.headers["X-Frame-Options"] = "DENY"
    # Referrer policy
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    # Permissions policy (restrict browser features)
    response.headers["Permissions-Policy"] = (
        "camera=(), microphone=(), geolocation=()"
    )
    # Remove server identity header
    response.headers["X-Powered-By"] = ""
    # Cache control for API responses
    if request.path.startswith("/api/"):
        response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
        response.headers["Pragma"] = "no-cache"

    return response


# ═══════════════════════════════════════════
# Content Security Policy Middleware
# ═══════════════════════════════════════════

@app.after_request
def add_csp_header(response):
    """Add Content-Security-Policy header to HTML responses."""
    # Only add CSP to HTML responses (not API JSON)
    content_type = response.headers.get("Content-Type", "")
    if "text/html" in content_type:
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; "
            "script-src 'self' 'unsafe-inline' 'unsafe-eval' https://unpkg.com https://cdn.jsdelivr.net; "
            "style-src 'self' 'unsafe-inline' https://unpkg.com https://fonts.googleapis.com; "
            "font-src 'self' https://fonts.gstatic.com; "
            "img-src 'self' data:; "
            "connect-src 'self' ws://127.0.0.1:* wss://*; "
            "frame-ancestors 'none'; "
            "form-action 'self'; "
        )
    return response


# ═══════════════════════════════════════════
# V2 Audit Logging Middleware
# ═══════════════════════════════════════════

@app.after_request
def v2_audit_logging(response):
    """Log API v2 requests to the audit trail."""
    if _v2_available and request.path.startswith("/api/v2/"):
        try:
            _ensure_audit_table_lazy()
            log_api_audit(
                method=request.method,
                path=request.path,
                status_code=response.status_code,
                duration_ms=0,
            )
        except Exception:
            pass  # Never let audit logging break the response
    return response


@app.teardown_appcontext
def _flush_audit_on_teardown(error=None):
    """Flush the audit buffer when a request context ends."""
    if _v2_available:
        try:
            _flush_audit_buffer()
        except Exception:
            pass


if __name__ == "__main__":
    # Initialize auth database and admin user
    auth.init_auth_db()
    auth.init_admin_user()
    auth.print_migration_instructions()

    # Start detection collectors immediately in standalone mode
    if DETECTION_AVAILABLE:
        detection.start_collectors()

    # Use SocketIO if available, otherwise plain Flask
    if _socketio_available and socketio is not None:
        print(f"[server] Starting with SocketIO on 127.0.0.1:8451 (React frontend: {_REACT_FRONTEND_ENABLED})")
        socketio.run(app, host="127.0.0.1", port=8451, debug=False, allow_unsafe_werkzeug=True)
    else:
        print(f"[server] Starting without SocketIO on 127.0.0.1:8451 (React frontend: {_REACT_FRONTEND_ENABLED})")
        app.run(host="127.0.0.1", port=8451, debug=False)
