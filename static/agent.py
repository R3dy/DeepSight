#!/usr/bin/env python3
"""
System Dashboard Agent — lightweight remote host reporter.
Runs on any Linux host, reports stats to a System Dashboard collector.

Usage:
  python3 agent.py                          # uses config.json in same dir
  python3 agent.py --host my-server \       # override hostname
      --collector https://IP:8451 \
      --secret my-key \
      --interval 3
"""

import json
import os
import sys
import time
import glob
import socket
import urllib.request
import urllib.error
import argparse

# ── Optional psutil ──
try:
    import psutil

    HAS_PSUTIL = True
except ImportError:
    HAS_PSUTIL = False


# ═══════════════════════════════════════════
# Pure-stdlib fallback collectors
# ═══════════════════════════════════════════


def _read_file(path, default=""):
    try:
        with open(path) as f:
            return f.read().strip()
    except Exception:
        return default


def _read_int(path, default=0):
    try:
        return int(_read_file(path, str(default)))
    except Exception:
        return default


def collect_memory_proc():
    """Parse /proc/meminfo for memory stats."""
    meminfo = {}
    try:
        with open("/proc/meminfo") as f:
            for line in f:
                parts = line.split(":")
                if len(parts) == 2:
                    key = parts[0].strip()
                    val = parts[1].strip().split()[0]
                    meminfo[key] = int(val)
    except Exception:
        pass

    # Convert from kB to bytes
    total = meminfo.get("MemTotal", 0) * 1024
    free = meminfo.get("MemFree", 0) * 1024
    available = meminfo.get("MemAvailable", 0) * 1024
    buffers = meminfo.get("Buffers", 0) * 1024
    cached = meminfo.get("Cached", 0) * 1024 + meminfo.get("SReclaimable", 0) * 1024
    used = total - free - buffers - cached
    if used < 0:
        used = total - available

    swap_total = meminfo.get("SwapTotal", 0) * 1024
    swap_free = meminfo.get("SwapFree", 0) * 1024
    swap_used = swap_total - swap_free
    swap_percent = (swap_used / swap_total * 100) if swap_total > 0 else 0

    return {
        "total": total,
        "available": available,
        "used": used,
        "free": free,
        "buffers": buffers,
        "cached": cached,
        "percent": round((used / total * 100) if total > 0 else 0, 1),
        "total_gb": round(total / 1024**3, 1),
        "used_gb": round(used / 1024**3, 1),
        "available_gb": round(available / 1024**3, 1),
        "free_gb": round(free / 1024**3, 1),
        "cached_gb": round(cached / 1024**3, 1),
        "buffers_gb": round(buffers / 1024**3, 1),
    }, {
        "total": swap_total,
        "used": swap_used,
        "free": swap_free,
        "percent": round(swap_percent, 1),
        "total_gb": round(swap_total / 1024**3, 1),
        "used_gb": round(swap_used / 1024**3, 1),
    }


def collect_cpu_proc():
    """Parse /proc/stat for CPU usage."""
    try:
        with open("/proc/stat") as f:
            line = f.readline()
        parts = line.split()
        if parts[0] != "cpu":
            return 0, [], 0, 0
        # user nice system idle iowait irq softirq steal
        vals = [int(x) for x in parts[1:8]]
        total = sum(vals)
        idle = vals[3] + vals[4]  # idle + iowait
        return total, idle, 0, 0
    except Exception:
        return 0, 0, 0, 0


# Cache for CPU delta calculation
_CPU_PREV = {"total": 0, "idle": 0, "ts": 0}


def collect_cpu():
    """Collect CPU stats using psutil if available, /proc fallback."""
    if HAS_PSUTIL:
        cpu_pct = psutil.cpu_percent(interval=0.1)
        cores = psutil.cpu_percent(interval=None, percpu=True)
        cores = [round(c, 1) for c in (cores or [])]
        freq = psutil.cpu_freq()
        logical = psutil.cpu_count(logical=True)
        physical = psutil.cpu_count(logical=False)
        f_cur = freq.current if freq else 0
        f_max = freq.max if freq else 0
    else:
        total, idle, _, _ = collect_cpu_proc()
        now = time.time()
        pct = 0.0
        if _CPU_PREV["total"] > 0 and (now - _CPU_PREV["ts"]) > 0.1:
            d_total = total - _CPU_PREV["total"]
            d_idle = idle - _CPU_PREV["idle"]
            if d_total > 0:
                pct = round((1 - d_idle / d_total) * 100, 1)
        _CPU_PREV["total"] = total
        _CPU_PREV["idle"] = idle
        _CPU_PREV["ts"] = now
        cpu_pct = pct
        cores = [pct]
        logical = os.cpu_count() or 1
        physical = logical
        f_cur = 0
        f_max = 0
        # Try to get CPU freq
        try:
            with open("/sys/devices/system/cpu/cpu0/cpufreq/scaling_cur_freq") as f:
                f_cur = int(f.read().strip()) * 1000  # kHz → Hz
        except Exception:
            pass
        try:
            with open("/sys/devices/system/cpu/cpu0/cpufreq/scaling_max_freq") as f:
                f_max = int(f.read().strip()) * 1000
        except Exception:
            pass

    load = os.getloadavg()
    return {
        "percent": cpu_pct,
        "cores": cores,
        "core_count_logical": logical,
        "core_count_physical": physical,
        "freq_current": f_cur,
        "freq_max": f_max,
        "load_1m": round(load[0], 2),
        "load_5m": round(load[1], 2),
        "load_15m": round(load[2], 2),
    }


def collect_gpu():
    """Collect GPU stats from sysfs."""
    gpu = {
        "name": "none", "usage": 0, "vram_used": 0, "vram_total": 0,
        "vram_used_gb": 0, "vram_total_gb": 0, "gtt_used": 0, "gtt_used_gb": 0,
    }
    found = False
    for card in sorted(glob.glob("/sys/class/drm/card*/device")):
        try:
            vf = os.path.join(card, "mem_info_vram_total")
            if os.path.exists(vf):
                gpu["usage"] = _read_int(os.path.join(card, "gpu_busy_percent"))
                gpu["vram_used"] = _read_int(os.path.join(card, "mem_info_vram_used"))
                gpu["vram_total"] = _read_int(vf)
                gpu["gtt_used"] = _read_int(os.path.join(card, "mem_info_gtt_used"))
                gpu["vram_used_gb"] = round(gpu["vram_used"] / 1024**3, 1)
                gpu["vram_total_gb"] = round(gpu["vram_total"] / 1024**3, 1)
                gpu["gtt_used_gb"] = round(gpu["gtt_used"] / 1024**3, 1)
                # Try to get name
                try:
                    with open(os.path.join(card, "../uevent")) as f:
                        for line in f:
                            if "DRIVER=amdgpu" in line:
                                gpu["name"] = "AMD Radeon (amdgpu)"
                            elif "DRIVER=i915" in line:
                                gpu["name"] = "Intel (i915)"
                            elif "DRIVER=nouveau" in line:
                                gpu["name"] = "NVIDIA (nouveau)"
                except Exception:
                    pass
                found = True
                break
        except Exception:
            pass
    if not found:
        gpu["name"] = "none detected"
    return gpu


def collect_disks():
    """Collect disk usage stats."""
    disks = []
    if HAS_PSUTIL:
        for part in psutil.disk_partitions():
            if part.device.startswith("/dev/loop") or part.device.startswith("tmp"):
                continue
            try:
                usage = psutil.disk_usage(part.mountpoint)
                disks.append({
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
                })
            except PermissionError:
                pass
    else:
        # /proc/mounts fallback
        try:
            with open("/proc/mounts") as f:
                for line in f:
                    parts = line.split()
                    if len(parts) < 3:
                        continue
                    dev, mp, fstype = parts[0], parts[1], parts[2]
                    if dev.startswith("/dev/loop") or fstype in ("tmpfs", "devtmpfs",
                            "proc", "sysfs", "cgroup", "cgroup2", "debugfs",
                            "securityfs", "pstore", "efivarfs", "bpf", "fusectl",
                            "configfs", "hugetlbfs", "mqueue", "tracefs"):
                        continue
                    if mp == "/snap" or "/snap/" in mp:
                        continue
                    try:
                        st = os.statvfs(mp)
                        total = st.f_blocks * st.f_frsize
                        free = st.f_bfree * st.f_frsize
                        used = total - free
                        pct = round(used / total * 100, 1) if total > 0 else 0
                        disks.append({
                            "device": dev,
                            "mountpoint": mp,
                            "fstype": fstype,
                            "total": total,
                            "used": used,
                            "free": free,
                            "percent": pct,
                            "total_gb": round(total / 1024**3, 1),
                            "used_gb": round(used / 1024**3, 1),
                            "free_gb": round(free / 1024**3, 1),
                        })
                    except Exception:
                        pass
        except Exception:
            pass
    return disks


def collect_processes(mem_total):
    """Collect top processes by RAM and CPU."""
    ram_procs = []
    cpu_procs = []

    if HAS_PSUTIL:
        for proc in psutil.process_iter(["pid", "name", "memory_info", "cpu_percent"]):
            try:
                info = proc.info
                rss = info["memory_info"].rss
                cpu = info.get("cpu_percent", 0) or 0
                if rss > 2 * 1024 * 1024:
                    entry = {
                        "pid": info["pid"],
                        "name": info["name"],
                        "memory": rss,
                        "memory_mb": round(rss / (1024 * 1024), 1),
                        "memory_gb": round(rss / (1024**3), 2),
                        "ram_percent": round(rss / mem_total * 100, 2),
                        "cpu_percent": round(cpu, 1),
                    }
                    ram_procs.append(entry)
                    if cpu > 0.05:
                        cpu_procs.append(entry)
                    elif cpu > 0:
                        cpu_procs.append(entry)
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
    else:
        # /proc fallback — basic
        for pid_dir in glob.glob("/proc/[0-9]*"):
            try:
                pid = int(os.path.basename(pid_dir))
                with open(os.path.join(pid_dir, "comm")) as f:
                    name = f.read().strip()
                # Read RSS from /proc/pid/statm
                with open(os.path.join(pid_dir, "statm")) as f:
                    rss_pages = int(f.read().split()[1])
                rss = rss_pages * 4096
                if rss > 2 * 1024 * 1024:
                    entry = {
                        "pid": pid,
                        "name": name,
                        "memory": rss,
                        "memory_mb": round(rss / (1024 * 1024), 1),
                        "memory_gb": round(rss / (1024**3), 2),
                        "ram_percent": round(rss / mem_total * 100, 2),
                        "cpu_percent": 0,
                    }
                    ram_procs.append(entry)
            except Exception:
                continue

    ram_procs.sort(key=lambda x: x["memory"], reverse=True)
    cpu_procs.sort(key=lambda x: x["cpu_percent"], reverse=True)

    # Aggregate
    def aggregate(procs, top_n, by_field):
        top = procs[:top_n]
        rest = procs[top_n:]
        if rest:
            total = sum(p[by_field] for p in rest)
            t_mb = round(total / (1024 * 1024), 1) if by_field == "memory" else round(total, 1)
            t_pct = round(total / mem_total * 100, 2) if by_field == "memory" else total
            top.append({
                "pid": 0,
                "name": f"other ({len(rest)})",
                "memory": total if by_field == "memory" else 0,
                "memory_mb": t_mb if by_field == "memory" else 0,
                "memory_gb": round(total / (1024**3), 2) if by_field == "memory" else 0,
                "ram_percent": t_pct if by_field == "memory" else 0,
                "cpu_percent": round(total, 1) if by_field == "cpu_percent" else 0,
            })
        return top

    return (
        aggregate(ram_procs, 15, "memory"),
        aggregate(cpu_procs, 15, "cpu_percent"),
    )


def collect_all():
    """Collect all system stats."""
    mem, swap = collect_memory_proc() if not HAS_PSUTIL else _collect_memory_psutil()
    cpu = collect_cpu()
    gpu = collect_gpu()
    disks = collect_disks()
    ram_procs, cpu_procs = collect_processes(mem["total"])
    return {
        "memory": mem,
        "swap": swap,
        "cpu": cpu,
        "gpu": gpu,
        "disks": disks,
        "ram_processes": ram_procs,
        "cpu_processes": cpu_procs,
    }


def _collect_memory_psutil():
    """Memory stats using psutil."""
    mem = psutil.virtual_memory()
    swap = psutil.swap_memory()
    return {
        "total": mem.total, "available": mem.available, "used": mem.used,
        "free": mem.free, "buffers": getattr(mem, "buffers", 0),
        "cached": getattr(mem, "cached", 0), "percent": mem.percent,
        "total_gb": round(mem.total / 1024**3, 1),
        "used_gb": round(mem.used / 1024**3, 1),
        "available_gb": round(mem.available / 1024**3, 1),
        "free_gb": round(mem.free / 1024**3, 1),
        "cached_gb": round(getattr(mem, "cached", 0) / 1024**3, 1),
        "buffers_gb": round(getattr(mem, "buffers", 0) / 1024**3, 1),
    }, {
        "total": swap.total, "used": swap.used, "free": swap.free,
        "percent": swap.percent, "total_gb": round(swap.total / 1024**3, 1),
        "used_gb": round(swap.used / 1024**3, 1),
    }


def load_config():
    """Load config from config.json or CLI args."""
    script_dir = os.path.dirname(os.path.abspath(__file__))
    config_path = os.path.join(script_dir, "config.json")

    defaults = {
        "collector_url": "https://open-claw01.tail9058f7.ts.net:8451",
        "secret": "sysdash-agent-key-2026",
        "host": socket.gethostname(),
        "interval": 2,
    }

    # Try config file
    if os.path.exists(config_path):
        try:
            with open(config_path) as f:
                cfg = json.load(f)
            defaults.update(cfg)
        except Exception:
            pass

    # CLI overrides
    parser = argparse.ArgumentParser(description="System Dashboard Agent")
    parser.add_argument("--host", help="Host identifier (default: hostname)")
    parser.add_argument("--collector", help="Collector URL")
    parser.add_argument("--secret", help="Shared secret")
    parser.add_argument("--interval", type=int, help="Report interval in seconds")
    args = parser.parse_args()

    if args.host:
        defaults["host"] = args.host
    if args.collector:
        defaults["collector_url"] = args.collector.rstrip("/")
    if args.secret:
        defaults["secret"] = args.secret
    if args.interval:
        defaults["interval"] = args.interval

    return defaults


def report(config, stats):
    """POST stats to collector."""
    url = f"{config['collector_url']}/api/report"
    payload = {
        "host": config["host"],
        "secret": config["secret"],
        "timestamp": time.time(),
        **stats,
    }
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        url, data=data, headers={"Content-Type": "application/json"}
    )
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            return json.loads(resp.read())
    except urllib.error.HTTPError as e:
        body = e.read().decode()[:200] if e.fp else ""
        return {"error": f"HTTP {e.code}: {body}"}
    except Exception as e:
        return {"error": str(e)[:200]}


def main():
    config = load_config()
    print(f"═══ System Dashboard Agent ═══")
    print(f"Host:      {config['host']}")
    print(f"Collector: {config['collector_url']}")
    print(f"Interval:  {config['interval']}s")
    print(f"psutil:    {'available' if HAS_PSUTIL else 'fallback (/proc)'}")
    print()

    consecutive_errors = 0
    while True:
        try:
            stats = collect_all()
            result = report(config, stats)

            if "error" in result:
                consecutive_errors += 1
                if consecutive_errors <= 3:
                    print(f"[{time.strftime('%H:%M:%S')}] ❌ {result['error']}", flush=True)
            else:
                if consecutive_errors > 0:
                    print(f"[{time.strftime('%H:%M:%S')}] ✅ reconnected", flush=True)
                consecutive_errors = 0
        except Exception as e:
            consecutive_errors += 1
            if consecutive_errors <= 3:
                print(f"[{time.strftime('%H:%M:%S')}] ❌ {e}", flush=True)

        time.sleep(config["interval"])


if __name__ == "__main__":
    main()
