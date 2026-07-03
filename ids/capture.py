import os
import re
import shutil
import subprocess

from django.conf import settings

from . import ml

PORT_SERVICE = {
    80: "http", 443: "http", 8080: "http",
    22: "ssh", 21: "ftp", 25: "smtp", 53: "dns", 110: "other", 143: "other",
}


def find_tshark():
    custom = getattr(settings, "TSHARK_PATH", None)
    if custom and os.path.isfile(custom):
        return custom
    found = shutil.which("tshark")
    if found:
        return found
    for path in (
        r"C:\Program Files\Wireshark\tshark.exe",
        r"C:\Program Files (x86)\Wireshark\tshark.exe",
        "/usr/bin/tshark",
        "/usr/local/bin/tshark",
        "/Applications/Wireshark.app/Contents/MacOS/tshark",
    ):
        if os.path.isfile(path):
            return path
    return None


def get_interfaces(tshark=None):
    tshark = tshark or find_tshark()
    if not tshark:
        return []
    try:
        result = subprocess.run(
            [tshark, "-D"],
            capture_output=True,
            text=True,
            timeout=10,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0) if os.name == "nt" else 0,
        )
        interfaces = []
        for line in result.stdout.splitlines():
            match = re.match(r"^\s*(\d+)\.\s+(.+)$", line)
            if match:
                interfaces.append({"id": match.group(1), "name": match.group(2).strip()})
        return interfaces
    except (OSError, subprocess.SubprocessError):
        return []


def packet_to_features(pkt):
    protocol_raw = (pkt.get("protocol") or "tcp").lower()
    if "icmp" in protocol_raw:
        protocol_type = "icmp"
    elif "udp" in protocol_raw:
        protocol_type = "udp"
    else:
        protocol_type = "tcp"

    try:
        dst_port = int(pkt.get("dst_port") or 0)
    except (TypeError, ValueError):
        dst_port = 0
    service = PORT_SERVICE.get(dst_port, "other")

    frame_len = int(pkt.get("length") or 0)
    src_bytes = max(frame_len // 2, 0)
    dst_bytes = max(frame_len - src_bytes, 0)

    flags = pkt.get("tcp_flags") or ""
    if "A" in flags and "S" in flags:
        flag = "SF"
    elif "S" in flags:
        flag = "S0"
    elif "R" in flags:
        flag = "REJ"
    else:
        flag = "SF"

    base = {name: 0 for name in ml.FEATURE_NAMES}
    base.update(
        {
            "duration": 0,
            "protocol_type": protocol_type,
            "service": service,
            "flag": flag,
            "src_bytes": src_bytes,
            "dst_bytes": dst_bytes,
            "count": 1,
            "srv_count": 1,
            "same_srv_rate": 1.0,
            "diff_srv_rate": 0.0,
            "srv_diff_host_rate": 0.0,
            "dst_host_count": 1,
            "dst_host_srv_count": 1,
            "dst_host_same_srv_rate": 1.0,
            "dst_host_diff_srv_rate": 0.0,
            "dst_host_same_src_port_rate": 1.0,
            "dst_host_srv_diff_host_rate": 0.0,
        }
    )
    return base


def capture_packets(count=None, interface=None, duration=None):
    tshark = find_tshark()
    if not tshark:
        return {
            "ok": False,
            "message": "Wireshark (tshark) not found. Install from https://www.wireshark.org/ and add tshark to PATH.",
            "packets": [],
        }

    count = count or getattr(settings, "CAPTURE_PACKET_COUNT", 10)
    duration = duration or getattr(settings, "CAPTURE_DURATION", 3)
    if not interface:
        interface = getattr(settings, "CAPTURE_INTERFACE", None)
    if not interface:
        ifaces = get_interfaces(tshark)
        interface = ifaces[0]["id"] if ifaces else "1"

    cmd = [
        tshark,
        "-i",
        str(interface),
        "-a",
        f"duration:{duration}",
        "-c",
        str(count),
        "-T",
        "fields",
        "-E",
        "separator=|",
        "-e",
        "ip.src",
        "-e",
        "ip.dst",
        "-e",
        "_ws.col.Protocol",
        "-e",
        "frame.len",
        "-e",
        "tcp.dstport",
        "-e",
        "udp.dstport",
        "-e",
        "tcp.flags.str",
    ]

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=duration + 20,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0) if os.name == "nt" else 0,
        )
    except subprocess.TimeoutExpired:
        return {"ok": False, "message": "Capture timed out.", "packets": []}
    except OSError as exc:
        return {"ok": False, "message": str(exc), "packets": []}

    if result.returncode != 0 and not result.stdout.strip():
        err_lines = (result.stderr or "").strip().splitlines()
        msg = err_lines[-1] if err_lines else "Capture failed. Try running as Administrator with Npcap installed."
        return {"ok": False, "message": msg, "packets": [], "interface": interface}

    packets = []
    for line in result.stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        parts = line.split("|")
        if len(parts) < 4:
            continue
        src, dst, protocol, length = parts[0], parts[1], parts[2], parts[3]
        if not src or not dst:
            continue
        dst_port = parts[4] if len(parts) > 4 and parts[4] else (parts[5] if len(parts) > 5 else "")
        packets.append(
            {
                "source_ip": src,
                "dest_ip": dst,
                "protocol": (protocol or "TCP").upper(),
                "length": int(length or 0),
                "dst_port": dst_port,
                "tcp_flags": parts[6] if len(parts) > 6 else "",
            }
        )

    iface_name = interface
    for item in get_interfaces(tshark):
        if item["id"] == str(interface):
            iface_name = item["name"]
            break

    return {
        "ok": True,
        "packets": packets,
        "interface": interface,
        "interface_name": iface_name,
        "message": f"Captured {len(packets)} packet(s) via Wireshark",
    }
