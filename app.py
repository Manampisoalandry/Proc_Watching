from __future__ import annotations

import os
import time
import json
import csv
import io
import hashlib
import re
import pwd
import ipaddress
import sqlite3
import subprocess
from typing import Any, Dict, List, Optional, Tuple

from flask import Flask, jsonify, render_template, request, Response, send_file
import psutil

app = Flask(__name__)

# =============================================================================
# Storage / Configuration
# =============================================================================

BASE_DIR = os.path.abspath(os.path.dirname(__file__))
DATA_DIR = os.environ.get("PROCWATCH_DATA_DIR", os.path.join(BASE_DIR, "data"))
os.makedirs(DATA_DIR, exist_ok=True)

DB_PATH = os.path.join(DATA_DIR, "baseline.sqlite3")
ALLOWLIST_PATH = os.path.join(DATA_DIR, "allowlist.json")

ADMIN_TOKEN = os.environ.get("PROCWATCH_ADMIN_TOKEN", "").strip()  # required for dangerous actions / allowlist changes
EBPF_LOG_PATH = os.environ.get("PROCWATCH_EBPF_LOG", "/tmp/procwatch_ebpf.jsonl")

# Red threshold (risk_score >= => category "suspicious")
RED_THRESHOLD = int(os.environ.get("PROCWATCH_RED_THRESHOLD", "3"))

# Limits (avoid killing performance)
DETAIL_MAX_OPEN_FILES = 25
DETAIL_MAX_CONNECTIONS = 60
SCRIPT_SCAN_MAX_BYTES = 32768
AUDIT_MAX_EVENTS = 250
EBPF_MAX_EVENTS = 250

# Cache for heavier lookups
_HASH_CACHE: Dict[str, Tuple[float, int, str]] = {}
_DPKG_CACHE: Dict[str, Tuple[float, Optional[str]]] = {}  # path -> (ts, owner)
_RULES_CACHE: Dict[str, Any] = {}

# Snapshot memory for diff
_LAST_SNAPSHOT: Dict[int, Dict[str, Any]] = {}
_LAST_SNAPSHOT_TS: int = 0


def _now() -> int:
    return int(time.time())


def _db() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH, timeout=3, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn


def _init_db() -> None:
    conn = _db()
    cur = conn.cursor()
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS exec_seen (
            sha256 TEXT PRIMARY KEY,
            first_seen INTEGER NOT NULL,
            last_seen INTEGER NOT NULL,
            path TEXT,
            dpkg_owner TEXT,
            times_seen INTEGER NOT NULL DEFAULT 1
        )
        """
    )
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS cmd_seen (
            cmd_hash TEXT PRIMARY KEY,
            first_seen INTEGER NOT NULL,
            last_seen INTEGER NOT NULL,
            cmd TEXT,
            times_seen INTEGER NOT NULL DEFAULT 1
        )
        """
    )
    conn.commit()
    conn.close()


_init_db()


# =============================================================================
# Allowlist (whitelist)
# =============================================================================

def _load_allowlist() -> Dict[str, Any]:
    default = {"sha256": [], "paths": [], "cmd_regex": [], "names": [], "users": []}
    try:
        if not os.path.exists(ALLOWLIST_PATH):
            with open(ALLOWLIST_PATH, "w", encoding="utf-8") as f:
                json.dump(default, f, indent=2, ensure_ascii=False)
            return default
        with open(ALLOWLIST_PATH, "r", encoding="utf-8") as f:
            data = json.load(f)
        for k in default:
            if k not in data or not isinstance(data[k], list):
                data[k] = []
        return data
    except Exception:
        return default


def _save_allowlist(data: Dict[str, Any]) -> None:
    tmp = ALLOWLIST_PATH + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)
    os.replace(tmp, ALLOWLIST_PATH)


def _is_allowlisted(name: str, user: str, exe: str, cmd: str, sha256: str) -> Tuple[bool, str]:
    al = _load_allowlist()
    if sha256 and sha256 in al["sha256"]:
        return True, "allowlist: sha256"
    if exe and exe in al["paths"]:
        return True, "allowlist: path"
    if name and name in al["names"]:
        return True, "allowlist: name"
    if user and user in al["users"]:
        return True, "allowlist: user"
    if cmd:
        for pat in al["cmd_regex"]:
            try:
                if re.search(pat, cmd):
                    return True, "allowlist: cmd_regex"
            except re.error:
                continue
    return False, ""


# =============================================================================
# Heuristics / Detection (no antivirus claims)
# =============================================================================

COMMON_COMMANDS = {
    "bash", "zsh", "fish", "sh", "dash",
    "sudo", "su", "ssh", "scp", "sftp",
    "top", "htop", "ps", "pgrep", "pkill",
    "grep", "awk", "sed", "cut", "sort", "less", "more",
    "curl", "wget", "nc", "netcat", "ss", "ip", "ping", "traceroute",
    "rsync", "tar", "gzip", "gunzip", "zip", "unzip",
    "python", "python3", "node", "npm", "npx", "ruby", "php", "java", "go",
    "make", "cmake", "gcc", "g++", "clang",
    "docker", "podman", "git",
}

SYSTEM_PATH_PREFIXES = ("/sbin/", "/usr/sbin/", "/lib/systemd/", "/usr/lib/systemd/")
TEMP_PATH_PREFIXES = ("/tmp/", "/var/tmp/", "/dev/shm/")
RUNTIME_WRITABLE_PREFIXES = ("/run/user/",)

SCRIPT_INTERPRETERS = {
    "bash", "sh", "dash", "zsh",
    "python", "python3",
    "perl", "ruby",
    "node", "php",
}

INLINE_FLAGS = {
    "bash": {"-c"},
    "sh": {"-c"},
    "dash": {"-c"},
    "zsh": {"-c"},
    "python": {"-c"},
    "python3": {"-c"},
    "perl": {"-e"},
    "ruby": {"-e"},
    "node": {"-e"},
    "php": {"-r"},
}

MASQUERADE_NAMES = {
    "kworker", "ksoftirqd", "kswapd", "rcu_sched", "rcu_preempt", "migration",
    "systemd", "journald", "dbus-daemon", "udevd",
}

# LOLBins (very partial but practical)
LOLBINS = {
    "curl", "wget", "bash", "sh", "python", "python3", "perl", "ruby", "node", "php",
    "openssl", "base64", "socat", "nc", "ncat", "ssh", "tar", "dd", "xxd",
}

SUSPICIOUS_PORTS = {4444, 1337, 6667, 9001, 9050, 1080}

SUSPICIOUS_SCRIPT_PATTERNS = [
    (re.compile(r"\bcurl\b.*\|\s*(sh|bash)\b", re.I), "pipeline curl | sh/bash"),
    (re.compile(r"\bwget\b.*\|\s*(sh|bash)\b", re.I), "pipeline wget | sh/bash"),
    (re.compile(r"/dev/tcp/\d{1,3}(\.\d{1,3}){3}/\d+", re.I), "reverse shell /dev/tcp"),
    (re.compile(r"\bmkfifo\b.*\b(nc|netcat|ncat|socat)\b", re.I), "reverse shell mkfifo + netcat/socat"),
    (re.compile(r"\b(eval|exec)\b", re.I), "eval/exec"),
    (re.compile(r"\bos\.system\b|\bsubprocess\.(popen|run|call)\b", re.I), "execution via system/subprocess"),
    (re.compile(r"\b(crontab|@reboot)\b", re.I), "persistence via cron"),
    (re.compile(r"\bsystemctl\b.*\b(enable|daemon-reload)\b", re.I), "persistence via systemd"),
    (re.compile(r"\b(base64|openssl)\b", re.I), "obfuscation/encoding base64/openssl"),
    (re.compile(r"[A-Za-z0-9+/]{160,}={0,2}"), "long base64-like blob"),
    (re.compile(r"(\\x[0-9a-fA-F]{2}){6,}"), "hex-escaped blob"),
    (re.compile(r"(\\u[0-9a-fA-F]{4}){6,}"), "unicode-escaped blob"),
    (re.compile(r"\b(xmrig|minerd|stratum\+tcp|cryptonight|monero)\b", re.I), "miner indicators"),
]

def _basename(s: str) -> str:
    return s.split("/")[-1] if s else s


def _looks_like_path(arg: str) -> bool:
    if not arg:
        return False
    return arg.startswith(("/", "./", "../"))


def _is_world_writable(path: str) -> Optional[bool]:
    try:
        st = os.stat(path)
        return bool(st.st_mode & 0o002)
    except Exception:
        return None


def _read_proc_environ(pid: int, max_bytes: int = 4096) -> Dict[str, str]:
    env: Dict[str, str] = {}
    try:
        with open(f"/proc/{pid}/environ", "rb") as f:
            raw = f.read(max_bytes)
        for chunk in raw.split(b"\x00"):
            if b"=" not in chunk:
                continue
            k, v = chunk.split(b"=", 1)
            env[k.decode(errors="ignore")] = v.decode(errors="ignore")
    except Exception:
        return {}
    return env


def safe_username(uid: Optional[int]) -> str:
    if uid is None:
        return "unknown"
    try:
        return pwd.getpwuid(uid).pw_name
    except Exception:
        return str(uid)


def readlink_safe(path: str) -> Optional[str]:
    try:
        return os.readlink(path)
    except Exception:
        return None


def get_exe_path(proc: psutil.Process) -> Optional[str]:
    link = readlink_safe(f"/proc/{proc.pid}/exe")
    if link:
        return link
    try:
        return proc.exe()
    except Exception:
        return None


def get_cmdline(proc: psutil.Process) -> List[str]:
    try:
        return proc.cmdline()
    except Exception:
        return []


def _sha256_file(path: str, max_bytes: Optional[int] = None) -> Optional[str]:
    try:
        st = os.stat(path)
        mtime = float(st.st_mtime)
        size = int(st.st_size)
        cached = _HASH_CACHE.get(path)
        if cached and cached[0] == mtime and cached[1] == size and max_bytes is None:
            return cached[2]

        h = hashlib.sha256()
        with open(path, "rb") as f:
            if max_bytes is None:
                for chunk in iter(lambda: f.read(1024 * 1024), b""):
                    h.update(chunk)
            else:
                remaining = max_bytes
                while remaining > 0:
                    chunk = f.read(min(1024 * 1024, remaining))
                    if not chunk:
                        break
                    h.update(chunk)
                    remaining -= len(chunk)
        digest = h.hexdigest()
        if max_bytes is None:
            _HASH_CACHE[path] = (mtime, size, digest)
        return digest
    except Exception:
        return None


def _looks_randomish(name: str) -> bool:
    if not name:
        return False
    n = name.strip()
    if len(n) < 12:
        return False
    if any(ch in n for ch in (".", " ")):
        return False
    letters = sum(c.isalpha() for c in n)
    digits = sum(c.isdigit() for c in n)
    if letters + digits < len(n) * 0.85:
        return False
    if digits / max(1, len(n)) >= 0.35:
        return True
    vowels = sum(c.lower() in "aeiouy" for c in n if c.isalpha())
    return vowels <= 1


def _looks_like_masquerade(proc_name: str, exe: Optional[str]) -> bool:
    if not proc_name:
        return False
    base = proc_name.split()[0]
    key = base.split("/")[0].split(":")[0]
    if key not in MASQUERADE_NAMES:
        return False
    if not exe:
        return True
    return not exe.startswith(SYSTEM_PATH_PREFIXES) and not exe.startswith("/usr/bin/") and not exe.startswith("/bin/")


def _is_private_ip(ip: str) -> Optional[bool]:
    try:
        o = ipaddress.ip_address(ip)
        return o.is_private or o.is_loopback or o.is_link_local
    except Exception:
        return None


def _dpkg_owner(path: str, ttl: int = 3600) -> Optional[str]:
    if not path:
        return None
    now = _now()
    cached = _DPKG_CACHE.get(path)
    if cached and (now - int(cached[0])) < ttl:
        return cached[1]
    owner: Optional[str] = None
    try:
        # dpkg -S returns e.g. "coreutils: /bin/ls"
        cp = subprocess.run(
            ["dpkg", "-S", path],
            capture_output=True,
            text=True,
            timeout=0.5,
            check=False,
        )
        if cp.returncode == 0 and cp.stdout:
            line = cp.stdout.strip().splitlines()[0]
            owner = line.split(":", 1)[0].strip() if ":" in line else line.strip()
        else:
            owner = None
    except Exception:
        owner = None
    _DPKG_CACHE[path] = (float(now), owner)
    return owner


def _baseline_upsert_exec(sha256: str, path: str, dpkg_owner: Optional[str]) -> Dict[str, Any]:
    if not sha256:
        return {"known": False}
    conn = _db()
    cur = conn.cursor()
    now = _now()
    cur.execute("SELECT sha256, first_seen, last_seen, times_seen, path, dpkg_owner FROM exec_seen WHERE sha256=?", (sha256,))
    row = cur.fetchone()
    if row:
        cur.execute(
            "UPDATE exec_seen SET last_seen=?, times_seen=times_seen+1, path=COALESCE(?, path), dpkg_owner=COALESCE(?, dpkg_owner) WHERE sha256=?",
            (now, path or None, dpkg_owner or None, sha256),
        )
        conn.commit()
        conn.close()
        return {
            "known": True,
            "first_seen": int(row["first_seen"]),
            "last_seen": now,
            "times_seen": int(row["times_seen"]) + 1,
            "path": row["path"] or path,
            "dpkg_owner": row["dpkg_owner"] or dpkg_owner,
        }
    cur.execute(
        "INSERT OR REPLACE INTO exec_seen(sha256, first_seen, last_seen, path, dpkg_owner, times_seen) VALUES(?,?,?,?,?,?)",
        (sha256, now, now, path or None, dpkg_owner or None, 1),
    )
    conn.commit()
    conn.close()
    return {"known": False, "first_seen": now, "last_seen": now, "times_seen": 1, "path": path, "dpkg_owner": dpkg_owner}


def _baseline_upsert_cmd(cmd: str) -> Dict[str, Any]:
    if not cmd:
        return {"known": False}
    h = hashlib.sha1(cmd.encode("utf-8", errors="ignore")).hexdigest()
    conn = _db()
    cur = conn.cursor()
    now = _now()
    cur.execute("SELECT cmd_hash, first_seen, last_seen, times_seen FROM cmd_seen WHERE cmd_hash=?", (h,))
    row = cur.fetchone()
    if row:
        cur.execute("UPDATE cmd_seen SET last_seen=?, times_seen=times_seen+1 WHERE cmd_hash=?", (now, h))
        conn.commit()
        conn.close()
        return {"known": True, "first_seen": int(row["first_seen"]), "last_seen": now, "times_seen": int(row["times_seen"]) + 1, "cmd_hash": h}
    cur.execute("INSERT OR REPLACE INTO cmd_seen(cmd_hash, first_seen, last_seen, cmd, times_seen) VALUES(?,?,?,?,?)", (h, now, now, cmd[:2000], 1))
    conn.commit()
    conn.close()
    return {"known": False, "first_seen": now, "last_seen": now, "times_seen": 1, "cmd_hash": h}


def risk_level(score: int) -> str:
    if score >= RED_THRESHOLD:
        return "high"
    if score == 2:
        return "medium"
    if score == 1:
        return "low"
    return "none"


def _read_small_text(path: str, max_bytes: int) -> str:
    try:
        with open(path, "rb") as f:
            raw = f.read(max_bytes)
        return raw.decode("utf-8", errors="ignore")
    except Exception:
        return ""


def _find_script_path(cmdline: List[str], cwd: str) -> Optional[str]:
    if not cmdline:
        return None
    base = _basename(cmdline[0])
    if base not in SCRIPT_INTERPRETERS:
        return None
    flags = INLINE_FLAGS.get(base, set())

    # ignore inline
    for a in cmdline[1:4]:
        if a in flags:
            return None

    for arg in cmdline[1:12]:
        if not isinstance(arg, str):
            continue
        if arg in {"--", "-c", "-e", "-r", "-m"}:
            continue
        if arg.startswith("-"):
            continue
        if _looks_like_path(arg):
            p = arg
            if p.startswith("./") and cwd:
                p = os.path.normpath(os.path.join(cwd, p))
            elif not p.startswith("/") and cwd:
                p = os.path.normpath(os.path.join(cwd, p))
            return p
    return None


def _score_script_content(script_path: str) -> Tuple[int, List[str]]:
    score = 0
    reasons: List[str] = []
    if not script_path or not os.path.exists(script_path):
        return 0, []
    txt = _read_small_text(script_path, SCRIPT_SCAN_MAX_BYTES)
    if not txt:
        return 0, []
    low = txt.lower()

    for rx, label in SUSPICIOUS_SCRIPT_PATTERNS:
        if rx.search(txt):
            reasons.append(f"script: {label}")
            # weighting
            if "pipeline" in label or "reverse shell" in label:
                score += 3
            elif "persistence" in label:
                score += 2
            elif "miner" in label:
                score += 2
            else:
                score += 1

    # extra: many urls + suspicious keywords
    if low.count("http://") + low.count("https://") >= 3 and any(k in low for k in ("base64", "eval", "exec", "subprocess", "mkfifo", "/dev/tcp")):
        reasons.append("script: combinaisons URLs + exécution/obfuscation")
        score += 2

    # de-dup
    seen = set()
    out = []
    for r in reasons:
        if r not in seen:
            seen.add(r)
            out.append(r)
    return score, out


def _format_connections(proc: psutil.Process, limit: int = DETAIL_MAX_CONNECTIONS) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    try:
        try:
            conns = proc.net_connections(kind="inet")
        except Exception:
            conns = proc.connections(kind="inet")  # older psutil
        for c in conns[:limit]:
            laddr = ""
            raddr = ""
            r_ip = ""
            r_port = None
            if c.laddr:
                laddr = f"{c.laddr.ip}:{c.laddr.port}"
            if c.raddr:
                r_ip = c.raddr.ip
                r_port = c.raddr.port
                raddr = f"{r_ip}:{r_port}"
            out.append({
                "laddr": laddr,
                "raddr": raddr,
                "rip": r_ip,
                "rport": r_port,
                "status": getattr(c, "status", ""),
            })
    except Exception:
        return []
    return out


def _network_risk(conns: List[Dict[str, Any]]) -> Tuple[int, List[str], Dict[str, Any]]:
    score = 0
    reasons: List[str] = []
    if not conns:
        return 0, [], {"remote_public": 0, "remote_private": 0, "unique_remote_ips": 0, "suspicious_ports": 0, "established": 0}

    remote_public = 0
    remote_private = 0
    suspicious_ports = 0
    established = 0
    ips = set()

    for c in conns:
        rip = c.get("rip") or ""
        rport = c.get("rport")
        st = (c.get("status") or "").upper()
        if st == "ESTABLISHED":
            established += 1
        if rip:
            ips.add(rip)
            priv = _is_private_ip(rip)
            if priv is True:
                remote_private += 1
            elif priv is False:
                remote_public += 1
        if isinstance(rport, int) and rport in SUSPICIOUS_PORTS:
            suspicious_ports += 1

    # scoring rules (conservative)
    if remote_public >= 1 and established >= 1:
        reasons.append("réseau: connexions établies vers IP publique")
        score += 1
    if remote_public >= 3:
        reasons.append("réseau: plusieurs connexions vers IP publiques")
        score += 1
    if suspicious_ports >= 1:
        reasons.append("réseau: port distant atypique (heuristique)")
        score += 1
    if len(conns) >= 25:
        reasons.append("réseau: volume de connexions élevé")
        score += 1

    meta = {
        "remote_public": remote_public,
        "remote_private": remote_private,
        "unique_remote_ips": len(ips),
        "suspicious_ports": suspicious_ports,
        "established": established,
        "count": len(conns),
    }
    return score, reasons, meta


def _parent_chain(pid: int, depth: int = 3) -> List[Dict[str, Any]]:
    chain: List[Dict[str, Any]] = []
    try:
        proc = psutil.Process(pid)
    except Exception:
        return chain
    cur = proc
    for _ in range(depth):
        try:
            parent = cur.parent()
            if not parent:
                break
            chain.append({
                "pid": parent.pid,
                "name": parent.name() if parent else "",
                "exe": get_exe_path(parent) or "",
                "cmd": " ".join(get_cmdline(parent)) if parent else "",
            })
            cur = parent
        except Exception:
            break
    return chain


def _parent_correlation(cmdline: List[str], chain: List[Dict[str, Any]]) -> Tuple[int, List[str]]:
    """Correlate parent->child patterns (download/execute, lolbins chain)."""
    score = 0
    reasons: List[str] = []
    if not cmdline or not chain:
        return 0, []
    child = " ".join(cmdline).lower()
    p0 = chain[0].get("cmd", "").lower() if chain else ""

    if ("curl" in p0 or "wget" in p0) and any(x in child for x in ("bash", " sh", "python", "python3", "perl", "ruby", "node", "php")):
        reasons.append("parent: curl/wget suivi d’un interpréteur (download & execute)")
        score += 2

    if ("bash -c" in child or "sh -c" in child or "python -c" in child or "python3 -c" in child) and ("ssh" not in child):
        # common fileless pattern
        reasons.append("chaîne: exécution inline via -c (fileless possible)")
        score += 1

    # LOLBins chain: parent and child are both common lolbins and contain obfuscation keywords
    if any(b in p0.split()[:1] for b in LOLBINS) and any(b in child.split()[:1] for b in LOLBINS):
        if any(k in child for k in ("base64", "openssl", "/dev/tcp", "mkfifo", "socat", "nc ")):
            reasons.append("chaîne: LOLBins + obfuscation/réseau")
            score += 1

    return score, reasons


def _lolbins_score(cmd: str) -> Tuple[int, List[str]]:
    score = 0
    reasons: List[str] = []
    low = (cmd or "").lower()
    toks = low.split()
    if not toks:
        return 0, []
    base = _basename(toks[0])
    if base not in LOLBINS:
        return 0, []

    # combinations
    if base in {"curl", "wget"} and ("| sh" in low or "|bash" in low or "| bash" in low):
        reasons.append("lolbin: download & execute")
        score += 2
    if base in {"python", "python3", "node", "php", "perl", "ruby"} and any(x in low for x in ("-c", "-e", "-r")):
        reasons.append("lolbin: exécution inline (fileless)")
        score += 1
    if base in {"openssl", "base64"}:
        reasons.append("lolbin: obfuscation/encoding")
        score += 1
    if base in {"ssh"} and any(x in low for x in ("-R", "-L", "-D")):
        reasons.append("lolbin: tunnel ssh (à vérifier)")
        score += 1
    return score, reasons


def is_system_process(uid: Optional[int], exe: Optional[str], name: str) -> bool:
    if uid == 0:
        return True
    if exe:
        if exe.startswith(SYSTEM_PATH_PREFIXES):
            return True
        if "/systemd/" in exe:
            return True
    if name.startswith("[") and name.endswith("]"):
        return True
    return False


def is_command_process(name: str, cmdline: List[str], terminal: Optional[str]) -> bool:
    if name in COMMON_COMMANDS:
        return True
    if terminal and cmdline:
        if _basename(cmdline[0]) in COMMON_COMMANDS:
            return True
    return False


def suspicion_score(
    pid: int,
    uid: Optional[int],
    user: str,
    name: str,
    exe: Optional[str],
    cmdline: List[str],
    cwd: str = "",
    include_network: bool = False,
) -> Tuple[int, List[str], Dict[str, Any]]:
    """
    Returns: (score, reasons, meta)
    meta includes: sha256, dpkg_owner, baseline, allowlisted, network_meta, parent_chain
    """
    reasons: List[str] = []
    score = 0

    cmd = " ".join(cmdline) if cmdline else ""
    joined = cmd.lower()

    # --- hashes / package ownership / baseline
    sha = _sha256_file(exe) if exe else None
    dpkg_owner = _dpkg_owner(exe) if exe else None
    baseline_exec = _baseline_upsert_exec(sha or "", exe or "", dpkg_owner) if sha else {"known": False}
    baseline_cmd = _baseline_upsert_cmd(cmd) if cmd else {"known": False}

    # baseline anomalies (conservative)
    if exe and sha and not baseline_exec.get("known", False):
        reasons.append("baseline: exécutable jamais vu (nouveau hash)")
        score += 1
    if cmd and not baseline_cmd.get("known", False) and any(t in joined for t in ("-c", "|", "base64", "openssl", "/dev/tcp", "mkfifo", "socat", "crontab", "systemctl")):
        reasons.append("baseline: commande jamais vue + indicateurs")
        score += 1

    if exe and (exe.startswith("/usr/bin/") or exe.startswith("/bin/") or exe.startswith("/sbin/") or exe.startswith("/usr/sbin/")) and dpkg_owner is None:
        reasons.append("intégrité: binaire système sans propriétaire dpkg (à vérifier)")
        score += 2

    # --- masquerading / names
    if _looks_like_masquerade(name, exe):
        reasons.append("masquerading: nom type système mais exécutable non standard")
        score += 2
    if _looks_randomish(name):
        reasons.append("nom atypique (potentiellement généré)")
        score += 1

    # --- strong binary signals
    if exe and exe.startswith(TEMP_PATH_PREFIXES):
        reasons.append("binaire lancé depuis un répertoire temporaire (/tmp, /var/tmp, /dev/shm)")
        score += 3
    if exe and exe.endswith(" (deleted)"):
        reasons.append("binaire supprimé mais toujours en exécution (deleted)")
        score += 3
    if uid == 0 and exe and (exe.startswith("/home/") or exe.startswith(TEMP_PATH_PREFIXES) or exe.startswith(RUNTIME_WRITABLE_PREFIXES)):
        reasons.append("root: binaire lancé depuis un répertoire utilisateur/writable")
        score += 3
    if exe:
        ww = _is_world_writable(exe)
        if ww is True:
            reasons.append("permissions: exécutable world-writable")
            score += 2

    # --- commandline patterns
    if ("curl" in joined and ("| sh" in joined or "|bash" in joined or "| bash" in joined)):
        reasons.append("pattern: curl | sh/bash (download & execute)")
        score += 3
    if ("wget" in joined and ("| sh" in joined or "|bash" in joined or "| bash" in joined)):
        reasons.append("pattern: wget | sh/bash (download & execute)")
        score += 3

    if "base64" in joined or "-base64" in joined or "openssl" in joined:
        reasons.append("pattern: base64/openssl (obfuscation/encoding)")
        score += 1
    if re.search(r"[A-Za-z0-9+/]{120,}={0,2}", joined):
        reasons.append("pattern: longue séquence base64-like")
        score += 1
    if joined.count("\\x") >= 6 or joined.count("\\u") >= 6:
        reasons.append("pattern: obfuscation \\x/\\u")
        score += 1

    if "/dev/tcp/" in joined or "mkfifo" in joined or "socat" in joined:
        reasons.append("pattern: reverse shell (/dev/tcp, mkfifo, socat)")
        score += 2
    if "nc " in joined or " netcat" in joined or "ncat" in joined:
        if " -e " in joined or " -c " in joined:
            reasons.append("pattern: netcat avec exécution (-e/-c)")
            score += 2
        else:
            score += 1
    if "bash -i" in joined or "sh -i" in joined:
        reasons.append("pattern: shell interactif (-i)")
        score += 1

    if "crontab" in joined or "@reboot" in joined:
        reasons.append("pattern: persistance via cron")
        score += 2
    if "systemctl" in joined and ("enable" in joined or "daemon-reload" in joined):
        reasons.append("pattern: persistance via systemd")
        score += 2
    if any(x in joined for x in ("/etc/rc.local", "/etc/profile", ".bashrc", ".profile", ".zshrc")):
        reasons.append("pattern: fichiers de profil shell (persistance possible)")
        score += 1

    if any(k in joined for k in ("xmrig", "minerd", "cryptonight", "stratum+tcp", "monero")):
        reasons.append("pattern: miner (xmrig/minerd/stratum)")
        score += 2

    if "nohup" in joined or "setsid" in joined:
        reasons.append("pattern: détachement (nohup/setsid)")
        score += 1

    # --- LOLBins
    s_lol, r_lol = _lolbins_score(cmd)
    if s_lol:
        score += s_lol
        reasons.extend(r_lol)

    # --- script specific: inline / temp scripts / content scanning
    base0 = _basename(cmdline[0]) if cmdline else ""
    script_path = _find_script_path(cmdline, cwd)
    if base0 in SCRIPT_INTERPRETERS:
        flags = INLINE_FLAGS.get(base0, set())
        if any(a in flags for a in cmdline[1:4]):
            reasons.append(f"script: exécution inline via {base0} ({', '.join(sorted(flags))})")
            score += 1
            if any(tok in joined for tok in ("eval", "exec", "subprocess", "popen", "os.system", "pty.spawn")):
                reasons.append("script: exécution dynamique (eval/exec/subprocess)")
                score += 2

        if script_path and script_path.startswith(TEMP_PATH_PREFIXES + RUNTIME_WRITABLE_PREFIXES):
            reasons.append("script: lancé depuis un dossier temporaire/writable")
            score += 2

        if script_path and any(x in script_path for x in ("/.cache/", "/.local/", "/.config/")):
            bn = _basename(script_path)
            if bn.startswith(".") or len(bn) >= 12:
                reasons.append("script: placé dans un dossier caché (.cache/.local/.config)")
                score += 1

        if "<<" in joined:
            reasons.append("script: heredoc (<<) utilisé pour du fileless possible")
            score += 1

        # content scan
        if script_path and os.path.exists(script_path):
            s2, r2 = _score_script_content(script_path)
            if s2:
                score += min(4, s2)  # cap content boost
                reasons.extend(r2)

    # --- environment suspicious
    if score >= 1 or base0 in SCRIPT_INTERPRETERS:
        env = _read_proc_environ(pid)
        if env:
            for key in ("LD_PRELOAD", "LD_LIBRARY_PATH", "BASH_ENV", "PYTHONPATH", "NODE_OPTIONS"):
                if key not in env:
                    continue
                val = env.get(key, "")
                low = val.lower()
                if val.startswith(TEMP_PATH_PREFIXES + RUNTIME_WRITABLE_PREFIXES) or any(p in low for p in ("/tmp/", "/dev/shm/", "/var/tmp/", "/run/user/")):
                    reasons.append(f"env: {key} pointe vers un chemin temporaire/writable")
                    score += 2

    # --- parent chain + correlation (cheap depth=3)
    chain = _parent_chain(pid, depth=3)
    pscore, preasons = _parent_correlation(cmdline, chain)
    if pscore:
        score += pscore
        reasons.extend(preasons)

    # --- network (optional, avoid heavy calls in list view)
    network_meta: Dict[str, Any] = {}
    if include_network:
        try:
            proc = psutil.Process(pid)
            conns = _format_connections(proc, limit=DETAIL_MAX_CONNECTIONS)
        except Exception:
            conns = []
        nscore, nreasons, nmeta = _network_risk(conns)
        if nscore:
            score += nscore
            reasons.extend(nreasons)
        network_meta = nmeta

    # allowlist handling (do not hide score; just mark and optionally downgrade)
    allow, allow_reason = _is_allowlisted(name=name, user=user, exe=exe or "", cmd=cmd, sha256=sha or "")
    if allow:
        reasons.append(allow_reason)
        # reduce impact, but keep score visible
        score = max(0, score - 3)

    # de-dup reasons
    seen = set()
    out: List[str] = []
    for r in reasons:
        if r not in seen:
            seen.add(r)
            out.append(r)

    meta = {
        "sha256": sha or "",
        "dpkg_owner": dpkg_owner or "",
        "baseline_exec": baseline_exec,
        "baseline_cmd": baseline_cmd,
        "allowlisted": allow,
        "allowlist_reason": allow_reason,
        "script_path": script_path or "",
        "parent_chain": chain,
        "network_meta": network_meta,
    }
    return int(score), out, meta


def classify_process(proc: psutil.Process) -> Tuple[str, List[str], int, Dict[str, Any]]:
    try:
        name = proc.name()
    except Exception:
        name = str(proc.pid)

    uid: Optional[int] = None
    user = "unknown"
    try:
        uid = proc.uids().real
        user = safe_username(uid)
    except Exception:
        try:
            user = proc.username()
        except Exception:
            user = "unknown"

    exe = get_exe_path(proc)
    cmdline = get_cmdline(proc)

    try:
        terminal = proc.terminal()
    except Exception:
        terminal = None

    try:
        cwd = proc.cwd()
    except Exception:
        cwd = ""

    score, reasons, meta = suspicion_score(
        pid=proc.pid,
        uid=uid,
        user=user,
        name=name,
        exe=exe,
        cmdline=cmdline,
        cwd=cwd,
        include_network=False,
    )

    # "reasons" are shown fully only if suspicious; otherwise we keep meta
    if score >= RED_THRESHOLD:
        return "suspicious", reasons, score, meta

    if is_system_process(uid, exe, name):
        return "system", [], score, meta

    if is_command_process(name, cmdline, terminal):
        return "commands", [], score, meta

    return "apps", [], score, meta


def proc_to_dict(proc: psutil.Process) -> Dict[str, Any]:
    pid = proc.pid

    try:
        name = proc.name()
    except Exception:
        name = str(pid)

    try:
        status = proc.status()
    except Exception:
        status = "unknown"

    try:
        create_time = proc.create_time()
    except Exception:
        create_time = None

    uid: Optional[int] = None
    username = "unknown"
    try:
        uid = proc.uids().real
        username = safe_username(uid)
    except Exception:
        try:
            username = proc.username()
        except Exception:
            username = "unknown"

    exe = get_exe_path(proc)
    cmdline = get_cmdline(proc)

    try:
        terminal = proc.terminal()
    except Exception:
        terminal = None

    try:
        cpu = proc.cpu_percent(interval=None)
    except Exception:
        cpu = 0.0

    try:
        mem = proc.memory_percent()
    except Exception:
        mem = 0.0

    category, reasons, risk_score, meta = classify_process(proc)
    level = risk_level(risk_score)

    cmd = " ".join(cmdline) if cmdline else ""
    sha = meta.get("sha256", "")
    allowlisted = bool(meta.get("allowlisted", False))

    return {
        "pid": pid,
        "name": name,
        "user": username,
        "status": status,
        "cpu": round(cpu, 1),
        "mem": round(mem, 1),
        "risk_score": int(risk_score),
        "risk_level": level,
        "exe": exe or "",
        "cmd": cmd,
        "terminal": terminal or "",
        "category": category,
        "reasons": reasons,
        "started": int(create_time) if create_time else None,
        "sha256": sha,
        "dpkg_owner": meta.get("dpkg_owner", ""),
        "baseline": {
            "exec": meta.get("baseline_exec", {}),
            "cmd": meta.get("baseline_cmd", {}),
        },
        "allowlisted": allowlisted,
    }


def prime_cpu() -> None:
    for p in psutil.process_iter(attrs=[]):
        try:
            p.cpu_percent(interval=None)
        except Exception:
            pass


prime_cpu()

# =============================================================================
# Admin guard
# =============================================================================

def _require_admin(req: Any) -> Tuple[bool, str]:
    if not ADMIN_TOKEN:
        return False, "admin_token_not_configured"
    token = (req.headers.get("X-Admin-Token") or req.args.get("token") or "").strip()
    if token != ADMIN_TOKEN:
        return False, "invalid_admin_token"
    return True, ""


# =============================================================================
# YARA integration (optional dependency)
# =============================================================================

def _yara_available() -> bool:
    try:
        import yara  # type: ignore
        return True
    except Exception:
        return False


def _yara_compile_rules() -> Any:
    # compile once
    if "compiled" in _RULES_CACHE:
        return _RULES_CACHE["compiled"]
    if not _yara_available():
        _RULES_CACHE["compiled"] = None
        return None
    import yara  # type: ignore

    rules_dir = os.path.join(BASE_DIR, "rules", "yara")
    if not os.path.isdir(rules_dir):
        _RULES_CACHE["compiled"] = None
        return None

    filepaths = {}
    for fn in os.listdir(rules_dir):
        if fn.endswith((".yar", ".yara")):
            filepaths[fn] = os.path.join(rules_dir, fn)
    if not filepaths:
        _RULES_CACHE["compiled"] = None
        return None

    try:
        compiled = yara.compile(filepaths=filepaths)
        _RULES_CACHE["compiled"] = compiled
        return compiled
    except Exception:
        _RULES_CACHE["compiled"] = None
        return None


def _yara_scan_path(path: str, max_bytes: int = 5 * 1024 * 1024) -> Dict[str, Any]:
    compiled = _yara_compile_rules()
    if compiled is None:
        return {"available": False, "matches": [], "error": "yara_not_available_or_rules_failed"}
    if not path or not os.path.exists(path):
        return {"available": True, "matches": [], "error": "path_not_found"}
    try:
        # Avoid scanning huge files by default (optional)
        try:
            st = os.stat(path)
            if st.st_size > max_bytes:
                return {"available": True, "matches": [], "error": "file_too_large"}
        except Exception:
            pass
        matches = compiled.match(path)
        out = []
        for m in matches:
            out.append({
                "rule": getattr(m, "rule", ""),
                "tags": list(getattr(m, "tags", []) or []),
                "meta": dict(getattr(m, "meta", {}) or {}),
            })
        return {"available": True, "matches": out, "error": ""}
    except Exception as e:
        return {"available": True, "matches": [], "error": str(e)}


# =============================================================================
# Auditd parsing (best-effort)
# =============================================================================

def _tail_file(path: str, max_bytes: int = 2 * 1024 * 1024) -> str:
    try:
        with open(path, "rb") as f:
            f.seek(0, os.SEEK_END)
            size = f.tell()
            start = max(0, size - max_bytes)
            f.seek(start)
            raw = f.read()
        return raw.decode("utf-8", errors="ignore")
    except Exception:
        return ""


_AUDIT_LINE_RE = re.compile(r"msg=audit\((?P<ts>\d+\.\d+):(?P<id>\d+)\)")
_PID_RE = re.compile(r"\bpid=(\d+)\b")
_UID_RE = re.compile(r"\buid=(\d+)\b")
_EXE_RE = re.compile(r'\bexe="([^"]+)"')
_COMM_RE = re.compile(r'\bcomm="([^"]+)"')
_A_RE = re.compile(r'\ba(\d+)=(".*?"|\S+)')


def _parse_audit_recent(minutes: int = 15, max_events: int = AUDIT_MAX_EVENTS) -> Dict[str, Any]:
    path = "/var/log/audit/audit.log"
    if not os.path.exists(path):
        return {"available": False, "events": [], "error": "audit_log_not_found"}

    cutoff = time.time() - (minutes * 60)
    text = _tail_file(path)
    if not text:
        return {"available": True, "events": [], "error": "empty_or_unreadable"}

    groups: Dict[str, Dict[str, Any]] = {}
    for line in text.splitlines():
        if "type=" not in line or "msg=audit(" not in line:
            continue
        m = _AUDIT_LINE_RE.search(line)
        if not m:
            continue
        ts = float(m.group("ts"))
        if ts < cutoff:
            continue
        rid = m.group("id")
        g = groups.setdefault(rid, {"id": rid, "ts": ts, "types": set(), "pid": None, "uid": None, "exe": "", "comm": "", "args": []})
        g["ts"] = ts
        # type
        tpos = line.find("type=")
        t = line[tpos + 5:].split()[0] if tpos >= 0 else ""
        g["types"].add(t)

        # pid/uid/exe/comm (often in SYSCALL)
        mp = _PID_RE.search(line)
        if mp and g["pid"] is None:
            g["pid"] = int(mp.group(1))
        mu = _UID_RE.search(line)
        if mu and g["uid"] is None:
            g["uid"] = int(mu.group(1))
        me = _EXE_RE.search(line)
        if me and not g["exe"]:
            g["exe"] = me.group(1)
        mc = _COMM_RE.search(line)
        if mc and not g["comm"]:
            g["comm"] = mc.group(1)

        # args (EXECVE)
        if t == "EXECVE":
            args = []
            for ma in _A_RE.finditer(line):
                idx = int(ma.group(1))
                val = ma.group(2)
                if val.startswith('"') and val.endswith('"'):
                    val = val[1:-1]
                args.append((idx, val))
            if args:
                args.sort(key=lambda x: x[0])
                g["args"] = [a[1] for a in args]

    events = []
    for rid, g in groups.items():
        types = sorted(list(g["types"]))
        events.append({
            "id": rid,
            "ts": int(g["ts"]),
            "types": types,
            "pid": g["pid"],
            "uid": g["uid"],
            "user": safe_username(g["uid"]) if g["uid"] is not None else "unknown",
            "exe": g["exe"],
            "comm": g["comm"],
            "cmd": " ".join(g["args"]) if g["args"] else "",
        })

    events.sort(key=lambda e: e["ts"], reverse=True)
    events = events[: max_events]
    return {"available": True, "events": events, "error": ""}


# =============================================================================
# eBPF ingestion (optional)
# =============================================================================

def _read_ebpf_events(max_events: int = EBPF_MAX_EVENTS) -> Dict[str, Any]:
    if not os.path.exists(EBPF_LOG_PATH):
        return {"available": False, "events": [], "error": "ebpf_log_not_found", "path": EBPF_LOG_PATH}
    try:
        text = _tail_file(EBPF_LOG_PATH, max_bytes=2 * 1024 * 1024)
        out = []
        for line in text.splitlines()[-max_events:]:
            line = line.strip()
            if not line:
                continue
            try:
                out.append(json.loads(line))
            except Exception:
                continue
        return {"available": True, "events": out, "error": "", "path": EBPF_LOG_PATH}
    except Exception as e:
        return {"available": True, "events": [], "error": str(e), "path": EBPF_LOG_PATH}


# =============================================================================
# Diff / snapshots
# =============================================================================

def _build_snapshot(limit: int = 2000, category: str = "all", search: str = "") -> Dict[int, Dict[str, Any]]:
    snap: Dict[int, Dict[str, Any]] = {}
    search = (search or "").strip().lower()
    for p in psutil.process_iter(attrs=[]):
        try:
            d = proc_to_dict(p)
        except (psutil.NoSuchProcess, psutil.ZombieProcess):
            continue
        except Exception:
            continue
        if category != "all" and d.get("category") != category:
            continue
        if search:
            hay = f'{d.get("pid")} {d.get("name")} {d.get("user")} {d.get("exe")} {d.get("cmd")}'.lower()
            if search not in hay:
                continue
        snap[int(d["pid"])] = d
        if len(snap) >= limit:
            break
    return snap


def _diff_snapshots(old: Dict[int, Dict[str, Any]], new: Dict[int, Dict[str, Any]]) -> Dict[str, Any]:
    old_pids = set(old.keys())
    new_pids = set(new.keys())

    started = sorted(list(new_pids - old_pids))
    stopped = sorted(list(old_pids - new_pids))

    changed: List[Dict[str, Any]] = []
    for pid in (old_pids & new_pids):
        o = old[pid]
        n = new[pid]
        if int(o.get("risk_score", 0)) != int(n.get("risk_score", 0)) or o.get("category") != n.get("category"):
            changed.append({
                "pid": pid,
                "name": n.get("name", ""),
                "old_score": int(o.get("risk_score", 0)),
                "new_score": int(n.get("risk_score", 0)),
                "old_cat": o.get("category", ""),
                "new_cat": n.get("category", ""),
            })

    new_suspicious = [pid for pid in started if new.get(pid, {}).get("category") == "suspicious"]
    return {
        "started": started[:300],
        "stopped": stopped[:300],
        "changed": changed[:300],
        "new_suspicious": new_suspicious[:300],
    }


# =============================================================================
# Routes
# =============================================================================

@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/config")
def api_config():
    return jsonify({
        "ts": _now(),
        "red_threshold": RED_THRESHOLD,
        "admin_actions_enabled": bool(ADMIN_TOKEN),
        "yara_available": _yara_available(),
        "audit_log_exists": os.path.exists("/var/log/audit/audit.log"),
        "ebpf_log_path": EBPF_LOG_PATH,
    })


@app.route("/api/processes")
def api_processes():
    global _LAST_SNAPSHOT, _LAST_SNAPSHOT_TS

    limit = int(request.args.get("limit", "300"))
    sort = request.args.get("sort", "cpu")  # cpu|mem|pid|name|risk
    category = request.args.get("category", "all")  # all|system|apps|commands|suspicious
    search = request.args.get("search", "").strip().lower()

    procs: List[Dict[str, Any]] = []
    for p in psutil.process_iter(attrs=[]):
        try:
            d = proc_to_dict(p)
        except (psutil.NoSuchProcess, psutil.ZombieProcess):
            continue
        except Exception:
            continue

        if category != "all" and d["category"] != category:
            continue

        if search:
            hay = f'{d["pid"]} {d["name"]} {d["user"]} {d["exe"]} {d["cmd"]}'.lower()
            if search not in hay:
                continue

        procs.append(d)

    key_map = {
        "cpu": lambda x: x.get("cpu", 0.0),
        "mem": lambda x: x.get("mem", 0.0),
        "pid": lambda x: x.get("pid", 0),
        "name": lambda x: x.get("name", ""),
        "risk": lambda x: x.get("risk_score", 0),
    }
    key_fn = key_map.get(sort, key_map["cpu"])
    reverse = True if sort in {"cpu", "mem", "risk"} else False
    procs.sort(key=key_fn, reverse=reverse)

    # build + store snapshot for diff (using filtered, limited set)
    snapshot = {int(d["pid"]): d for d in procs[: max(1, min(limit, 2000))]}
    diff = _diff_snapshots(_LAST_SNAPSHOT, snapshot) if _LAST_SNAPSHOT else {"started": [], "stopped": [], "changed": [], "new_suspicious": []}
    _LAST_SNAPSHOT = snapshot
    _LAST_SNAPSHOT_TS = _now()

    return jsonify({
        "ts": _LAST_SNAPSHOT_TS,
        "count": len(procs),
        "items": list(snapshot.values()),
        "diff": diff,
        "note": (
            "La catégorie rouge est basée sur un score heuristique. "
            "Un score élevé signifie 'à investiguer', pas une preuve."
        )
    })


@app.route("/api/diff")
def api_diff():
    # recompute vs last snapshot (if any)
    global _LAST_SNAPSHOT
    current = _build_snapshot(limit=2000)
    diff = _diff_snapshots(_LAST_SNAPSHOT, current) if _LAST_SNAPSHOT else _diff_snapshots({}, current)
    _LAST_SNAPSHOT = current
    return jsonify({"ts": _now(), "diff": diff, "count": len(current)})


@app.route("/api/stream")
def api_stream():
    """SSE stream: pushes diffs periodically."""
    try:
        interval_ms = int(request.args.get("interval", "1500"))
        interval_ms = max(500, min(5000, interval_ms))
    except Exception:
        interval_ms = 1500

    def gen():
        global _LAST_SNAPSHOT
        while True:
            cur = _build_snapshot(limit=1200)
            diff = _diff_snapshots(_LAST_SNAPSHOT, cur) if _LAST_SNAPSHOT else _diff_snapshots({}, cur)
            _LAST_SNAPSHOT = cur
            payload = json.dumps({"ts": _now(), "diff": diff, "count": len(cur)}, ensure_ascii=False)
            yield f"data: {payload}\n\n"
            time.sleep(interval_ms / 1000.0)

    return Response(gen(), mimetype="text/event-stream", headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})


@app.route("/api/process/<int:pid>")
def api_process(pid: int):
    """Enriched PID details: parent chain, network, hash, dpkg owner, baseline, open files, allowlist, YARA on demand."""
    try:
        proc = psutil.Process(pid)
    except Exception:
        return jsonify({"error": "process_not_found", "pid": pid}), 404

    try:
        d = proc_to_dict(proc)
    except Exception:
        d = {"pid": pid}

    errors: List[str] = []

    # CWD
    try:
        cwd = proc.cwd()
    except Exception:
        cwd = ""
        errors.append("cwd_access_denied")

    # Full scoring incl network for details
    try:
        name = proc.name()
    except Exception:
        name = str(pid)
    uid: Optional[int] = None
    username = "unknown"
    try:
        uid = proc.uids().real
        username = safe_username(uid)
    except Exception:
        try:
            username = proc.username()
        except Exception:
            username = "unknown"
    exe = get_exe_path(proc)
    cmdline = get_cmdline(proc)

    score, signals, meta = suspicion_score(
        pid=pid,
        uid=uid,
        user=username,
        name=name,
        exe=exe,
        cmdline=cmdline,
        cwd=cwd,
        include_network=True,
    )

    d["risk_score"] = int(score)
    d["risk_level"] = risk_level(int(score))
    d["signals"] = signals
    d["category"] = "suspicious" if score >= RED_THRESHOLD else d.get("category", "apps")
    d["cwd"] = cwd
    d["ppid"] = proc.ppid() if hasattr(proc, "ppid") else None

    d["sha256"] = meta.get("sha256", "")
    d["dpkg_owner"] = meta.get("dpkg_owner", "")
    d["baseline"] = {
        "exec": meta.get("baseline_exec", {}),
        "cmd": meta.get("baseline_cmd", {}),
    }
    d["allowlisted"] = bool(meta.get("allowlisted", False))
    d["allowlist_reason"] = meta.get("allowlist_reason", "")
    d["script_path"] = meta.get("script_path", "")
    d["parent_chain"] = meta.get("parent_chain", [])
    d["network_meta"] = meta.get("network_meta", {})

    # Connections
    conns = _format_connections(proc)
    d["connections"] = conns

    # Open files
    try:
        files = proc.open_files()
        d["open_files"] = [f.path for f in files[:DETAIL_MAX_OPEN_FILES]]
    except Exception:
        d["open_files"] = []

    # YARA scan summary (only when requested)
    if request.args.get("yara", "0") == "1":
        target = exe or d.get("script_path", "")
        d["yara"] = _yara_scan_path(target)

    d["errors"] = errors
    return jsonify(d)


# ---------------- Allowlist endpoints (admin) ----------------

@app.route("/api/allowlist")
def api_allowlist_get():
    return jsonify({"ts": _now(), "allowlist": _load_allowlist()})


@app.route("/api/allowlist/add", methods=["POST"])
def api_allowlist_add():
    ok, err = _require_admin(request)
    if not ok:
        return jsonify({"error": err}), 403

    data = request.get_json(silent=True) or {}
    al = _load_allowlist()

    for key in ("sha256", "paths", "cmd_regex", "names", "users"):
        vals = data.get(key)
        if not vals:
            continue
        if isinstance(vals, str):
            vals = [vals]
        if isinstance(vals, list):
            for v in vals:
                if isinstance(v, str) and v and v not in al[key]:
                    al[key].append(v)

    _save_allowlist(al)
    return jsonify({"ts": _now(), "allowlist": al})


@app.route("/api/allowlist/remove", methods=["POST"])
def api_allowlist_remove():
    ok, err = _require_admin(request)
    if not ok:
        return jsonify({"error": err}), 403

    data = request.get_json(silent=True) or {}
    al = _load_allowlist()
    key = data.get("key")
    value = data.get("value")
    if key in al and value in al[key]:
        al[key].remove(value)
        _save_allowlist(al)
    return jsonify({"ts": _now(), "allowlist": al})


# ---------------- Actions (admin) ----------------

@app.route("/api/action/kill", methods=["POST"])
def api_action_kill():
    ok, err = _require_admin(request)
    if not ok:
        return jsonify({"error": err}), 403
    data = request.get_json(silent=True) or {}
    pid = int(data.get("pid", 0))
    sig = int(data.get("sig", 15))
    try:
        p = psutil.Process(pid)
        p.send_signal(sig)
        return jsonify({"ts": _now(), "ok": True})
    except Exception as e:
        return jsonify({"ts": _now(), "ok": False, "error": str(e)}), 400


@app.route("/api/action/suspend", methods=["POST"])
def api_action_suspend():
    ok, err = _require_admin(request)
    if not ok:
        return jsonify({"error": err}), 403
    pid = int((request.get_json(silent=True) or {}).get("pid", 0))
    try:
        psutil.Process(pid).suspend()
        return jsonify({"ts": _now(), "ok": True})
    except Exception as e:
        return jsonify({"ts": _now(), "ok": False, "error": str(e)}), 400


@app.route("/api/action/resume", methods=["POST"])
def api_action_resume():
    ok, err = _require_admin(request)
    if not ok:
        return jsonify({"error": err}), 403
    pid = int((request.get_json(silent=True) or {}).get("pid", 0))
    try:
        psutil.Process(pid).resume()
        return jsonify({"ts": _now(), "ok": True})
    except Exception as e:
        return jsonify({"ts": _now(), "ok": False, "error": str(e)}), 400


@app.route("/api/action/renice", methods=["POST"])
def api_action_renice():
    ok, err = _require_admin(request)
    if not ok:
        return jsonify({"error": err}), 403
    data = request.get_json(silent=True) or {}
    pid = int(data.get("pid", 0))
    nice = int(data.get("nice", 10))
    nice = max(-20, min(19, nice))
    try:
        psutil.Process(pid).nice(nice)
        return jsonify({"ts": _now(), "ok": True, "nice": nice})
    except Exception as e:
        return jsonify({"ts": _now(), "ok": False, "error": str(e)}), 400


# ---------------- Export ----------------

@app.route("/api/export")
def api_export():
    fmt = request.args.get("format", "json").lower()
    category = request.args.get("category", "all")
    search = request.args.get("search", "")
    limit = int(request.args.get("limit", "2000"))
    snap = _build_snapshot(limit=limit, category=category, search=search)
    items = list(snap.values())

    if fmt == "csv":
        out = io.StringIO()
        w = csv.writer(out)
        w.writerow(["pid", "name", "user", "cpu", "mem", "risk_score", "category", "status", "exe", "cmd", "sha256", "dpkg_owner", "allowlisted"])
        for d in items:
            w.writerow([
                d.get("pid"),
                d.get("name"),
                d.get("user"),
                d.get("cpu"),
                d.get("mem"),
                d.get("risk_score"),
                d.get("category"),
                d.get("status"),
                d.get("exe"),
                d.get("cmd"),
                d.get("sha256"),
                d.get("dpkg_owner"),
                d.get("allowlisted"),
            ])
        bio = io.BytesIO(out.getvalue().encode("utf-8"))
        bio.seek(0)
        return send_file(bio, mimetype="text/csv", as_attachment=True, download_name=f"procwatch_export_{_now()}.csv")

    # default json
    bio = io.BytesIO(json.dumps({"ts": _now(), "items": items}, ensure_ascii=False, indent=2).encode("utf-8"))
    bio.seek(0)
    return send_file(bio, mimetype="application/json", as_attachment=True, download_name=f"procwatch_export_{_now()}.json")


# ---------------- Audit / eBPF / YARA helpers ----------------

@app.route("/api/audit/recent")
def api_audit_recent():
    minutes = int(request.args.get("minutes", "15"))
    minutes = max(1, min(240, minutes))
    return jsonify(_parse_audit_recent(minutes=minutes))


@app.route("/api/ebpf/events")
def api_ebpf_events():
    return jsonify(_read_ebpf_events())


@app.route("/api/yara/scan")
def api_yara_scan():
    pid = request.args.get("pid")
    path = request.args.get("path", "")
    target = ""
    if pid:
        try:
            p = psutil.Process(int(pid))
            target = get_exe_path(p) or ""
        except Exception:
            target = ""
    if path:
        target = path
    return jsonify({"ts": _now(), "target": target, "result": _yara_scan_path(target)})


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", "5000")), debug=True)
