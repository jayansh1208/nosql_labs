from __future__ import annotations

import re
import subprocess
from typing import Any

from backend.app.scanner.collector_utils import IS_WINDOWS, parse_json_items, run_powershell_collector

KNOWN_SUSPICIOUS_TOOLS = {
    "mimikatz.exe", "mimikatz", "procdump.exe", "procdump",
    "nc.exe", "ncat.exe", "netcat.exe", "psexec.exe",
    "chisel.exe", "lazagne.exe", "rubeus.exe", "bloodhound.exe",
}

ENCODED_PS_PATTERN = re.compile(r"-(?:e|enc|encodedcommand)\s+[A-Za-z0-9+/=]{10,}", re.IGNORECASE)
DOWNLOAD_CRADLE_PATTERN = re.compile(r"(?:downloadstring|downloadfile|invoke-webrequest).*?(?:iex|invoke-expression)", re.IGNORECASE)


def detect_suspicious_processes(items: list[dict[str, Any]]) -> list[dict[str, Any]]:
    findings = []
    seen_keys = set()

    for item in items:
        pid = item.get("pid")
        name = str(item.get("name") or "").lower()
        cmd = str(item.get("command_line") or "")
        cmd_lower = cmd.lower()

        # 1. Known hacktools
        if name in KNOWN_SUSPICIOUS_TOOLS:
            key = ("tool", name, pid)
            if key not in seen_keys:
                seen_keys.add(key)
                findings.append({
                    "severity": "high",
                    "category": "process",
                    "title": f"Unauthorized security tool observed: {name}",
                    "description": f"Process '{name}' (PID {pid}) is known to be used for credential dumping or remote access.",
                })

        # 2. Encoded or download cradle PowerShell commands
        if "powershell" in name or "pwsh" in name or "powershell" in cmd_lower:
            if ENCODED_PS_PATTERN.search(cmd):
                key = ("encoded_ps", pid)
                if key not in seen_keys:
                    seen_keys.add(key)
                    findings.append({
                        "severity": "high",
                        "category": "process",
                        "title": f"Encoded PowerShell command line (PID {pid})",
                        "description": f"PowerShell was executed with an encoded/obfuscated command parameter.",
                    })
            if DOWNLOAD_CRADLE_PATTERN.search(cmd_lower):
                key = ("download_cradle", pid)
                if key not in seen_keys:
                    seen_keys.add(key)
                    findings.append({
                        "severity": "high",
                        "category": "process",
                        "title": f"In-memory download cradle execution (PID {pid})",
                        "description": f"PowerShell command line indicates dynamic script download and execution.",
                    })

        # 3. LOLBAS tool abuse
        if "certutil" in name and ("-urlcache" in cmd_lower or "-split" in cmd_lower):
            key = ("certutil", pid)
            if key not in seen_keys:
                seen_keys.add(key)
                findings.append({
                    "severity": "high",
                    "category": "process",
                    "title": f"Suspicious certutil file retrieval (PID {pid})",
                    "description": f"certutil was invoked with download flags (-urlcache / -split).",
                })
        if "vssadmin" in name and "delete" in cmd_lower and "shadows" in cmd_lower:
            key = ("vssadmin", pid)
            if key not in seen_keys:
                seen_keys.add(key)
                findings.append({
                    "severity": "critical",
                    "category": "process",
                    "title": f"Shadow copies deletion attempt (PID {pid})",
                    "description": f"vssadmin was invoked to delete volume shadow copies, a common ransomware tactic.",
                })

        # 4. Process executing from temporary directory
        if ("\\appdata\\local\\temp\\" in cmd_lower or "\\windows\\temp\\" in cmd_lower) and name not in {"installer.exe"}:
            if name.endswith((".exe", ".scr", ".bat", ".cmd", ".vbs", ".ps1")):
                key = ("temp_exec", name, pid)
                if key not in seen_keys:
                    seen_keys.add(key)
                    findings.append({
                        "severity": "medium",
                        "category": "process",
                        "title": f"Process executing from temporary directory: {name}",
                        "description": f"Binary '{name}' (PID {pid}) is running from a temporary storage path.",
                    })

    # 5. Read-only service inspection (unquoted service paths & user-directory services)
    if IS_WINDOWS:
        try:
            svc_cmd = "ConvertTo-Json -InputObject @(Get-CimInstance Win32_Service | Select-Object Name, DisplayName, PathName, State | Where-Object { $_.PathName -ne $null }) -Depth 3 -Compress"
            proc = subprocess.run(
                ["powershell", "-NoProfile", "-NonInteractive", "-Command", svc_cmd],
                capture_output=True, text=True, check=False, timeout=15,
            )
            if proc.returncode == 0 and proc.stdout.strip():
                services = parse_json_items(proc.stdout)
                for svc in services:
                    s_name = str(svc.get("Name") or "")
                    s_display = str(svc.get("DisplayName") or s_name)
                    path = str(svc.get("PathName") or "").strip()
                    path_lower = path.lower()
                    # Check unquoted path with spaces before .exe
                    if ".exe" in path_lower and not path.startswith('"'):
                        exe_idx = path_lower.find(".exe")
                        prefix = path[:exe_idx]
                        if " " in prefix and "\\windows\\" not in prefix.lower():
                            key = ("unquoted_service", s_name)
                            if key not in seen_keys:
                                seen_keys.add(key)
                                findings.append({
                                    "severity": "medium",
                                    "category": "process",
                                    "title": f"Unquoted service path: {s_name}",
                                    "description": f"Service '{s_display}' has an unquoted binary path with spaces: '{path}'.",
                                })
                    # Check service running from user directory
                    if "\\users\\" in path_lower or "\\temp\\" in path_lower:
                        key = ("user_service", s_name)
                        if key not in seen_keys:
                            seen_keys.add(key)
                            findings.append({
                                "severity": "high",
                                "category": "process",
                                "title": f"Service installed in user profile: {s_name}",
                                "description": f"Service '{s_display}' points to a user-writable path: '{path}'.",
                            })
        except Exception:
            pass

    return findings


def parse_process_list(items: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [{
        "pid": item.get("pid") or item.get("ProcessId"),
        "name": item.get("name") or item.get("Name") or item.get("ProcessName") or "unknown",
        "command_line": item.get("command_line") or item.get("CommandLine") or "",
        "severity": item.get("severity") or "low", "category": "process",
        "title": item.get("title") or f"Process {item.get('Name') or item.get('name') or 'unknown'} observed",
        "description": item.get("description") or "Host-level process activity observed during scan.",
    } for item in items]


def scan_processes(limit: int | None = None) -> dict[str, Any]:
    command = "ConvertTo-Json -InputObject @(Get-CimInstance Win32_Process | Select-Object ProcessId, Name, CommandLine | Sort-Object ProcessId) -Depth 3 -Compress"
    result = run_powershell_collector("processes", command, parse_process_list, detector=detect_suspicious_processes)
    if limit is not None:
        result["items"] = result["items"][:max(0, limit)]
        result["items_collected"] = len(result["items"])
    return result
