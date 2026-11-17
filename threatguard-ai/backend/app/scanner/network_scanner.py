from __future__ import annotations

import subprocess
from typing import Any

from backend.app.scanner.collector_utils import IS_WINDOWS, parse_json_items, run_powershell_collector

SENSITIVE_PORTS = {
    21: ("FTP", "high"),
    23: ("Telnet", "high"),
    445: ("SMB", "medium"),
    3389: ("RDP", "low"),
}


def detect_suspicious_network(items: list[dict[str, Any]]) -> list[dict[str, Any]]:
    findings = []
    seen = set()

    for item in items:
        loc = str(item.get("local_address") or "")
        state = str(item.get("state") or "").lower()
        if state in {"listen", "listening"}:
            port = None
            if ":" in loc:
                try:
                    port = int(loc.split(":")[-1])
                except (ValueError, IndexError):
                    pass
            if port in SENSITIVE_PORTS and (loc.startswith("0.0.0.0") or loc.startswith("::") or loc.startswith("*")):
                svc, sev = SENSITIVE_PORTS[port]
                key = ("listener", port)
                if key not in seen:
                    seen.add(key)
                    findings.append({
                        "severity": sev,
                        "category": "network",
                        "title": f"Sensitive service listening on all interfaces (Port {port}/{svc})",
                        "description": f"Service '{svc}' is bound to all network interfaces on port {port} in listening state.",
                    })

    # Read-only check for Windows Firewall status
    if IS_WINDOWS:
        try:
            fw_cmd = "ConvertTo-Json -InputObject @(Get-NetFirewallProfile | Select-Object Name, Enabled) -Depth 3 -Compress"
            proc = subprocess.run(
                ["powershell", "-NoProfile", "-NonInteractive", "-Command", fw_cmd],
                capture_output=True, text=True, check=False, timeout=10,
            )
            if proc.returncode == 0 and proc.stdout.strip():
                profiles = parse_json_items(proc.stdout)
                for profile in profiles:
                    p_name = str(profile.get("Name") or "Unknown")
                    enabled = profile.get("Enabled")
                    # Enabled can be 1, True, 0, False
                    is_enabled = enabled in {1, True, "True", "true"}
                    if not is_enabled:
                        key = ("firewall_disabled", p_name)
                        if key not in seen:
                            seen.add(key)
                            findings.append({
                                "severity": "high",
                                "category": "network",
                                "title": f"Windows Firewall profile '{p_name}' is disabled",
                                "description": f"Windows Defender Firewall profile '{p_name}' is currently disabled.",
                            })
        except Exception:
            pass

    return findings


def parse_network_list(items: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [{
        "local_address": item.get("local_address") or item.get("LocalAddress") or "unknown",
        "remote_address": item.get("remote_address") or item.get("RemoteAddress") or "unknown",
        "state": item.get("state") or item.get("State") or "unknown",
        "severity": item.get("severity") or "medium", "category": "network",
        "title": item.get("title") or f"Network connection: {item.get('LocalAddress') or item.get('local_address') or 'unknown'}",
        "description": item.get("description") or "Network activity observed during host inspection.",
    } for item in items]


def scan_network_connections(limit: int | None = None) -> dict[str, Any]:
    command = "ConvertTo-Json -InputObject @(Get-NetTCPConnection | Select-Object LocalAddress, RemoteAddress, State) -Depth 4 -Compress"
    result = run_powershell_collector("network", command, parse_network_list, detector=detect_suspicious_network)
    if limit is not None:
        if "items" in result:
            result["items"] = result["items"][:max(0, limit)]
            result["items_collected"] = len(result["items"])
        if "findings" in result:
            result["findings"] = result["findings"][:max(0, limit)]
    return result
