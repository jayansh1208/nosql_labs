from __future__ import annotations

from typing import Any

from backend.app.scanner.collector_utils import run_powershell_collector


def detect_suspicious_startup(items: list[dict[str, Any]]) -> list[dict[str, Any]]:
    findings = []
    seen = set()

    for item in items:
        name = str(item.get("name") or "unknown")
        path = str(item.get("path") or "")
        path_lower = path.lower()

        # 1. Script files in startup
        if any(path_lower.endswith(ext) or ext in path_lower for ext in (".vbs", ".js", ".bat", ".cmd", ".ps1")):
            key = ("script_startup", name)
            if key not in seen:
                seen.add(key)
                findings.append({
                    "severity": "medium",
                    "category": "startup",
                    "title": f"Script-based startup item: {name}",
                    "description": f"Startup entry '{name}' executes a script file: '{path}'.",
                })

        # 2. Startup executing from temp or downloads
        if "\\temp\\" in path_lower or "\\downloads\\" in path_lower:
            key = ("temp_startup", name)
            if key not in seen:
                seen.add(key)
                findings.append({
                    "severity": "high",
                    "category": "startup",
                    "title": f"Startup item in temporary path: {name}",
                    "description": f"Startup entry '{name}' executes from a temporary or downloads folder: '{path}'.",
                })

        # 3. Obfuscated parameters in startup
        if "-enc" in path_lower or "-encodedcommand" in path_lower or "-w hidden" in path_lower:
            key = ("encoded_startup", name)
            if key not in seen:
                seen.add(key)
                findings.append({
                    "severity": "high",
                    "category": "startup",
                    "title": f"Obfuscated startup command: {name}",
                    "description": f"Startup entry '{name}' uses encoded or hidden parameters: '{path}'.",
                })

    return findings


def parse_startup_list(items: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [{
        "name": item.get("name") or item.get("Name") or "unknown",
        "path": item.get("path") or item.get("Path") or item.get("Command") or "",
        "severity": item.get("severity") or "low", "category": "startup",
        "title": item.get("title") or f"Startup item: {item.get('Name') or item.get('name') or 'unknown'}",
        "description": item.get("description") or "Startup entry is present on the host.",
    } for item in items]


def scan_startup_items(limit: int | None = None) -> dict[str, Any]:
    command = "ConvertTo-Json -InputObject @(Get-CimInstance Win32_StartupCommand | Select-Object Name, Command, Location) -Depth 4 -Compress"
    result = run_powershell_collector("startup", command, parse_startup_list, detector=detect_suspicious_startup)
    if limit is not None:
        if "items" in result:
            result["items"] = result["items"][:max(0, limit)]
            result["items_collected"] = len(result["items"])
        if "findings" in result:
            result["findings"] = result["findings"][:max(0, limit)]
    return result
