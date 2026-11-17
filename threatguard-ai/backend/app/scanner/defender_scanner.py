from __future__ import annotations

import json
import os
import subprocess
from typing import Any

from backend.app.scanner.collector_utils import scan_timestamp

IS_WINDOWS = os.name == "nt"

def scan_defender_status() -> dict[str, Any]:
    timestamp = scan_timestamp()
    base = {"collector_name": "windows_defender", "items_collected": 0, "scanned_at": timestamp, "findings": []}
    if not IS_WINDOWS:
        return {**base, "status": "unsupported", "error_code": "UNSUPPORTED_PLATFORM",
                "error_message": "Windows Defender status requires Windows.",
                "available": None, "enabled": None, "defender_status": "unknown"}

    command = "Get-MpComputerStatus | Select-Object AMServiceEnabled, AntivirusEnabled, AntispywareEnabled, NISEnabled, AntivirusSignatureAge, ProductStatus | ConvertTo-Json -Compress"
    try:
        result = subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-Command", command],
            capture_output=True, text=True, check=False, timeout=30,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        error_code = "COLLECTOR_TIMEOUT" if isinstance(exc, subprocess.TimeoutExpired) else "PROCESS_LAUNCH_ERROR"
        return {**base, "status": "failed", "error_code": error_code,
                "error_message": "PowerShell could not complete the Defender status query.", "available": None, "enabled": None,
                "defender_status": "unknown"}

    if result.returncode != 0 or not result.stdout.strip():
        raw_error = (result.stderr or result.stdout or "").strip()
        restricted = any(token in raw_error.lower() for token in ("access denied", "permissiondenied", "0x80041003", "unauthorized"))
        message = ("Access denied while querying Windows Defender status." if restricted
                   else f"PowerShell Defender query exited with code {result.returncode}.")
        return {**base, "status": "permission_restricted" if restricted else "failed",
                "error_code": "ACCESS_DENIED" if restricted else f"POWERSHELL_EXIT_{result.returncode}",
                "error_message": message, "available": None, "enabled": None,
                "defender_status": "unknown"}
    try:
        values = json.loads(result.stdout)
    except json.JSONDecodeError as exc:
        return {**base, "status": "failed", "error_code": "INVALID_COLLECTOR_OUTPUT",
                "error_message": str(exc)[:1000], "available": None, "enabled": None,
                "defender_status": "unknown"}
    if not isinstance(values, dict) or not isinstance(values.get("AntivirusEnabled"), bool):
        return {**base, "status": "failed", "error_code": "INCOMPLETE_COLLECTOR_OUTPUT",
                "error_message": "Windows did not return a verifiable AntivirusEnabled value.",
                "available": None, "enabled": None, "defender_status": "unknown"}
    enabled = values["AntivirusEnabled"]
    defender_findings = []
    if not enabled:
        defender_findings.append({
            "severity": "high",
            "category": "defender",
            "title": "Windows Defender Antivirus is disabled",
            "description": "Windows Defender real-time antivirus protection is reported disabled on this host.",
        })
    if values.get("AMServiceEnabled") is False:
        defender_findings.append({
            "severity": "high",
            "category": "defender",
            "title": "Windows Antimalware Service is disabled",
            "description": "The core Antimalware service (WinDefend) is not running on this host.",
        })
    sig_age = values.get("AntivirusSignatureAge")
    if isinstance(sig_age, (int, float)) and sig_age > 7:
        defender_findings.append({
            "severity": "medium",
            "category": "defender",
            "title": f"Antivirus signatures outdated ({int(sig_age)} days)",
            "description": f"Antivirus signatures are {int(sig_age)} days old, exceeding the 7-day recommended maximum.",
        })
    return {**base, "status": "success", "items_collected": 1, "error_code": None, "error_message": None,
            "available": True, "enabled": enabled,
            "defender_status": "enabled" if enabled else "disabled",
            "findings": defender_findings,
            "details": {key: values.get(key) for key in (
                "AMServiceEnabled", "AntivirusEnabled", "AntispywareEnabled", "NISEnabled",
                "AntivirusSignatureAge", "ProductStatus")}}
