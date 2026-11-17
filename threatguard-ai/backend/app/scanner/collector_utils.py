from __future__ import annotations

import json
import os
import subprocess
from datetime import datetime, timezone
from typing import Any, Callable

IS_WINDOWS = os.name == "nt"

def scan_timestamp() -> str:
    return datetime.now(timezone.utc).isoformat()


def parse_json_items(raw: str) -> list[dict[str, Any]]:
    if not raw.strip():
        raise ValueError("Collector returned no JSON output.")
    value = json.loads(raw)
    if value is None:
        return []
    if isinstance(value, dict):
        return [value]
    if isinstance(value, list):
        return [item for item in value if isinstance(item, dict)]
    raise ValueError("Collector returned an unexpected JSON shape.")


def run_powershell_collector(
    collector_name: str,
    command: str,
    parser: Callable[[list[dict[str, Any]]], list[dict[str, Any]]],
    detector: Callable[[list[dict[str, Any]]], list[dict[str, Any]]] | None = None,
) -> dict[str, Any]:
    timestamp = scan_timestamp()
    if not IS_WINDOWS:
        return {
            "collector_name": collector_name, "status": "unsupported", "items_collected": 0,
            "error_code": "UNSUPPORTED_PLATFORM", "error_message": "This collector requires Windows.",
            "scanned_at": timestamp, "items": [], "findings": [],
        }
    try:
        result = subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-Command", command],
            capture_output=True, text=True, check=False, timeout=30,
        )
    except FileNotFoundError as exc:
        return {
            "collector_name": collector_name, "status": "unsupported", "items_collected": 0,
            "error_code": "POWERSHELL_NOT_FOUND", "error_message": "PowerShell is not installed or is not available on PATH.",
            "scanned_at": timestamp, "items": [], "findings": [],
        }
    except subprocess.TimeoutExpired:
        return {
            "collector_name": collector_name, "status": "failed", "items_collected": 0,
            "error_code": "COLLECTOR_TIMEOUT", "error_message": "PowerShell collection timed out.",
            "scanned_at": timestamp, "items": [], "findings": [],
        }
    except OSError as exc:
        return {
            "collector_name": collector_name, "status": "failed", "items_collected": 0,
            "error_code": "PROCESS_LAUNCH_ERROR", "error_message": "PowerShell could not be started.",
            "scanned_at": timestamp, "items": [], "findings": [],
        }

    if result.returncode != 0:
        raw_error = (result.stderr or result.stdout or "").strip()
        restricted = any(token in raw_error.lower() for token in ("access denied", "permissiondenied", "0x80041003", "unauthorized"))
        message = (f"Access to {collector_name} data was denied." if restricted
                   else f"PowerShell collector exited with code {result.returncode}.")
        return {
            "collector_name": collector_name,
            "status": "permission_restricted" if restricted else "failed",
            "items_collected": 0,
            "error_code": "ACCESS_DENIED" if restricted else f"POWERSHELL_EXIT_{result.returncode}",
            "error_message": message, "scanned_at": timestamp, "items": [], "findings": [],
        }
    try:
        findings = parser(parse_json_items(result.stdout))
    except (ValueError, json.JSONDecodeError) as exc:
        return {
            "collector_name": collector_name, "status": "failed", "items_collected": 0,
            "error_code": "INVALID_COLLECTOR_OUTPUT", "error_message": str(exc)[:1000],
            "scanned_at": timestamp, "items": [], "findings": [],
        }
    detected = detector(findings) if detector is not None else []
    return {
        "collector_name": collector_name, "status": "success", "items_collected": len(findings),
        "error_code": None, "error_message": None, "scanned_at": timestamp,
        "items": findings, "findings": detected,
    }
