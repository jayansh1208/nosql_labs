from __future__ import annotations

import argparse
import json
import sys

from backend.app.scanner.scanner_service import collect_scan_report, export_scan_report


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Run a native Windows host scan and export the JSON report.")
    parser.add_argument("--host", default="windows-host", help="Host name or identifier to report in the scan.")
    parser.add_argument("--scanner-name", default="native-windows-scanner", help="Name of the scanner implementation.")
    parser.add_argument("--source", default="native_windows_cli", help="Source label for the scan report.")
    parser.add_argument("--limit", type=int, default=20, help="Maximum total findings across process, network, and startup collectors (default: 20).")
    parser.add_argument("--output", default=None, help="Optional output JSON file path.")
    parser.add_argument("--api-url", default=None, help="Optional backend API URL to submit the report (e.g. http://localhost:8000).")
    parser.add_argument("--token", default=None, help="JWT bearer token for authenticated API submission.")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.limit < 0:
        parser.error("--limit must be zero or greater")
    report = collect_scan_report(host=args.host, scanner_name=args.scanner_name, source=args.source, limit=args.limit)
    if args.output:
        export_scan_report(report, args.output)
        print(f"Scan report exported to: {args.output}")

    if args.api_url and args.token:
        import urllib.error
        import urllib.request

        url = f"{args.api_url.rstrip('/')}/scanner/scans"
        headers = {
            "Authorization": f"Bearer {args.token.strip()}",
            "Content-Type": "application/json",
        }
        body = json.dumps(report, default=str).encode("utf-8")
        req = urllib.request.Request(url, data=body, headers=headers, method="POST")
        try:
            with urllib.request.urlopen(req, timeout=30) as resp:
                resp_data = json.loads(resp.read().decode("utf-8"))
                print(f"Scan report successfully submitted to {url}. Scan ID: {resp_data.get('scan_id')}")
        except urllib.error.HTTPError as exc:
            err_body = exc.read().decode("utf-8")
            print(f"API submission failed ({exc.code}): {err_body}", file=sys.stderr)
            return 1
        except Exception as exc:
            print(f"API submission error: {exc}", file=sys.stderr)
            return 1
    elif not args.output:
        print(json.dumps(report, indent=2, default=str))
    return 0


if __name__ == "__main__":
    sys.exit(main())
