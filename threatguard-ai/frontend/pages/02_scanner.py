from __future__ import annotations

import requests
import streamlit as st

from app_common import api_request, current_user, show_api_error


user = current_user()
if user is None:
    st.warning("Your session has expired. Return to the sign-in page.")
    st.stop()

st.title("Windows Security Scanner")
st.caption("Read-only host observations stored for your tenant. This interface never executes remediation commands.")

try:
    response = api_request(
        "GET",
        "/scanner/scans",
        params={"org_id": user["org_id"], "tenant_id": user["tenant_id"], "page": 1, "page_size": 100},
    )
except requests.RequestException:
    st.error("The backend is unavailable. Scanner records could not be loaded.")
    st.stop()

if not response.ok:
    show_api_error(response, "Scanner records could not be loaded.")
    st.stop()

records = response.json().get("items", [])
if not records:
    st.info("No scanner records are stored for this tenant yet. Run the read-only host scanner from the approved Windows host workflow, then submit its report through the authenticated API.")
    st.stop()

labels = {
    item["scan_id"]: f"{item.get('created_at', 'Unknown time')} · {item.get('scan_type', 'scan')} · {item['scan_id']}"
    for item in records
}
scan_id = st.selectbox("Stored scan", list(labels), format_func=labels.get)

try:
    detail = api_request(
        "GET",
        f"/scanner/scans/{scan_id}",
        params={"org_id": user["org_id"], "tenant_id": user["tenant_id"]},
    )
except requests.RequestException:
    st.error("The backend is unavailable. The selected scanner record could not be loaded.")
    st.stop()

if not detail.ok:
    show_api_error(detail, "The selected scanner record could not be loaded.")
    st.stop()

scan = detail.json()
summary = scan.get("summary") or {}
left, middle, right = st.columns(3)
left.metric("Severity", str(summary.get("severity", "unknown")).upper())
middle.metric("Findings", summary.get("total_findings", "unknown"))
right.metric("Coverage", str((scan.get("details") or {}).get("completeness", {}).get("status", "unknown")).upper())

st.subheader("Stored summary")
st.write(summary.get("summary") or scan.get("summary") or "No summary was stored.")

details = scan.get("details") or {}
if details.get("observation_mode") == "simulated":
    st.warning("This record is marked simulated. It is not evidence of a live host finding.")

st.subheader("Stored findings")
findings = details.get("findings") or []
if not findings:
    st.info("This scan reported no stored findings.")
for finding in findings:
    severity = str(finding.get("severity", "unknown")).upper()
    st.markdown(f"**{severity} · {finding.get('title', 'Stored finding')}**")
    st.caption(finding.get("category", "unknown"))
    st.write(finding.get("description", "No description was stored."))
