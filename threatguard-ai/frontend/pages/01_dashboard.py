from __future__ import annotations

import requests
import streamlit as st

from app_common import api_request, backend_status, current_user


user = current_user()
if user is None:
    st.warning("Your session has expired. Return to the sign-in page.")
    st.stop()

st.title("Security workspace")
st.caption("Tenant-scoped information only. ThreatGuard does not run remediation commands.")

connected, description = backend_status()
(st.success if connected else st.warning)(description)

scan_count = document_count = session_count = "—"
try:
    scans = api_request("GET", "/scanner/scans", params={"org_id": user["org_id"], "tenant_id": user["tenant_id"], "page": 1, "page_size": 1})
    documents = api_request("GET", "/knowledge/documents", params={"page": 1, "page_size": 1})
    sessions = api_request("GET", "/chat/sessions", params={"page": 1, "page_size": 1})
    if scans.ok:
        scan_count = scans.json().get("total", 0)
    if documents.ok:
        document_count = documents.json().get("total", 0)
    if sessions.ok:
        session_count = sessions.json().get("total", 0)
except requests.RequestException:
    st.warning("Some workspace counters could not be loaded.")

one, two, three = st.columns(3)
one.metric("Stored security scans", scan_count)
two.metric("Knowledge documents", document_count)
three.metric("Your chat sessions", session_count)

st.subheader("Getting started")
st.write("Review stored scanner records, upload tenant-approved references to the Knowledge Base, then ask the AI Chatbot for evidence-grounded explanations when a provider is configured.")
