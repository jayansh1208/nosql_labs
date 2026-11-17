from __future__ import annotations

import requests
import streamlit as st

from app_common import api_request, can_write, current_user, show_api_error


user = current_user()
if user is None:
    st.warning("Your session has expired. Return to the sign-in page.")
    st.stop()
if not can_write(user):
    st.error("Your role does not have permission to create AI conversations.")
    st.stop()

st.title("AI Threat Intelligence Chatbot")
st.caption("Evidence-grounded explanations only. ThreatGuard does not execute generated commands or make host changes.")

try:
    session_response = api_request("GET", "/chat/sessions", params={"page": 1, "page_size": 100})
    provider_response = api_request("GET", "/chat/providers")
except requests.RequestException:
    st.error("The backend is unavailable. Conversations cannot be loaded.")
    st.stop()

if not session_response.ok:
    show_api_error(session_response, "Conversations could not be loaded.")
    st.stop()
sessions = session_response.json().get("items", [])
provider_info = provider_response.json() if provider_response.ok else None
if not provider_response.ok:
    show_api_error(provider_response, "Provider configuration could not be loaded.")

session_by_id = {item["session_id"]: item for item in sessions}
with st.sidebar:
    st.subheader("Conversations")
    if st.button("New conversation", use_container_width=True):
        try:
            response = api_request("POST", "/chat/sessions", json={"title": "New chat"})
        except requests.RequestException:
            st.error("The backend is unavailable. The conversation was not created.")
        else:
            if response.status_code == 201:
                st.session_state["chat_active_id"] = response.json()["session_id"]
                st.rerun()
            show_api_error(response, "The conversation could not be created.")

    choices = list(session_by_id)
    active_id = st.session_state.get("chat_active_id")
    if active_id not in choices:
        active_id = choices[0] if choices else None
        st.session_state["chat_active_id"] = active_id
    if choices:
        selected = st.selectbox(
            "Conversation history", choices,
            index=choices.index(active_id) if active_id in choices else 0,
            format_func=lambda item_id: session_by_id[item_id].get("title") or "Conversation",
            key="chat_session_selector",
        )
        st.session_state["chat_active_id"] = selected

    st.divider()
    st.subheader("AI provider")
    if provider_info:
        st.write(f"**Selected by server configuration:** {provider_info.get('provider', 'unknown')}")
        st.caption(f"Model: {provider_info.get('model') or 'not set'}")
        if not provider_info.get("configured"):
            st.warning("This provider is not configured. Set the server environment variables and rebuild the backend.")
        elif st.button("Test provider connection", use_container_width=True):
            try:
                tested = api_request("POST", "/chat/providers/test", timeout=90)
            except requests.RequestException:
                st.error("The backend is unavailable. Provider test could not run.")
            else:
                if tested.ok:
                    st.success(f"Connected to {tested.json()['provider']} using {tested.json()['model']}.")
                else:
                    show_api_error(tested, "The selected provider is unavailable. Configure OpenAI or start Ollama separately.")

    with st.expander("Manage selected conversation"):
        if active_id and active_id in session_by_id:
            title = st.text_input("Conversation title", value=session_by_id[active_id].get("title", "Conversation"), key="chat_rename_title")
            if st.button("Save title"):
                updated = api_request("PATCH", f"/chat/sessions/{active_id}", json={"title": title})
                if updated.ok:
                    st.success("Conversation renamed.")
                    st.rerun()
                show_api_error(updated, "The title could not be saved.")
            if st.button("Delete conversation", type="secondary"):
                deleted = api_request("DELETE", f"/chat/sessions/{active_id}")
                if deleted.ok:
                    st.session_state.pop("chat_active_id", None)
                    st.success("Conversation deleted.")
                    st.rerun()
                show_api_error(deleted, "The conversation could not be deleted.")
        else:
            st.caption("Create a conversation first.")

active_id = st.session_state.get("chat_active_id")
if not active_id:
    st.info("Create a conversation from the sidebar to start. Answers cite only retrieved tenant-visible sources.")
else:
    try:
        history = api_request("GET", f"/chat/sessions/{active_id}", params={"message_offset": 0, "message_limit": 100})
    except requests.RequestException:
        st.error("The backend is unavailable. Conversation history could not be loaded.")
        st.stop()
    if not history.ok:
        show_api_error(history, "Conversation history could not be loaded.")
        st.stop()
    for message in history.json().get("messages", []):
        with st.chat_message("assistant" if message.get("role") == "assistant" else "user"):
            st.markdown(message.get("content", ""))
            if message.get("provider"):
                st.caption(f"{message['provider']} · {message.get('model', '')}")
            for citation in message.get("citations", []):
                page = f" · page {citation['page_number']}" if citation.get("page_number") else ""
                with st.expander(f"{citation.get('citation_id', 'Source')} · {citation.get('title', 'Document')}{page}"):
                    st.caption(citation.get("source", ""))
                    st.write(citation.get("excerpt", ""))
            for scan in message.get("scanner_sources", []):
                with st.expander(f"Stored scanner evidence · {scan.get('scan_id', 'scan')}"):
                    st.caption(f"Host: {scan.get('host') or 'not recorded'} · {scan.get('generated_at') or 'time not recorded'}")
                    st.write(scan.get("summary", ""))
                    for finding in scan.get("findings", []):
                        st.markdown(f"**{str(finding.get('severity', 'unknown')).upper()} · {finding.get('title', 'Stored finding')}**")
                        st.caption(finding.get("description", ""))

use_rag = st.checkbox("Retrieve matching knowledge-base excerpts", value=True)
include_scanner = st.checkbox("Include latest stored scanner records", value=False)
question = st.chat_input("Ask for an explanation, evidence review, or defensive recommendation")
if question:
    if not active_id:
        try:
            created = api_request("POST", "/chat/sessions", json={"title": question[:60] or "New chat"})
        except requests.RequestException:
            st.error("The backend is unavailable. The conversation was not created.")
            st.stop()
        if not created.ok:
            show_api_error(created, "The conversation could not be created.")
            st.stop()
        active_id = created.json()["session_id"]
        st.session_state["chat_active_id"] = active_id
    with st.spinner("Retrieving tenant evidence and preparing an answer…"):
        try:
            response = api_request(
                "POST", f"/chat/sessions/{active_id}/messages",
                json={"content": question, "use_rag": use_rag, "include_scanner_context": include_scanner}, timeout=180,
            )
        except requests.RequestException:
            st.error("The backend is unavailable. The message was not sent.")
        else:
            if response.ok:
                st.rerun()
            show_api_error(response, "No answer was generated. Configure OpenAI or make Ollama available, then try again.")
