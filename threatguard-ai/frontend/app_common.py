"""Shared, token-based frontend helpers for the ThreatGuard Streamlit application."""

from __future__ import annotations

import os
from typing import Any

import requests
import streamlit as st


BACKEND_URL = os.getenv("BACKEND_URL", "http://localhost:8000").rstrip("/")
READ_ROLES = {"super_admin", "tenant_admin", "security_analyst", "security_operator", "auditor"}
WRITE_ROLES = {"super_admin", "tenant_admin", "security_analyst", "security_operator"}


def can_read(user: dict[str, Any]) -> bool:
    return user.get("role") in READ_ROLES


def can_write(user: dict[str, Any]) -> bool:
    return user.get("role") in WRITE_ROLES


def auth_headers() -> dict[str, str]:
    token = st.session_state.get("access_token", "")
    return {"Authorization": f"Bearer {token}"} if token else {}


def api_request(method: str, path: str, **kwargs: Any) -> requests.Response:
    headers = dict(kwargs.pop("headers", {}))
    headers.update(auth_headers())
    return requests.request(method, f"{BACKEND_URL}{path}", headers=headers, timeout=kwargs.pop("timeout", 30), **kwargs)


def response_message(response: requests.Response, fallback: str = "The request could not be completed.") -> str:
    try:
        detail = response.json().get("detail", fallback)
    except (ValueError, AttributeError):
        return fallback
    if isinstance(detail, dict):
        detail = detail.get("message") or detail.get("code") or fallback
    return str(detail)[:500]


def show_api_error(response: requests.Response, fallback: str = "The request could not be completed.") -> None:
    if response.status_code == 401:
        clear_session()
        st.error("Your session has expired. Please sign in again.")
        return
    st.error(f"Request failed ({response.status_code}): {response_message(response, fallback)}")


def clear_session() -> None:
    for key in ("access_token", "current_user", "chat_active_id", "chat_draft", "chat_clear_draft"):
        st.session_state.pop(key, None)


def current_user() -> dict[str, Any] | None:
    if not st.session_state.get("access_token"):
        return None
    try:
        response = api_request("GET", "/auth/me", timeout=10)
    except requests.RequestException:
        return None
    if response.status_code == 401:
        clear_session()
        return None
    if not response.ok:
        return None
    user = response.json()
    st.session_state["current_user"] = user
    return user


def render_login() -> None:
    st.title("ThreatGuard AI")
    st.caption("Sign in to the authenticated security workspace.")
    try:
        health = requests.get(f"{BACKEND_URL}/health", timeout=5)
        if health.ok:
            st.success("Backend connection is available.")
        else:
            st.warning("The backend returned an unexpected status. Try again shortly.")
    except requests.RequestException:
        st.error("The backend is unavailable. Verify the application services and try again.")

    with st.form("login_form", clear_on_submit=False):
        email = st.text_input("Email", autocomplete="username")
        password = st.text_input("Password", type="password", autocomplete="current-password")
        submitted = st.form_submit_button("Sign in", type="primary")
    if not submitted:
        return
    if not email.strip() or not password:
        st.warning("Enter both your email address and password.")
        return
    try:
        response = requests.post(
            f"{BACKEND_URL}/auth/login",
            json={"email": email.strip(), "password": password},
            timeout=15,
        )
    except requests.RequestException:
        st.error("The backend is unavailable. Your credentials were not sent again.")
        return
    if not response.ok:
        show_api_error(response, "Unable to sign in with those credentials.")
        return
    payload = response.json()
    token = payload.get("access_token")
    user = payload.get("user")
    if not isinstance(token, str) or not token or not isinstance(user, dict):
        st.error("The backend returned an invalid login response.")
        return
    st.session_state["access_token"] = token
    st.session_state["current_user"] = user
    st.rerun()


def logout() -> None:
    try:
        api_request("POST", "/auth/logout", timeout=10)
    except requests.RequestException:
        # Local session state is still cleared, even if the backend is unavailable.
        pass
    clear_session()
    st.rerun()


def backend_status() -> tuple[bool, str]:
    try:
        response = requests.get(f"{BACKEND_URL}/health", timeout=5)
        if not response.ok:
            return False, "Backend returned an unexpected status."
        payload = response.json()
        mongo = payload.get("mongo", "unknown")
        return mongo == "connected", f"Backend: {payload.get('status', 'unknown')} · MongoDB: {mongo}"
    except requests.RequestException:
        return False, "Backend unavailable."
