import streamlit as st

from app_common import backend_status, can_read, can_write, current_user, logout, render_login


st.set_page_config(page_title="ThreatGuard AI", page_icon="🛡️", layout="wide", initial_sidebar_state="expanded")

user = current_user()
if user is None:
    render_login()
    st.stop()

pages = [st.Page("pages/01_dashboard.py", title="Dashboard", icon="🏠", default=True)]
if can_read(user):
    pages.extend([
        st.Page("pages/02_scanner.py", title="Windows Security Scanner", icon="🔎"),
        st.Page("pages/03_knowledge_base.py", title="Knowledge Base", icon="📚"),
    ])
if can_write(user):
    pages.append(st.Page("pages/04_chatbot.py", title="AI Chatbot", icon="💬"))
pages.append(st.Page("pages/05_account.py", title="Account", icon="👤"))

with st.sidebar:
    st.title("ThreatGuard AI")
    st.caption(f"{user.get('display_name') or user.get('email')} · {user.get('role', 'unknown')}")
    connected, description = backend_status()
    (st.success if connected else st.warning)(description)
    if st.button("Sign out", use_container_width=True):
        logout()

navigation = st.navigation(pages, position="sidebar")
navigation.run()
