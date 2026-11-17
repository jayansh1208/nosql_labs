from __future__ import annotations

import streamlit as st

from app_common import backend_status, current_user


user = current_user()
if user is None:
    st.warning("Your session has expired. Return to the sign-in page.")
    st.stop()

st.title("Account")
st.caption("Current authenticated identity and service status.")
st.write(f"**Name:** {user.get('display_name') or 'Not set'}")
st.write(f"**Email:** {user.get('email')}")
st.write(f"**Role:** {user.get('role')}")
st.write(f"**Organization:** {user.get('org_id')}")
st.write(f"**Tenant:** {user.get('tenant_id')}")

connected, description = backend_status()
st.subheader("Connection")
(st.success if connected else st.warning)(description)
st.info("Use the Sign out button in the sidebar when you finish. Signing out revokes the current application token.")
