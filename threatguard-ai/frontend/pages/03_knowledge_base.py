from __future__ import annotations

import requests
import streamlit as st

from app_common import api_request, can_write, current_user, show_api_error


user = current_user()
if user is None:
    st.warning("Your session has expired. Return to the sign-in page.")
    st.stop()

st.title("Knowledge Base")
st.caption("Tenant-scoped PDF, TXT and Markdown references with real semantic retrieval. Search results are source excerpts, not generated answers.")

if can_write(user):
    st.subheader("Upload a reference")
    st.caption("Files are treated as untrusted data. Supported formats: PDF, TXT and Markdown. The backend enforces the upload-size limit.")
    uploaded_file = st.file_uploader("Choose a document", type=["pdf", "txt", "md", "markdown"])
    if uploaded_file is not None and st.button("Upload and process", type="primary"):
        try:
            response = api_request(
                "POST",
                "/knowledge/documents",
                files={"file": (uploaded_file.name, uploaded_file.getvalue(), uploaded_file.type or "application/octet-stream")},
                timeout=180,
            )
        except requests.RequestException:
            st.error("The backend is unavailable. The document was not uploaded.")
        else:
            if response.status_code == 201:
                document = response.json()
                st.success(f"Processed {document['original_filename']} into {document['chunk_count']} chunks using {document['embedding_model']}.")
            else:
                show_api_error(response, "The document could not be processed.")
else:
    st.info("Your role can search tenant references but cannot upload or delete them.")

st.subheader("Uploaded documents")
try:
    response = api_request("GET", "/knowledge/documents", params={"page": 1, "page_size": 100})
except requests.RequestException:
    st.error("The backend is unavailable. Documents could not be loaded.")
    st.stop()
if not response.ok:
    show_api_error(response, "Documents could not be loaded.")
    st.stop()

payload = response.json()
documents = payload.get("items", [])
st.caption(f"{payload.get('total', 0)} documents in this tenant")
if not documents:
    st.info("No documents have been uploaded for this tenant.")
for document in documents:
    with st.container(border=True):
        left, right = st.columns([5, 1])
        left.markdown(f"**{document['original_filename']}** · {document['file_type']}")
        left.caption(f"{document['chunk_count']} chunks · {document['embedding_model']} · uploaded {document['uploaded_at']}")
        owner = document.get("uploaded_by")
        if owner:
            left.caption("You uploaded this document." if owner == user["user_id"] else "Uploaded by another tenant user.")
        may_delete = can_write(user) and (owner == user["user_id"] or user.get("role") in {"tenant_admin", "super_admin"})
        if may_delete and right.button("Delete", key=f"delete-{document['document_id']}"):
            try:
                deleted = api_request("DELETE", f"/knowledge/documents/{document['document_id']}")
            except requests.RequestException:
                st.error("The backend is unavailable. The document was not deleted.")
            else:
                if deleted.ok:
                    st.success("Document deleted.")
                    st.rerun()
                show_api_error(deleted, "The document could not be deleted.")

st.subheader("Semantic search")
query = st.text_input("Ask about tenant references", max_chars=1000)
top_k = st.slider("Maximum excerpts", min_value=1, max_value=20, value=5)
if st.button("Search knowledge"):
    if not query.strip():
        st.warning("Enter a search query first.")
    else:
        try:
            search = api_request("POST", "/knowledge/search", json={"query": query, "top_k": top_k}, timeout=180)
        except requests.RequestException:
            st.error("The backend is unavailable. Search could not run.")
        else:
            if not search.ok:
                show_api_error(search, "Semantic retrieval is unavailable.")
            else:
                results = search.json().get("results", [])
                if not results:
                    st.info("No matching excerpts were found.")
                for result in results:
                    page = f" · page {result['page_number']}" if result.get("page_number") else ""
                    st.markdown(f"**{result['source']}{page} · relevance {result['relevance_score']:.3f}**")
                    st.write(result["excerpt"])
                    st.divider()
