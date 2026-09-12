import os

import httpx
import streamlit as st

API = os.getenv("API_BASE_URL", "http://localhost:8000")
st.set_page_config(page_title="Sentinel", page_icon="🛡️", layout="wide")
st.title("🛡️ Sentinel")
st.caption("Defensive threat-intelligence and IOC triage")

ioc = st.text_input("IP address, domain, URL, file hash, or CVE", placeholder="CVE-2021-44228")
if st.button("Analyze", type="primary", disabled=not ioc.strip()):
    try:
        response = httpx.post(f"{API}/api/analyze", json={"ioc":ioc}, timeout=30)
        response.raise_for_status(); report=response.json()
        left,right=st.columns(2); left.metric("Threat score", "Unavailable" if report["risk_score"] is None else f"{report['risk_score']}/100"); right.metric("Verdict", "Insufficient data" if report["verdict"] == "UNKNOWN" else report["verdict"])
        st.write("Detected type:",report["ioc_type"]); st.subheader("Why this score?")
        for explanation in report["risk_explanations"]: st.write("•",explanation)
        st.subheader("Provider results")
        for result in report["provider_results"]:
            with st.expander(f"{result['provider']} — {result['status']}"):
                st.json(result)
    except httpx.HTTPStatusError as exc:
        st.error(exc.response.json().get("detail","Analysis failed"))
    except httpx.HTTPError:
        st.error("Could not reach the Sentinel API. Start FastAPI and try again.")

st.divider(); st.subheader("Recent investigations")
try:
    rows=httpx.get(f"{API}/api/investigations",timeout=5).json()
    st.dataframe(rows,use_container_width=True,hide_index=True)
except httpx.HTTPError:
    st.info("Investigation history will appear when the API is running.")

