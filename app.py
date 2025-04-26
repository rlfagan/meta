import os
import json
import subprocess
import pandas as pd
import altair as alt
import streamlit as st
import pydeck as pdk
from geopy.geocoders import Nominatim
from collections import Counter

# ── Configuration ─────────────────────────────────────────────────────────────
SCANOSS_API_KEY = os.getenv("SCANOSS_API_KEY", "txnUfW0xwF0KI1U1RW5sDSBL")
geolocator = Nominatim(user_agent="scanoss_app")

@st.cache_data(show_spinner=False)
def get_coords(country: str):
    """Cache geocoding results to speed up repeated runs."""
    try:
        loc = geolocator.geocode(country, timeout=5)
        if loc:
            return loc.latitude, loc.longitude
    except:
        return None
    return None

# Load Blue Oak ratings
try:
    with open("blueoak_ratings.json") as f:
        br = json.load(f)
    blueoak_map = {
        lic["id"]: rating["name"]
        for rating in br.get("ratings", [])
        for lic in rating.get("licenses", [])
        if lic.get("id")
    }
except FileNotFoundError:
    blueoak_map = {}

# Algorithm categories
LEGACY_ALGOS = ["md2","md4","md5","rc4","rc4-hmac","des","tdes","ripemd","skipjack"]
MODERN_ALGOS = ["aes","bcrypt","camellia","pbkdf2","sha2","shax","ecc","x509","hmacx","diffiehellman"]

# Commands mapping
COMMANDS = [
    ("sp", "🛡️ Semgrep Findings", "sp"),
    ("vulns", "🐞 Vulnerability Findings", "vulns"),
    ("prv", "🌍 Provenance Info", "prv"),
    ("vs", "📦 Versions Info", "vs"),
    ("cr", "🔐 Encryption Info", "crypto")
]

# ── Streamlit Setup ───────────────────────────────────────────────────────────
st.set_page_config(page_title="SCANOSS DeepScan", layout="wide")
st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=Rubik:wght@500&family=Source+Sans+Pro&display=swap');
html, body, .block-container { font-family: 'Source Sans Pro', sans-serif; }
h1,h2,h3,h4 { font-family: 'Rubik', sans-serif; }
</style>
""", unsafe_allow_html=True)
st.title("🔍 SCANOSS DeepScan")

# ── CLI Runner ────────────────────────────────────────────────────────────────
def run_scanoss(sub, purl):
    cmd = ["scanoss-py", "comp", sub, "--key", SCANOSS_API_KEY, "--purl", purl]
    try:
        res = subprocess.run(cmd, check=False, capture_output=True, text=True)
    except FileNotFoundError:
        st.error("🔧 'scanoss-py' not found. Install SCANOSS CLI.")
        return {}
    out = res.stdout or ""
    idx = out.find('{')
    payload = out[idx:] if idx >= 0 else out
    try:
        return json.loads(payload)
    except json.JSONDecodeError:
        return {}

# ── Main UI ─────────────────────────────────────────────────────────────────
purl = st.text_input("Enter PURL", placeholder="pkg:github/heimdal/heimdal@version").strip()
if st.button("Scan"):
    if not purl:
        st.error("Please enter a valid PURL.")
        st.stop()

    with st.spinner("Running SCANOSS commands..."):
        progress = st.progress(0)
        data = {}
        total = len(COMMANDS)
        for idx, (key, _, cli) in enumerate(COMMANDS, start=1):
            data[key] = run_scanoss(cli, purl)
            progress.progress(int(idx/total * 100))
        progress.empty()

    # ... rest of code unchanged ...
    st.success("Analysis complete.")
    st.download_button("Download JSON", json.dumps(data, indent=2), "scanoss_results.json", "application/json")
