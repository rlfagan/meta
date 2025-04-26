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

    # Progress
    with st.spinner("Running SCANOSS commands..."):
        progress = st.progress(0)
        data = {}
        total = len(COMMANDS)
        for idx, (key, _, cli) in enumerate(COMMANDS, start=1):
            data[key] = run_scanoss(cli, purl)
            progress.progress(int(idx/total * 100))
        progress.empty()

    # --- Parse Data ---
    # Semgrep
    sem_rows = []
    for p in data['sp'].get('purls', []):
        for f in p.get('files', []):
            for i in f.get('issues', []):
                sem_rows.append({'Rule': i['ruleID'], 'Severity': i['severity']})
    sem_df = pd.DataFrame(sem_rows)
    sem_sev = sem_df['Severity'].value_counts().reset_index() if not sem_df.empty else pd.DataFrame(columns=['Severity','Count'])
    sem_sev.columns = ['Severity','Count']

    # Vulnerabilities
    vuln_rows = []
    for p in data['vulns'].get('purls', []):
        for arr in (p.get('vulnerabilities', []), p.get('vulns', [])):
            if isinstance(arr, list):
                for v in arr:
                    vuln_rows.append({'ID': v.get('id') or v.get('cve',''),
                                      'Severity': v.get('severity') or v.get('cvss_score',''),
                                      'Desc': (v.get('title') or v.get('description',''))[:100]})
                break
    vuln_df = pd.DataFrame(vuln_rows)
    vuln_sev = vuln_df['Severity'].value_counts().reset_index() if not vuln_df.empty else pd.DataFrame(columns=['Severity','Count'])
    vuln_sev.columns = ['Severity','Count']

    # Provenance
    declared = data['prv'].get('purls', [{}])[0].get('declared_locations', [])
    counts = Counter()
    coords = []
    for d in declared:
        country = d.get('location','').split(',')[-1].strip().title() or 'Unknown'
        counts[country] += 1
    top = counts.most_common(25)
    for country, cnt in top:
        coord = get_coords(country)
        if coord:
            coords.append({'lat': coord[0], 'lon': coord[1], 'weight': cnt})
    country_df = pd.DataFrame(counts.items(), columns=['Country','Count'])
    coords_df = pd.DataFrame(coords)

    # Versions & Licenses
    vs_list = data['vs'].get('component', {}).get('versions', [])
    versions = [v.get('version') for v in vs_list if v.get('version')]
    timeline_df = pd.DataFrame({'Release': versions, 'Index': list(range(1, len(versions)+1))})
    lic_rows = []
    for v in vs_list:
        for lic in v.get('licenses', []):
            spdx = lic.get('spdx_id')
            lic_rows.append({'Version': v.get('version'),
                             'License': lic.get('name'),
                             'SPDX': spdx,
                             'Blue Oak': blueoak_map.get(spdx, 'Not Rated')})
    lic_df = pd.DataFrame(lic_rows)
    rating_counts = lic_df['Blue Oak'].value_counts().reset_index() if not lic_df.empty else pd.DataFrame(columns=['Rating','Count'])
    rating_counts.columns = ['Rating','Count']

    # Encryption
    algos = data['cr'].get('purls', [{}])[0].get('algorithms', [])
    enc_df = pd.DataFrame(algos)
    if not enc_df.empty:
        enc_df.rename(columns={'algorithm':'Algorithm','strength':'Strength'}, inplace=True)
        enc_df['Category'] = enc_df['Algorithm'].apply(lambda x: 'Legacy' if x in LEGACY_ALGOS else 'Modern' if x in MODERN_ALGOS else 'Other')
    cat_counts = enc_df['Category'].value_counts().reset_index() if not enc_df.empty else pd.DataFrame(columns=['Category','Count'])
    cat_counts.columns = ['Category','Count']

    # Metrics
    c1, c2, c3, c4, c5 = st.columns(5)
    c1.metric("Semgrep Issues", len(sem_df))
    c2.metric("Vulnerabilities", len(vuln_df))
    c3.metric("Countries", len(country_df))
    c4.metric("Releases", len(versions))
    c5.metric("Algorithms", len(enc_df))

    # Tabs
    tabs = st.tabs([lbl for _, lbl, _ in COMMANDS])

    # 1. Semgrep
    with tabs[0]:
        st.subheader("Static Analysis: Severity Breakdown")
        st.write(f"Found **{len(sem_df)}** total issues.")
        if not sem_sev.empty:
            st.table(sem_sev)
            st.altair_chart(
                alt.Chart(sem_sev).mark_bar().encode(
                    x='Severity:N', y='Count:Q', color='Severity:N'),
                use_container_width=True)
        else:
            st.info("No Semgrep issues found.")
        st.markdown("**Security Concern Identified:** Review top severity rules and address immediately.")
        st.markdown("**Actionable Recommendations:** Prioritize fixes for HIGH severity and integrate Semgrep into CI/CD.")
        st.markdown("**Broader Implications:** Finding and resolving code quality issues early reduces long-term maintenance costs.")

    # 2. Vulnerabilities
    with tabs[1]:
        st.subheader("Vulnerability Analysis")
        st.write(f"Detected **{len(vuln_df)}** vulnerabilities across all versions.")
        if not vuln_sev.empty:
            st.table(vuln_sev)
            st.altair_chart(
                alt.Chart(vuln_sev).mark_arc(innerRadius=40).encode(
                    theta='Count:Q', color='Severity:N'),
                use_container_width=True)
        else:
            st.info("No known vulnerabilities detected.")
        st.markdown("**Security Concern Identified:** Address critical and high CVEs first.")
        st.markdown("**Actionable Recommendations:** Apply security patches and update dependencies regularly.")
        st.markdown("**Broader Implications:** Vulnerability management is key to maintaining trust and compliance.")

    # 3. Geomap
    with tabs[2]:
        st.subheader("Contributor Geographical Distribution")
        st.write(f"**{len(country_df)}** countries represented by contributors.")
        if not country_df.empty:
            st.table(country_df)
            st.pydeck_chart(
                pdk.Deck(
                    initial_view_state=pdk.ViewState(latitude=20, longitude=0, zoom=1),
                    layers=[
                        pdk.Layer('HeatmapLayer', coords_df,
                                  get_position='[lon, lat]', get_weight='weight', radiusPixels=60)
                    ]),
                use_container_width=True)
        else:
            st.info("No contributor location data available.")
        st.markdown("**Security Concern Identified:** Ensure diverse global input to mitigate blind spots.")
        st.markdown("**Actionable Recommendations:** Encourage contributions from underrepresented regions.")
        st.markdown("**Broader Implications:** Broad contributor base enhances project resilience.")

    # 4. Timeline & Licenses
    with tabs[3]:
        st.subheader("Release Timeline & License Ratings")
        st.write(f"**{len(versions)}** total releases detected.")
        if not timeline_df.empty:
            st.altair_chart(
                alt.Chart(timeline_df).mark_line(point=True).encode(
                    x='Index:Q', y='Index:Q', tooltip=['Release:N']),
                use_container_width=True)
            st.table(timeline_df)
        if not rating_counts.empty:
            st.table(rating_counts)
            st.altair_chart(
                alt.Chart(rating_counts).mark_arc(innerRadius=50).encode(
                    theta='Count:Q', color='Rating:N'),
                use_container_width=True)
            st.table(lic_df)
        st.markdown("**Security Concern Identified:** Monitor license compatibility across versions.")
        st.markdown("**Actionable Recommendations:** Ensure license compliance and consider upgrading restrictive licenses.")
        st.markdown("**Broader Implications:** Clear licensing fosters open collaboration and legal clarity.")

    # 5. Encryption
    with tabs[4]:
        st.subheader("Encryption Algorithm Analysis")
        st.write(f"**{len(enc_df)}** algorithms detected.")
        if not cat_counts.empty:
            st.table(cat_counts)
            st.altair_chart(
                alt.Chart(cat_counts).mark_arc(innerRadius=50).encode(
                    theta='Count:Q', color='Category:N'),
                use_container_width=True)
            st.table(enc_df)
        else:
            st.info("No encryption algorithm data available.")
        st.markdown("**Security Concern Identified:** Replace legacy ciphers to maintain strong cryptography.")
        st.markdown("**Actionable Recommendations:** Deprecate algorithms like MD5, RC4; adopt AES, SHA-2.")
        st.markdown("**Broader Implications:** Strong encryption is vital for data protection and compliance.")

    st.success("Analysis complete.")
    st.download_button("Download JSON", json.dumps(data, indent=2), "scanoss_results.json", "application/json")
