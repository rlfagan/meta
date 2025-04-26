import os
import json
import subprocess
import pandas as pd
import altair as alt
import streamlit as st
import pydeck as pdk
from geopy.geocoders import Nominatim
from packageurl import PackageURL
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

# ── Load Blue Oak ratings ─────────────────────────────────────────────────────
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

# ── Algorithm categories ──────────────────────────────────────────────────────
LEGACY_ALGOS = ["md2","md4","md5","rc4","rc4-hmac","des","tdes","ripemd","skipjack"]
MODERN_ALGOS = ["aes","bcrypt","camellia","pbkdf2","sha2","shax","ecc","x509","hmacx","diffiehellman"]

# ── Streamlit Setup ───────────────────────────────────────────────────────────
st.set_page_config(page_title="🔍 SCANOSS DeepScan", layout="wide")
st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=Rubik:wght@500&family=Source+Sans+Pro&display=swap');
html, body, .block-container { font-family: 'Source Sans Pro', sans-serif; }
h1,h2,h3,h4 { font-family: 'Rubik', sans-serif; }
</style>
""", unsafe_allow_html=True)
st.title("🔍 SCANOSS DeepScan")

# ── Helper: run SCANOSS CLI ────────────────────────────────────────────────────
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
purl_input = st.text_input(
    "Enter a valid Package URL (PURL)",
    placeholder="e.g. pkg:maven/log4j/log4j@1.2.17"
).strip()
if st.button("Scan"):
    if not purl_input:
        st.error("Please enter a valid PURL.")
        st.stop()
    # Validate PURL format
    try:
        PackageURL.from_string(purl_input)
    except Exception:
        st.error("Invalid PURL format. Please use pkg:type/namespace/name@version")
        st.stop()

    # Execute all component commands
    COMMANDS = ["sp","vulns","prv","vs","cr"]
    with st.spinner("Running SCANOSS commands..."):
        progress = st.progress(0)
        data = {}
        total = len(COMMANDS)
        for idx, cli in enumerate(COMMANDS, start=1):
            data[cli] = run_scanoss(cli, purl_input)
            progress.progress(int(idx/total * 100))
        progress.empty()

    # ── Parse and visualize results ─────────────────────────────────────────────
    # License Ratings
    vs_list = data['vs'].get('component', {}).get('versions', [])
    lic_rows = []
    for v in vs_list:
        for lic in v.get('licenses', []):
            spdx = lic.get('spdx_id')
            lic_rows.append({
                'Version': v.get('version'),
                'License': lic.get('name'),
                'SPDX': spdx,
                'Blue Oak': blueoak_map.get(spdx, 'Not Rated')
            })
    lic_df = pd.DataFrame(lic_rows)
    rating_counts = (
        lic_df['Blue Oak'].value_counts().reset_index()
        if not lic_df.empty else pd.DataFrame(columns=['Rating','Count'])
    )
    rating_counts.columns = ['Rating','Count']

    # Semgrep Findings
    sem_rows = []
    for p in data['sp'].get('purls', []):
        for f in p.get('files', []):
            for i in f.get('issues', []):
                sem_rows.append({'Rule': i['ruleID'], 'Severity': i['severity']})
    sem_df = pd.DataFrame(sem_rows)
    sem_sev = (
        sem_df['Severity'].value_counts().reset_index()
        if not sem_df.empty else pd.DataFrame(columns=['Severity','Count'])
    )
    sem_sev.columns = ['Severity','Count']

    # Vulnerabilities
    vuln_rows = []
    for p in data['vulns'].get('purls', []):
        for arr in (p.get('vulnerabilities', []), p.get('vulns', [])):
            if isinstance(arr, list):
                for v in arr:
                    vuln_rows.append({
                        'ID': v.get('id') or v.get('cve',''),
                        'Severity': v.get('severity') or v.get('cvss_score',''),
                        'Desc': (v.get('title') or v.get('description',''))[:100]
                    })
                break
    vuln_df = pd.DataFrame(vuln_rows)
    vuln_sev = (
        vuln_df['Severity'].value_counts().reset_index()
        if not vuln_df.empty else pd.DataFrame(columns=['Severity','Count'])
    )
    vuln_sev.columns = ['Severity','Count']

    # Provenance
    declared = data['prv'].get('purls', [{}])[0].get('declared_locations', [])
    country_counts = Counter()
    coords = []
    for d in declared:
        country = d.get('location','').split(',')[-1].strip().title() or 'Unknown'
        country_counts[country] += 1
    for country, cnt in country_counts.most_common(25):
        coord = get_coords(country)
        if coord:
            coords.append({'lat': coord[0], 'lon': coord[1], 'weight': cnt})
    country_df = pd.DataFrame(country_counts.items(), columns=['Country','Count'])
    coords_df = pd.DataFrame(coords)

    # Release Timeline
    versions = [v.get('version') for v in vs_list if v.get('version')]
    timeline_df = pd.DataFrame({'Index': range(1, len(versions)+1), 'Version': versions})

    # Encryption
    algos = data['cr'].get('purls', [{}])[0].get('algorithms', [])
    enc_df = pd.DataFrame(algos)
    if not enc_df.empty:
        enc_df.rename(columns={'algorithm':'Algorithm','strength':'Strength'}, inplace=True)
        enc_df['Category'] = enc_df['Algorithm'].apply(
            lambda x: 'Legacy' if x in LEGACY_ALGOS else 'Modern' if x in MODERN_ALGOS else 'Other'
        )
    cat_counts = (
        enc_df['Category'].value_counts().reset_index()
        if not enc_df.empty else pd.DataFrame(columns=['Category','Count'])
    )
    cat_counts.columns = ['Category','Count']

    # ── Summary Metrics ────────────────────────────────────────────────────────
    cols = st.columns(6)
    cols[0].metric("License Entries", len(lic_df))
    cols[1].metric("Semgrep Issues", len(sem_df))
    cols[2].metric("Vulnerabilities", len(vuln_df))
    cols[3].metric("Countries", len(country_df))
    cols[4].metric("Releases", len(versions))
    cols[5].metric("Algorithms", len(enc_df))

    # ── Tabs ───────────────────────────────────────────────────────────────────
    tabs = st.tabs([
        "📜 License Ratings",
        "🛡️ Semgrep Findings",
        "🐞 Vulnerability Findings",
        "🌍 Provenance Info",
        "🗓️ Release Timeline",
        "🔐 Encryption Info"
    ])

    # License Tab
    with tabs[0]:
        st.subheader("License Findings & Blue Oak Evaluation")
        if not rating_counts.empty:
            st.write(f"**{len(rating_counts)}** Blue Oak categories across {len(lic_df)} licenses.")
            st.altair_chart(
                alt.Chart(rating_counts)
                    .mark_arc(innerRadius=50)
                    .encode(theta='Count:Q', color='Rating:N'),
                use_container_width=True)
            st.table(lic_df)
        else:
            st.info("No license data found.")

    # Semgrep Tab
    with tabs[1]:
        st.subheader("Static Analysis Severity")
        st.write(f"Found **{len(sem_df)}** issues.")
        if not sem_sev.empty:
            st.altair_chart(
                alt.Chart(sem_sev)
                    .mark_bar()
                    .encode(x='Severity:N', y='Count:Q', color='Severity:N'),
                use_container_width=True)
            st.table(sem_sev)
            for sev in sem_sev['Severity']:
                rules = sem_df[sem_df['Severity']==sev]['Rule'].unique().tolist()
                st.markdown(f"**{sev} Issues:** {', '.join(rules)}")
        else:
            st.info("No Semgrep issues found.")

    # Vulnerabilities Tab
    with tabs[2]:
        st.subheader("Vulnerability Severity")
        st.write(f"Detected **{len(vuln_df)}** vulnerabilities.")
        if not vuln_sev.empty:
            st.altair_chart(
                alt.Chart(vuln_sev)
                    .mark_arc(innerRadius=40)
                    .encode(theta='Count:Q', color='Severity:N'),
                use_container_width=True)
            st.table(vuln_sev)
            for sev in vuln_sev['Severity']:
                items = vuln_df[vuln_df['Severity']==sev][['ID','Desc']].drop_duplicates().values.tolist()
                details = '; '.join(f"{i[0]} ({i[1]})" for i in items)
                st.markdown(f"**{sev} Vulnerabilities:** {details}")
        else:
            st.info("No vulnerabilities found.")

    # Provenance Tab
    with tabs[3]:
        st.subheader("Contributor Geomap")
        st.write(f"**{len(country_df)}** countries represented.")
        if not coords_df.empty:
            deck = pdk.Deck(
                layers=[
                    pdk.Layer('HeatmapLayer', coords_df, get_position='[lon, lat]', get_weight='weight', radiusPixels=60)
                ],
                initial_view_state=pdk.ViewState(latitude=20, longitude=0, zoom=1)
            )
            st.pydeck_chart(deck, use_container_width=True)
        else:
            st.info("No geolocation data.")

    # Timeline Tab
    with tabs[4]:
        st.subheader("Release Timeline")
        st.write(f"**{len(versions)}** releases.")
        if not timeline_df.empty:
            st.altair_chart(
                alt.Chart(timeline_df).mark_line(point=True)
                    .encode(x='Index:Q', y='Index:Q', tooltip=['Version:N']),
                use_container_width=True)
            st.table(timeline_df)

    # Encryption Tab
    with tabs[5]:
        st.subheader("Encryption Algorithm Analysis")
        st.write(f"**{len(enc_df)}** algorithms detected.")
        if not cat_counts.empty:
            st.altair_chart(
                alt.Chart(cat_counts)
                    .mark_arc(innerRadius=50)
                    .encode(theta='Count:Q', color='Category:N'),
                use_container_width=True)
            st.table(cat_counts)
            for cat in ['Legacy','Modern','Other']:
                subset = enc_df[enc_df['Category']==cat]
                if not subset.empty:
                    st.markdown(f"**{cat} Algorithms:** {', '.join(subset['Algorithm'].tolist())}")
        else:
            st.info("No encryption data.")

    st.success("Analysis complete.")
    st.download_button("Download JSON", json.dumps(data, indent=2), "scanoss_results.json", "application/json")
