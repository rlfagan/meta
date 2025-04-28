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
        for rating in br["ratings"]
        for lic in rating["licenses"]
        if lic.get("id")
    }
except FileNotFoundError:
    blueoak_map = {}

# Load SPDX license metadata
try:
    with open("licenses.json") as f:
        spdx_data = json.load(f)
    spdx_license_map = {
        lic["licenseId"]: lic
        for lic in spdx_data["licenses"]
        if lic.get("licenseId")
    }
except FileNotFoundError:
    spdx_license_map = {}

# Load GitHub Advisory if present
try:
    with open("vulcurl.json") as f:
        gha = json.load(f)
except FileNotFoundError:
    gha = None

# Algorithm categories
LEGACY_ALGOS = ["md2","md4","md5","rc4","rc4-hmac","des","tdes","ripemd","skipjack"]
MODERN_ALGOS = ["aes","bcrypt","camellia","pbkdf2","sha2","shax","ecc","x509","hmacx","diffiehellman"]
PUBLIC_KEY_ALGOS = {"rsa","dsa","diffiehellman","elgamal","ecmqv","ecc","x509"}

# Commands mapping
COMMANDS = [
    ("sp", "🛡️ Semgrep Findings", "sp"),
    ("vulns", "🐞 Vulnerability Findings", "vulns"),
    ("prv", "🌍 Provenance Info", "prv"),
    ("vs", "📜 License Ratings", "vs"),
    ("tl", "🗓️ Release Timeline", "tl"),
    ("cr", "🔐 Encryption Info", "crypto")
]

# ── Streamlit Setup ───────────────────────────────────────────────────────────
st.set_page_config(page_title="SSCANOSS DEEPSCAN", layout="wide")
st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=Rubik:wght@500&family=Source+Sans+Pro&display=swap');
html, body, .block-container { font-family: 'Source Sans Pro', sans-serif; }
h1,h2,h3,h4 { font-family: 'Rubik', sans-serif; }
</style>
""", unsafe_allow_html=True)
st.title("🔍 SCANOSS DEEPSCAN")

# ── CLI Runner ────────────────────────────────────────────────────────────────
def run_scanoss(sub: str, purl: str) -> dict:
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

    # Run commands with progress
    with st.spinner("Running SCANOSS commands..."):
        progress = st.progress(0)
        data = {}
        total = len(COMMANDS)
        for idx, (key, _, cli) in enumerate(COMMANDS, start=1):
            data[key] = run_scanoss(cli, purl)
            progress.progress(int(idx/total * 100))
        progress.empty()

    # -- Parse Semgrep Findings --
    sem_rows = []
    for p in data['sp'].get('purls', []):
        for f in p.get('files', []):
            file_path = f.get('path', 'Unknown file')
            for i in f.get('issues', []):
                rid = i['ruleID'].split('semgrep-rules.')[-1]
                sem_rows.append({
                    'Rule': rid,
                    'Severity': i['severity'],
                    'File': file_path,
                    'URL': f"https://semgrep.dev/r/{rid}"
                })
    sem_df = pd.DataFrame(sem_rows)
    sem_sev = (sem_df['Severity'].value_counts().reset_index()
               if not sem_df.empty else pd.DataFrame(columns=['Severity','Count']))
    sem_sev.columns = ['Severity','Count']

    # -- Parse Vulnerabilities --
    vuln_rows = []
    for p in data['vulns'].get('purls', []):
        for arr in (p.get('vulnerabilities', []), p.get('vulns', [])):
            if isinstance(arr, list):
                for v in arr:
                    vid = v.get('id') or v.get('cve','')
                    sev = v.get('severity') or v.get('cvss_score','')
                    desc = (v.get('title') or v.get('description',''))[:200]
                    if vid.startswith('GHSA'):
                        url = f"https://github.com/advisories/{vid}"
                    elif vid.startswith('CVE'):
                        url = f"https://cve.mitre.org/cgi-bin/cvename.cgi?name={vid}"
                    else:
                        url = v.get('url','')
                    vuln_rows.append({
                        'ID': vid,
                        'Severity': sev,
                        'Description': desc,
                        'Advisory URL': url
                    })
                break
    vuln_df = pd.DataFrame(vuln_rows)
    vuln_sev = (vuln_df['Severity'].value_counts().reset_index()
                if not vuln_df.empty else pd.DataFrame(columns=['Severity','Count']))
    vuln_sev.columns = ['Severity','Count']

    # -- Parse Provenance Info --
    declared = data['prv'].get('purls',[{}])[0].get('declared_locations',[])
    counts = Counter()
    coords = []
    for d in declared:
        country = d.get('location','').split(',')[-1].strip().title() or 'Unknown'
        counts[country]+=1
    for country, cnt in counts.most_common(25):
        coord = get_coords(country)
        if coord:
            coords.append({'lat':coord[0],'lon':coord[1],'weight':cnt})
    country_df = pd.DataFrame(counts.items(),columns=['Country','Contributors'])
    coords_df = pd.DataFrame(coords)

    # -- Parse License Ratings --
    vs_list = data['vs'].get('component',{}).get('versions',[])
    comp_url = data['vs'].get('component',{}).get('url','')

    ranges, current = [], None
    for v in vs_list:
        ver = v.get('version')
        lic_list = v.get('licenses',[])
        if lic_list:
            lic0=lic_list[0]
            spdx,name,lurl = lic0.get('spdx_id'), lic0.get('name'), lic0.get('url','')
        else:
            spdx,name,lurl = None, None, None
        key = (spdx,name,lurl)
        if current is None:
            current = {'start':ver,'end':ver,'spdx':spdx,'name':name,'url':lurl}
        elif (current['spdx'],current['name'],current['url']) == key:
            current['end'] = ver
        else:
            ranges.append(current)
            current = {'start':ver,'end':ver,'spdx':spdx,'name':name,'url':lurl}
    if current: ranges.append(current)

    lic_rows = []
    for r in ranges:
        if not r['spdx']: continue
        vr = r['start'] if r['start']==r['end'] else f"{r['end']} – {r['start']}"
        rating = blueoak_map.get(r['spdx'],'Not Rated')
        spdx_info = spdx_license_map.get(r['spdx'],{})
        osi = spdx_info.get("isOsiApproved","Unknown")
        dep = spdx_info.get("isDeprecatedLicenseId","Unknown")
        lic_rows.append({
            'Version Range': vr,
            'License': f"[{r['name']}]({r['url']})",
            'Blue Oak Rating': rating,
            'OSI Approved': osi,
            'Deprecated': dep
        })
    lic_df = pd.DataFrame(lic_rows)

    # -- Parse Encryption Info --
    algos = data['cr'].get('purls',[{}])[0].get('algorithms',[])
    enc_rows = []
    for a in algos:
        alg=a.get('algorithm'); strength=a.get('strength')
        cat=('Legacy' if alg in LEGACY_ALGOS else 'Modern' if alg in MODERN_ALGOS else 'Other')
        quantum=('✖ Not quantum-safe' if alg in PUBLIC_KEY_ALGOS else '✔ Quantum-safe')
        enc_rows.append({'Algorithm':alg,'Strength':strength,'Category':cat,'Quantum Safe':quantum})
    enc_df = pd.DataFrame(enc_rows)
    cat_counts = (enc_df['Category'].value_counts().reset_index()
                  if not enc_df.empty else pd.DataFrame(columns=['Category','Count']))
    cat_counts.columns = ['Category','Count']

    # ── Metrics Row ────────────────────────────────────────────────────────────
    c1,c2,c3,c4,c5 = st.columns(5)
    c1.metric("Semgrep Issues", len(sem_df))
    c2.metric("Vulnerabilities", len(vuln_df))
    c3.metric("Countries", len(country_df))
    c4.metric("License Ranges", len(lic_df))
    c5.metric("Algorithms", len(enc_df))

    # ── Tabs ───────────────────────────────────────────────────────────────────
    tabs = st.tabs([
        "📜 License Ratings",
        "🛡️ Semgrep Findings",
        "🐞 Vulnerability Findings",
        "🌍 Provenance Info",
        "🗓️ Release Timeline",
        "🔐 Encryption Info"
    ])

    # 1. License Ratings
    with tabs[0]:
        st.subheader("License Ratings")
        if not lic_df.empty:
            st.markdown(lic_df.to_markdown(index=False), unsafe_allow_html=True)
        else:
            st.info("No license metadata available.")

    # 2. Semgrep Findings
    with tabs[1]:
        st.subheader("Static Analysis Findings")
        if not sem_df.empty:
            st.write(f"Found **{len(sem_df)}** issues.")
            # make Rule clickable
            sem_display = sem_df.copy()
            sem_display['Rule'] = sem_display.apply(
                lambda r: f"[{r['Rule']}]({r['URL']})", axis=1
            )
            st.markdown(
                sem_display[['Rule','Severity','File']].to_markdown(index=False),
                unsafe_allow_html=True
            )
            st.altair_chart(
                alt.Chart(sem_sev).mark_bar().encode(
                    x='Severity:N', y='Count:Q', color='Severity:N'
                ), use_container_width=True
            )
        else:
            st.info("🚫 No Semgrep issues found.")

    # 3. Vulnerability Findings
    with tabs[2]:
        st.subheader("Vulnerability Findings")
        if gha:
            st.markdown(f"**Summary:** {gha['summary']}")
            st.markdown(f"**Description:** {gha['description']}")
            st.markdown("**References:**")
            for r in gha['references']:
                st.markdown(f"- [{r}]({r})")
        if not vuln_df.empty:
            st.write(f"Detected **{len(vuln_df)}** vulnerabilities.")
            st.table(vuln_df)
            st.altair_chart(
                alt.Chart(vuln_sev).mark_arc(innerRadius=40).encode(
                    theta='Count:Q', color='Severity:N'
                ), use_container_width=True
            )
        else:
            st.info("🛡️ No known vulnerabilities for this component.")

    # 4. Provenance Info
    with tabs[3]:
        st.subheader("Contributor Provenance")
        if not country_df.empty:
            st.table(country_df)
            if not coords_df.empty:
                st.pydeck_chart(
                    pdk.Deck(
                        layers=[pdk.Layer('HeatmapLayer', coords_df,
                                          get_position='[lon, lat]',
                                          get_weight='weight',
                                          radiusPixels=60)],
                        initial_view_state=pdk.ViewState(latitude=20,
                                                         longitude=0,
                                                         zoom=1)
                    ), use_container_width=True
                )
        else:
            st.info("🌐 No contributor provenance data available.")

    # 5. Release Timeline
    with tabs[4]:
        st.subheader("Release Timeline")
        timeline_df = pd.DataFrame({
            'Index': list(range(1, len(vs_list)+1)),
            'Version': [v.get('version') for v in vs_list]
        })
        if len(vs_list)>1:
            st.altair_chart(
                alt.Chart(timeline_df).mark_line(point=True)
                  .encode(x='Index:Q', y='Index:Q', tooltip=['Version:N']),
                use_container_width=True
            )
            st.table(timeline_df)
        else:
            st.info("📈 Only one release found; timeline chart omitted.")

    # 6. Encryption Info
    with tabs[5]:
        st.subheader("Encryption Algorithms")
        if not enc_df.empty:
            st.table(enc_df)
            st.altair_chart(
                alt.Chart(cat_counts).mark_arc(innerRadius=50).encode(
                    theta='Count:Q', color='Category:N'
                ), use_container_width=True
            )
        else:
            st.info("🔒 No encryption metadata found for this component.")

    st.success("Analysis complete.")
    st.download_button(
        "Download JSON", json.dumps(data, indent=2),
        "scanoss_results.json", "application/json"
    )
