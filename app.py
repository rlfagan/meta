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

# ── Blue Oak Ratings ─────────────────────────────────────────────────────────
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

# ── Algorithm Categories ───────────────────────────────────────────────────────
LEGACY_ALGOS = ["md2","md4","md5","rc4","rc4-hmac","des","tdes","ripemd","skipjack"]
MODERN_ALGOS = ["aes","bcrypt","camellia","pbkdf2","sha2","shax","ecc","x509","hmacx","diffiehellman"]
QUANTUM_VULNERABLE = {"rsa","dsa","elgamal","diffiehellman","ecmqv","ecc","mqv"}

# ── Streamlit Setup ───────────────────────────────────────────────────────────
st.set_page_config(page_title="🔍 SCANOSS Component Security Report", layout="wide")
st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=Rubik:wght@500&family=Source+Sans+Pro&display=swap');
html, body, .block-container { font-family: 'Source Sans Pro', sans-serif; }
h1,h2,h3,h4 { font-family: 'Rubik', sans-serif; }
</style>
""", unsafe_allow_html=True)
st.title("🔍 SCANOSS Component Security Report")

# ── CLI Runner ────────────────────────────────────────────────────────────────
def run_scanoss(sub: str, purl: str):
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

    # Run SCANOSS commands
    with st.spinner("Running SCANOSS commands..."):
        data = {
            'sp': run_scanoss('sp', purl),
            'vulns': run_scanoss('vulns', purl),
            'prv': run_scanoss('prv', purl),
            'vs': run_scanoss('vs', purl),
            'cr': run_scanoss('crypto', purl)
        }

    # -- Semgrep Findings --
    sem_rows = []
    for p in data['sp'].get('purls', []):
        for f in p.get('files', []):
            filepath = f.get('path', '')
            for i in f.get('issues', []):
                rule = i.get('ruleID')
                severity = i.get('severity')
                rule_url = f"https://semgrep.dev/r/{rule}"
                sem_rows.append({
                    'Rule': rule,
                    'Severity': severity,
                    'File': filepath,
                    'URL': rule_url
                })
    sem_df = pd.DataFrame(sem_rows)

    # -- Vulnerability Findings --
    vuln_rows = []
    for p in data['vulns'].get('purls', []):
        arr = p.get('vulnerabilities') or p.get('vulns') or []
        for v in arr:
            vid = v.get('id') or v.get('cve', '')
            desc = (v.get('title') or v.get('description', ''))[:200]
            vid_up = vid.upper()
            if vid_up.startswith('CVE'):
                url = f"https://nvd.nist.gov/vuln/detail/{vid_up}"
            elif vid_up.startswith('GHSA'):
                url = f"https://github.com/advisories/{vid_up}"
            else:
                url = ''
            vuln_rows.append({
                'ID': vid,
                'Severity': v.get('severity') or v.get('cvss_score', ''),
                'Desc': desc,
                'URL': url
            })
    vuln_df = pd.DataFrame(vuln_rows)

    # -- Provenance Info --
    declared = data['prv'].get('purls', [{}])[0].get('declared_locations', [])
    counts = Counter(d.get('location', '').split(',')[-1].strip().title() or 'Unknown' for d in declared)
    country_df = pd.DataFrame(counts.items(), columns=['Country', 'Count'])
    coords = []
    for country, cnt in counts.most_common(25):
        coord = get_coords(country)
        if coord:
            coords.append({'lat': coord[0], 'lon': coord[1], 'weight': cnt})
    coords_df = pd.DataFrame(coords)

    # -- Versions & License Ratings --
    comp = data['vs'].get('component', {})
    homepage = comp.get('url', '')
    vs_list = comp.get('versions', [])
    # group contiguous entries with same license
    license_rows = []
    groups = []
    for entry in vs_list:
        ver = entry.get('version')
        lic = entry.get('licenses', [{}])[0]
        spdx = lic.get('spdx_id')
        name = lic.get('name')
        lic_url = lic.get('url', '')
        license_rows.append({'version': ver, 'spdx': spdx, 'name': name, 'lic_url': lic_url})
    for r in license_rows:
        if not groups or any(groups[-1][k] != r[k] for k in ('spdx','name','lic_url')):
            groups.append(dict(start=r['version'], end=r['version'], spdx=r['spdx'], name=r['name'], lic_url=r['lic_url']))
        else:
            groups[-1]['end'] = r['version']
    lic_display = []
    for g in groups:
        vr = g['start'] if g['start'] == g['end'] else f"{g['start']}–{g['end']}"
        lic_display.append({
            'Version Range': vr,
            'License': g['name'] or 'Unknown',
            'SPDX': g['spdx'] or '',
            'URL': g['lic_url'],
            'Blue Oak Rating': blueoak_map.get(g['spdx'], 'Not Rated')
        })
    lic_df = pd.DataFrame(lic_display)

    # -- Encryption Info --
    algos = data['cr'].get('purls', [{}])[0].get('algorithms', [])
    enc_rows = []
    for a in algos:
        algo = a.get('algorithm')
        strength = a.get('strength')
        category = 'Legacy' if algo in LEGACY_ALGOS else 'Modern' if algo in MODERN_ALGOS else 'Other'
        quantum_safe = 'No' if algo in QUANTUM_VULNERABLE else 'Yes'
        enc_rows.append({'Algorithm': algo, 'Strength': strength, 'Category': category, 'Quantum Safe': quantum_safe})
    enc_df = pd.DataFrame(enc_rows)

    # ── Tabs ─────────────────────────────────────────────────────────────────
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
        st.subheader("Component Licenses")
        if homepage:
            st.markdown(f"**Homepage:** [{homepage}]({homepage})")
        if not lic_df.empty:
            st.table(lic_df)
        else:
            st.info("No license data available.")

    # 2. Semgrep Findings
    with tabs[1]:
        st.subheader("Static Analysis (Semgrep)")
        if not sem_df.empty:
            st.dataframe(sem_df)
            sev_counts = sem_df['Severity'].value_counts().reset_index()
            sev_counts.columns = ['Severity','Count']
            st.altair_chart(
                alt.Chart(sev_counts).mark_bar().encode(x='Severity:N', y='Count:Q', color='Severity:N'),
                use_container_width=True
            )
        else:
            st.info("No Semgrep issues found.")

    # 3. Vulnerability Findings
    with tabs[2]:
        st.subheader("Vulnerabilities (CVE/GHSA)")
        if not vuln_df.empty:
            st.dataframe(vuln_df)
            v_counts = vuln_df['Severity'].value_counts().reset_index()
            v_counts.columns = ['Severity','Count']
            st.altair_chart(
                alt.Chart(v_counts).mark_arc(innerRadius=40).encode(theta='Count:Q', color='Severity:N'),
                use_container_width=True
            )
        else:
            st.info("No vulnerabilities detected.")

    # 4. Provenance Info
    with tabs[3]:
        st.subheader("Contributor Geography")
        if not country_df.empty and not coords_df.empty:
            st.pydeck_chart(
                pdk.Deck(
                    layers=[
                        pdk.Layer('HeatmapLayer', coords_df, get_position='[lon, lat]', get_weight='weight', radiusPixels=60)
                    ],
                    initial_view_state=pdk.ViewState(latitude=20, longitude=0, zoom=1)
                ),
                use_container_width=True
            )
        else:
            st.info("No provenance data available.")

    # 5. Release Timeline
    with tabs[4]:
        st.subheader("Release Timeline")
        releases = [r['version'] for r in license_rows]
        if releases:
            timeline_df = pd.DataFrame({'Index': range(1, len(releases)+1), 'Version': releases})
            st.altair_chart(
                alt.Chart(timeline_df).mark_line(point=True).encode(
                    x='Index:Q', y='Index:Q', tooltip=['Version']
                ),
                use_container_width=True
            )
            st.table(timeline_df)
        else:
            st.info("No release data available.")

    # 6. Encryption Info
    with tabs[5]:
        st.subheader("Encryption Algorithms")
        if not enc_df.empty:
            st.dataframe(enc_df)
            q_counts = enc_df['Quantum Safe'].value_counts().reset_index()
            q_counts.columns = ['Quantum Safe','Count']
            st.altair_chart(
                alt.Chart(q_counts).mark_arc(innerRadius=40).encode(theta='Count:Q', color='Quantum Safe:N'),
                use_container_width=True
            )
        else:
            st.info("No encryption data available.")

    st.success("Analysis complete.")
    st.download_button("Download JSON", json.dumps(data, indent=2), "scanoss_results.json", "application/json")
