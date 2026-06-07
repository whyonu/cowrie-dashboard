import streamlit as st
from streamlit_extras.metric_cards import style_metric_cards
import pandas as pd
import asyncio
from collections import Counter
from analyze import get_all_data
from datetime import datetime
import os
from dotenv import load_dotenv

load_dotenv()

COWRIE_CONTAINER = os.getenv('COWRIE_CONTAINER', 'cowrie_honeypot')
COWRIE_TTY_PATH = os.getenv('COWRIE_TTY_PATH', '/cowrie/cowrie-git/var/lib/cowrie/tty')
COWRIE_PYTHON = os.getenv('COWRIE_PYTHON', '/cowrie/cowrie-env/bin/python')
COWRIE_PLAYLOG = os.getenv('COWRIE_PLAYLOG', '/cowrie/cowrie-git/src/cowrie/scripts/playlog.py')

st.set_page_config(
    page_title="Honeypot Monitor",
    page_icon="📡",
    layout="wide",
    initial_sidebar_state="collapsed"
)

st.markdown("""
<style>
    /* Уменьшить padding сверху */
    .block-container {
        padding-top: 2rem;
    }
    
    /* Кастомные карточки метрик */
    [data-testid="stMetricValue"] {
        font-size: 2.2rem;
        font-weight: 700;
    }
    
    [data-testid="stMetricLabel"] {
        font-size: 0.9rem;
        opacity: 0.8;
    }
    
    /* Анимация для delta */
    [data-testid="stMetricDelta"] {
        font-weight: 600;
    }
    
    /* Subheader красивее */
    h3 {
        font-weight: 700;
        margin-top: 1.5rem;
    }
    
    /* Контейнеры с лёгкой тенью */
    [data-testid="stExpander"] {
        border: 1px solid #2d3142;
        border-radius: 8px;
    }
</style>
""", unsafe_allow_html=True)

@st.cache_data(ttl=10)
def load_data():
    return get_all_data()

col_title, col_btn = st.columns([4, 1])
with col_title:
    st.title("📡 Honeypot Monitor")
    st.caption("Real-time SSH honeypot threat intelligence")
with col_btn:
    st.write("")
    st.write("")
    if st.button("🔄 Refresh", use_container_width=True):
        st.cache_data.clear()
        st.rerun()

@st.fragment(run_every="3s")
def live_metrics():
    from database import query_one
    summary = query_one("""
        SELECT
            (SELECT COUNT(*) FROM events WHERE event_type='cowrie.session.connect') as attacks,
            (SELECT COUNT(*) FROM attackers) as ips,
            (SELECT COUNT(*) FROM login_attempts) as logins,
            (SELECT COUNT(*) FROM downloads) as files
    """)
    
    if 'prev_stats' not in st.session_state:
        st.session_state.prev_stats = summary
    prev = st.session_state.prev_stats
    
    def delta_html(current, previous):
        diff = current - previous
        if diff > 0:
            return f'<div style="color:#51cf66;font-size:0.9rem;font-weight:600;margin-top:4px">▲ +{diff}</div>'
        return '<div style="height:24px"></div>'
    
    def card(icon, label, value, delta):
        return f"""
        <div style="
            background: linear-gradient(135deg, #1a1d29 0%, #232735 100%);
            border: 1px solid #2d3142;
            border-radius: 12px;
            padding: 1.2rem 1.4rem;
            box-shadow: 0 4px 12px rgba(0,0,0,0.3);
            height: 130px;
            display: flex;
            flex-direction: column;
            justify-content: space-between;
        ">
            <div style="color:#8b8fa3;font-size:0.85rem;font-weight:500;letter-spacing:0.5px;text-transform:uppercase;">
                {icon} {label}
            </div>
            <div>
                <div style="color:#ffffff;font-size:2.2rem;font-weight:700;line-height:1;">
                    {value:,}
                </div>
                {delta}
            </div>
        </div>
        """
    
    col1, col2, col3, col4 = st.columns(4)
    col1.markdown(card("🔥", "Total attacks", summary['attacks'], delta_html(summary['attacks'], prev['attacks'])), unsafe_allow_html=True)
    col2.markdown(card("🌐", "Unique IPs", summary['ips'], delta_html(summary['ips'], prev['ips'])), unsafe_allow_html=True)
    col3.markdown(card("🔑", "Login attempts", summary['logins'], delta_html(summary['logins'], prev['logins'])), unsafe_allow_html=True)
    col4.markdown(card("📁", "Files", summary['files'], delta_html(summary['files'], prev['files'])), unsafe_allow_html=True)
    
    st.session_state.prev_stats = summary

live_metrics()
data = load_data()

st.divider()

@st.fragment(run_every="5s")
def live_top_ips():
    from analyze import get_attackers, get_ip_counts
    
    st.subheader("🚨 Top attacking IPs")
    attackers = get_attackers()
    ip_counts = get_ip_counts()
    
    top_ips = sorted(ip_counts.items(), key=lambda x: x[1], reverse=True)[:10]
    df_ips = pd.DataFrame([
        {
            "IP": ip,
            "Country": attackers.get(ip, {}).get("country", "?"),
            "ISP": attackers.get(ip, {}).get("isp", "?"),
            "Attacks": count
        }
        for ip, count in top_ips
    ])
    st.dataframe(df_ips, hide_index=True, use_container_width=True)


@st.fragment(run_every="5s")
def live_passwords():
    from analyze import get_top_passwords
    import plotly.express as px
    
    st.subheader("🔑 Top passwords")
    
    df_pwd = pd.DataFrame(get_top_passwords(15), columns=["Password", "Count"])
    df_pwd = df_pwd.sort_values("Count", ascending=True)
    
    fig = px.bar(
        df_pwd,
        x="Count",
        y="Password",
        orientation='h',
        height=450,
    )
    fig.update_traces(
        marker_color="#ff6b6b",
        texttemplate="%{x:,}",
        textposition='outside',
        hovertemplate="<b>%{y}</b><br>Tried %{x} times<extra></extra>",
    )
    fig.update_layout(
        plot_bgcolor="rgba(0,0,0,0)",
        paper_bgcolor="rgba(0,0,0,0)",
        showlegend=False,
        margin=dict(l=0, r=40, t=20, b=0),
        xaxis=dict(
            title=None,
            gridcolor="#2d3142",
            showgrid=True,
            tickformat=",d",
        ),
        yaxis=dict(
            title=None,
            tickfont=dict(size=12),
            type='category',
        ),
    )
    
    st.plotly_chart(fig, use_container_width=True)
        
        
col_left, col_right = st.columns(2)
with col_left:
    live_top_ips()
with col_right:
    live_passwords()
    
@st.fragment(run_every="10s")
def live_timeline():
    from analyze import get_attacks_timeline
    import plotly.graph_objects as go
    
    st.subheader("📈 Attacks over last 24h")
    
    timeline = get_attacks_timeline(24)
    if not timeline:
        st.info("No timeline data yet")
        return
    
    df_tl = pd.DataFrame(timeline, columns=["Hour", "Attacks"])
    
    fig = go.Figure()
    fig.add_trace(go.Scatter(
        x=df_tl["Hour"],
        y=df_tl["Attacks"],
        mode='lines',
        line=dict(color="#ff6b6b", width=3, shape="spline"),
        fill='tozeroy',
        fillcolor='rgba(255, 107, 107, 0.2)',
        hovertemplate="<b>%{x}</b><br>%{y} attacks<extra></extra>"
    ))
    fig.update_layout(
        plot_bgcolor="rgba(0,0,0,0)",
        paper_bgcolor="rgba(0,0,0,0)",
        height=350,
        margin=dict(l=0, r=0, t=20, b=0),
        xaxis=dict(title=None, gridcolor="#2d3142"),
        yaxis=dict(title=None, gridcolor="#2d3142"),
        hovermode='x unified',
    )
    
    st.plotly_chart(fig, use_container_width=True)

live_timeline()

st.subheader("🌍 Attack geography")

country_attacks = {}
for ip, info in data["attackers"].items():
    c = info.get("country", "Unknown")
    country_attacks[c] = country_attacks.get(c, 0) + data["ip_count"].get(ip, 0)

df_countries = pd.DataFrame(
    sorted(country_attacks.items(), key=lambda x: x[1], reverse=True),
    columns=["Country", "Attacks"]
)

col_chart, col_map = st.columns([1, 1])
with col_chart:
    st.markdown("##### Attacks by country")
    st.bar_chart(df_countries.set_index("Country").head(15), color="#4dabf7")

with col_map:
    st.markdown("##### Live map")
    map_data = pd.DataFrame([
        {"lat": info["lat"], "lon": info["lon"]}
        for info in data["attackers"].values()
        if info.get("lat") and info.get("lon")
    ])
    st.map(map_data, zoom=0)

st.divider()

st.subheader("🦠 Malware analysis")

if data["downloads"]:
    unique_files = {}
    for d in data["downloads"]:
        sha = d.get('sha256') or d.get('shasum')
        if sha and sha not in unique_files:
            unique_files[sha] = d

    col1, col2, col3, col4 = st.columns(4)
    col1.metric("📊 Download attempts", len(data["downloads"]))
    col2.metric("🔸 Unique samples", len(unique_files))

    total_size = sum(d.get('size', 0) for d in unique_files.values())
    col3.metric("💾 Total size", f"{round(total_size / 1024 / 1024, 1)} MB")

    malicious_count = sum(
        1 for d in unique_files.values()
        if d.get('vt') and d['vt'].get('malicious', 0) > 5
    )
    col4.metric("🔴 Confirmed malware", malicious_count)

    st.markdown("")

    for sha, d in unique_files.items():
        vt = d.get('vt')

        with st.container(border=True):
            col_info, col_vt = st.columns([2, 1])

            with col_info:
                ftype = d.get('file_type', 'Unknown')
                size_kb = round(d.get('size', 0) / 1024, 1)
                ip = d.get('src_ip', 'unknown')

                if vt and vt.get('malicious', 0) > 20:
                    indicator = "🔴"
                    status = "**MALWARE**"
                elif vt and vt.get('malicious', 0) > 0:
                    indicator = "🟡"
                    status = "**Suspicious**"
                else:
                    indicator = "🟢"
                    status = "Unknown / clean"

                st.markdown(f"### {indicator} {status}")
                st.markdown(f"**Type:** `{ftype}`")
                st.markdown(f"**Size:** `{size_kb} KB`")
                st.markdown(f"**From IP:** `{ip}`")
                st.code(sha, language=None)

            with col_vt:
                if vt:
                    mal = vt.get('malicious', 0)
                    total = vt.get('total', 0)
                    pct = round(mal / total * 100) if total else 0
                    st.metric("🔬 VT detections", f"{mal}/{total}", f"{pct}%")

                    if vt.get('threat_label'):
                        st.markdown(f"**Threat:** `{vt['threat_label']}`")

                    family = vt.get('family', [])
                    if family:
                        family_names = [f['value'] if isinstance(f, dict) else f for f in family[:3]]
                        st.markdown(f"**Family:** {', '.join(family_names)}")

                    vt_url = f"https://www.virustotal.com/gui/file/{sha}"
                    st.markdown(f"[🔗 View on VirusTotal]({vt_url})")
                else:
                    st.info("⚪ No VirusTotal data")
else:
    st.info("📭 No files downloaded yet")

st.divider()

st.subheader("🎯 Detected attack patterns")

patterns = data.get("patterns", [])
if not patterns:
    st.info("No patterns detected")
else:
    st.caption(f"Found {len(patterns)} pattern(s) — groups of attackers running identical command sequences (likely the same botnet)")

    for i, p in enumerate(patterns[:10], 1):
        with st.expander(
            f"🎭 Pattern #{i} — {p['unique_ips']} IPs · {p['total_attacks']} attacks"
        ):
            st.markdown("**Command signature:**")
            for cmd in p['signature']:
                st.code(cmd, language="bash")

            st.markdown("**Attackers in this cluster:**")
            df_p = pd.DataFrame(p['attackers'])
            df_p.columns = [c.capitalize() for c in df_p.columns]
            st.dataframe(df_p, hide_index=True, use_container_width=True)

st.divider()

st.subheader("🎯 Indicators of Compromise")

all_urls = set()
all_ips = set()
all_domains = set()
all_webhooks = set()

for d in data["downloads"]:
    iocs = d.get('iocs', {})
    all_urls.update(iocs.get('urls', []))
    all_ips.update(iocs.get('ips', []))
    all_domains.update(iocs.get('domains', []))
    all_webhooks.update(iocs.get('discord_webhooks', []))

all_urls.update(all_webhooks)

if not (all_urls or all_ips or all_domains):
    st.info("📭 No IOCs extracted")
else:
    col1, col2, col3 = st.columns(3)
    col1.metric("🔗 URLs", len(all_urls))
    col2.metric("🌐 IPs", len(all_ips))
    col3.metric("📝 Domains", len(all_domains))

    st.caption("Extracted from malware binaries via static string analysis")

    tab_urls, tab_ips, tab_domains = st.tabs(["🔗 URLs", "🌐 IPs", "📝 Domains"])

    with tab_urls:
        if all_urls:
            df_urls = pd.DataFrame({"URL": sorted(all_urls)})
            st.dataframe(df_urls, hide_index=True, use_container_width=True)
        else:
            st.info("No URLs")

    with tab_ips:
        if all_ips:
            df_ips_iocs = pd.DataFrame({"IP": sorted(all_ips)})
            st.dataframe(df_ips_iocs, hide_index=True, use_container_width=True)
        else:
            st.info("No IPs")

    with tab_domains:
        if all_domains:
            df_domains = pd.DataFrame({"Domain": sorted(all_domains)})
            st.dataframe(df_domains, hide_index=True, use_container_width=True)
        else:
            st.info("No domains")

st.divider()

st.subheader("🎬 Recorded attacker sessions")

tty = data.get("tty_sessions", [])
if not tty:
    st.info("📭 No sessions recorded")
else:
    total_duration = sum(s['duration_log'] for s in tty)
    matched = sum(1 for s in tty if s['src_ip'] != 'unknown')

    col1, col2, col3, col4 = st.columns(4)
    col1.metric("🎬 Total sessions", len(tty))
    col2.metric("🔗 Linked to IP", f"{matched}/{len(tty)}")
    col3.metric("⏱ Total duration", f"{round(total_duration, 1)}s")
    col4.metric("📦 Total size", f"{round(sum(s['size_kb'] for s in tty), 1)} KB")

    longest = sorted(tty, key=lambda x: x['duration_log'], reverse=True)[:5]

    st.markdown("##### 🔥 Longest sessions")
    df_top = pd.DataFrame([
        {
            "IP": s['src_ip'],
            "Country": s['country'],
            "Duration (s)": round(s['duration_log'], 1),
            "Size (KB)": s['size_kb'],
            "TTY file": s['session_id']
        }
        for s in longest
    ])
    st.dataframe(df_top, hide_index=True, use_container_width=True)

    st.markdown("##### ▶️ Replay a session")
    selected_tty = st.selectbox(
        "Select session",
        options=[s['session_id'] for s in tty],
        format_func=lambda x: f"{next((s['src_ip'] for s in tty if s['session_id'] == x), '?')} · {x[:20]}..."
    )

    if st.button("▶️ Generate replay command"):
        cmd = (
            f"docker exec {COWRIE_CONTAINER} {COWRIE_PYTHON} "
            f"{COWRIE_PLAYLOG} -m 1 "
            f"{COWRIE_TTY_PATH}/{selected_tty}"
        )
        st.code(cmd, language="bash")

    with st.expander(f"📋 All sessions ({len(tty)})"):
        df_all = pd.DataFrame([
            {
                "IP": s['src_ip'],
                "Country": s['country'],
                "Duration (s)": round(s['duration_log'], 1),
                "Size (KB)": s['size_kb'],
                "Time": datetime.fromtimestamp(s['modified']).strftime("%Y-%m-%d %H:%M"),
                "Session": s['session_id_short'] or '?'
            }
            for s in tty
        ])
        st.dataframe(df_all, hide_index=True, use_container_width=True)
