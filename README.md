# Cowrie Monitor Platform

Real-time web dashboard for threat analysis.

Captures attacks from internet, analyzes malware samples, identifies botnet patterns, and provides comprehensive threat intelligence.

## Features

- 🔥 **Cowrie SSH honeypot** integration
- 📊 **Streamlit web dashboard** with real-time analytics
- 🦠 **VirusTotal & MalwareBazaar** integration
- 🎯 **IOC extraction** from captured malware (URLs, IPs)
- 🌍 **GeoIP mapping** of attackers
- 🎬 **Session replay** of attacker activities
- 🎭 **Pattern detection** to analyze activity

## Setup

1. Copy `.env.example` to `.env` and fill in your credentials
2. Install dependencies: `pip install -r requirements.txt`
3. Run dashboard: `streamlit run dashboard.py`

## License

MIT
