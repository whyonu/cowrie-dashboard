# Cowrie Monitor

Real-time dashboard for analyzing attacks captured by a Cowrie SSH honeypot. Parses logs, geolocates attackers, analyzes downloaded malware via VirusTotal and MalwareBazaar, and clusters botnets by behavior.

## Features

- Real-time stats updated every few seconds via Streamlit fragments
- SQLite database with incremental log parsing
- Geo-mapping of attackers
- VirusTotal and MalwareBazaar lookups for captured files
- IOC extraction from malware binaries (URLs, IPs, domains)
- Session replay command generator for Cowrie TTY recordings
- Pattern detection to identify botnet activity by shared command sequences

## Requirements

- Python 3.10+
- A running [Cowrie honeypot](https://github.com/cowrie/cowrie) (Docker or native)
- VirusTotal API key (free tier works) — optional but recommended
- Linux server (uses systemd for background workers)

## Setup

1. Clone the repo:
```bash
   git clone https://github.com/whyonu/cowrie-dashboard.git
   cd cowrie-dashboard
```

2. Copy `.env.example` to `.env` and fill in your paths and API keys.

3. Install dependencies:
```bash
   pip install -r requirements.txt
```

4. Initialize the database:
```bash
   python3 migrations.py
```

5. Parse existing logs into the database:
```bash
   python3 ingest.py
```

6. Enrich data with geo and threat intel (run a few times — APIs rate-limit):
```bash
   python3 enricher.py
```

7. Launch the dashboard:
```bash
   streamlit run dashboard.py
```

## Running in the background

For continuous operation, set up systemd timers for `ingest.py` (every 30s) and `enricher.py` (every 5 minutes). Example unit files are in the repo discussion.

## Architecture

- `ingest.py` — incremental log parser, writes to SQLite
- `enricher.py` — fetches geo (ip-api), VirusTotal, and MalwareBazaar data
- `analyze.py` — SQL queries for the dashboard
- `dashboard.py` — Streamlit UI
- `database.py` — SQLite connection layer
- `migrations.py` — schema versioning

## Notes

- Without a VirusTotal API key, malware analysis section will be limited
- The dashboard expects Cowrie's JSON output format (`cowrie.json`)
- TTY session replay requires running Cowrie in Docker (configurable via `.env`)

## License

MIT
