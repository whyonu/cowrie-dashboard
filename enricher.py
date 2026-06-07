import asyncio
import aiohttp
import json
import os
from dotenv import load_dotenv
from database import get_db, query

load_dotenv()

VT_KEY = os.getenv('VT_KEY')
DOWNLOADS_DIR = os.getenv('DOWNLOADS_DIR', '/opt/honeypot/cowrie-data/downloads/')


async def fetch_geo(session, ip):
    try:
        async with session.get(f'http://ip-api.com/json/{ip}', timeout=10) as r:
            data = await r.json()
            if data.get('status') != 'success':
                return None
            return {
                'country': data.get('country'),
                'isp': data.get('isp'),
                'lat': data.get('lat'),
                'lon': data.get('lon'),
            }
    except Exception:
        return None


async def fetch_vt(session, sha256):
    if not VT_KEY:
        return None
    try:
        url = f'https://www.virustotal.com/api/v3/files/{sha256}'
        async with session.get(url, headers={"x-apikey": VT_KEY}, timeout=10) as r:
            if r.status != 200:
                return None
            data = await r.json()
    except Exception:
        return None

    attrs = data.get('data', {}).get('attributes', {})
    stats = attrs.get('last_analysis_stats', {})
    classification = attrs.get('popular_threat_classification', {})
    family = classification.get('popular_threat_name', [])
    family_names = [f['value'] if isinstance(f, dict) else f for f in family[:3]]

    return {
        'malicious': stats.get('malicious', 0),
        'total': sum(stats.values()) or None,
        'threat': classification.get('suggested_threat_label'),
        'family': ','.join(family_names) if family_names else None,
    }


async def fetch_bazaar(session, sha256):
    try:
        async with session.post(
            'https://mb-api.abuse.ch/api/v1/',
            data={'query': 'get_info', 'hash': sha256},
            timeout=10
        ) as r:
            if r.status != 200:
                return None
            result = await r.json()
    except Exception:
        return None

    if result.get('query_status') != 'ok':
        return None
    sample = result.get('data', [{}])[0]
    return {'signature': sample.get('signature')}


async def enrich_attackers():
    rows = query("SELECT ip FROM attackers WHERE country IS NULL LIMIT 200")
    if not rows:
        print("  ✅ Все IP уже обогащены")
        return 0

    print(f"  🌍 Обогащаю {len(rows)} IP...")
    semaphore = asyncio.Semaphore(3)

    async def worker(session, ip):
        async with semaphore:
            return ip, await fetch_geo(session, ip)

    async with aiohttp.ClientSession() as session:
        results = await asyncio.gather(*[worker(session, r['ip']) for r in rows])

    updated = 0
    with get_db() as conn:
        for ip, geo in results:
            if geo:
                conn.execute("""
                    UPDATE attackers
                    SET country = ?, isp = ?, lat = ?, lon = ?
                    WHERE ip = ?
                """, (geo['country'], geo['isp'], geo['lat'], geo['lon'], ip))
                updated += 1
    return updated


async def enrich_downloads():
    rows = query("""
        SELECT sha256 FROM downloads
        WHERE vt_total IS NULL OR vt_total = 0
        LIMIT 50
    """)
    if not rows:
        print("  ✅ Все файлы уже обогащены")
        return 0

    print(f"  🦠 Обогащаю {len(rows)} файлов...")
    async with aiohttp.ClientSession() as session:
        for r in rows:
            sha = r['sha256']
            vt = await fetch_vt(session, sha)
            bazaar = await fetch_bazaar(session, sha)

            filepath = os.path.join(DOWNLOADS_DIR, sha)
            size = os.path.getsize(filepath) if os.path.exists(filepath) else None

            with get_db() as conn:
                conn.execute("""
                    UPDATE downloads
                    SET size = ?,
                        vt_malicious = ?, vt_total = ?, vt_threat = ?, vt_family = ?,
                        bazaar_signature = ?
                    WHERE sha256 = ?
                """, (
                    size,
                    vt['malicious'] if vt else None,
                    vt['total'] if vt else None,
                    vt['threat'] if vt else None,
                    vt['family'] if vt else None,
                    bazaar['signature'] if bazaar else None,
                    sha
                ))
    return len(rows)


async def scan_orphan_files():
    if not os.path.exists(DOWNLOADS_DIR):
        return 0

    existing = {r['sha256'] for r in query("SELECT sha256 FROM downloads")}
    added = 0
    with get_db() as conn:
        for fname in os.listdir(DOWNLOADS_DIR):
            if len(fname) == 64 and fname not in existing:
                filepath = os.path.join(DOWNLOADS_DIR, fname)
                if os.path.isfile(filepath):
                    conn.execute("""
                        INSERT OR IGNORE INTO downloads (sha256, size)
                        VALUES (?, ?)
                    """, (fname, os.path.getsize(filepath)))
                    added += 1
    return added


async def main():
    print("🚀 Enricher\n")

    print("📁 Поиск файлов-сирот в /downloads/")
    orphans = await scan_orphan_files()
    print(f"  ➕ Добавлено: {orphans}\n")

    print("🌍 Обогащение IP")
    geo_count = await enrich_attackers()
    print(f"  ✅ Обновлено: {geo_count}\n")

    print("🦠 Обогащение файлов (VT + Bazaar)")
    file_count = await enrich_downloads()
    print(f"  ✅ Обновлено: {file_count}")


if __name__ == "__main__":
    asyncio.run(main())
