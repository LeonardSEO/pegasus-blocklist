#!/usr/bin/env python3
"""Sync trusted Pegasus indicators and record bounded passive research leads."""
from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import pathlib
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET

from build import ROOT, ALLOWLIST, DOMAIN_RE, load_domains, parse

SOURCE_URL = 'https://raw.githubusercontent.com/AmnestyTech/investigations/master/2021-07-18_nso/domains.txt'
FEEDS = ['https://securitylab.amnesty.org/feed/', 'https://citizenlab.ca/feed/']
SEED_LIMIT = 24  # Bounded public API traffic; rotate across the full source set daily.
NETWORK_ERRORS = (urllib.error.URLError, OSError, TimeoutError)


def fetch(url: str, deadline: float, *, accept: str | None = None) -> bytes:
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise TimeoutError('research time budget reached')
    headers = {'User-Agent': 'pegasus-blocklist/1.0 (passive defensive research)'}
    if accept:
        headers['Accept'] = accept
    request = urllib.request.Request(url, headers=headers)
    with urllib.request.urlopen(request, timeout=min(15, remaining)) as response:
        return response.read()


def validate_feed(data: bytes) -> list[str]:
    domains = set()
    for number, line in enumerate(data.decode('utf-8').splitlines(), 1):
        domain = line.strip().lower()
        if not domain or domain.startswith('#'):
            continue
        if not DOMAIN_RE.fullmatch(domain):
            raise ValueError(f'Invalid trusted source domain on line {number}: {domain!r}')
        domains.add(domain)
    if not domains:
        raise ValueError('Refusing an empty trusted domain feed')
    return sorted(domains)


def sync_source(data: bytes, root: pathlib.Path, stamp: str) -> int:
    domains = validate_feed(data)
    content = '# Source: ' + SOURCE_URL + '\n# Historical published Pegasus indicators; current ownership/activity unverified.\n'
    content += ''.join(f'{domain} # pegasus: Amnesty published indicator\n' for domain in domains)
    destination = root / 'sources/amnesty-pegasus.txt'
    provenance = root / 'sources/provenance.json'
    digest = hashlib.sha256(data).hexdigest()
    content_changed = not destination.exists() or destination.read_text(encoding='utf-8') != content
    previous_digest = json.loads(provenance.read_text(encoding='utf-8')).get('sha256') if provenance.exists() else None
    if content_changed:
        destination.write_text(content, encoding='utf-8')
    if content_changed or previous_digest != digest:
        provenance.write_text(json.dumps({
            'source_url': SOURCE_URL, 'sha256': digest,
            'domain_count': len(domains), 'snapshot_updated_at': stamp,
            'scope': 'Published historical attribution; not current malicious activity verification.'
        }, indent=2) + '\n', encoding='utf-8')
    return len(domains)


def select_seeds(domains: list[str], day: dt.date) -> list[str]:
    if not domains:
        return []
    ordered = sorted(set(domains))
    start = (day.toordinal() * SEED_LIMIT) % len(ordered)
    return [ordered[(start + i) % len(ordered)] for i in range(min(SEED_LIMIT, len(ordered)))]


def certificate_names(rows: list[dict], seed: str) -> dict[str, list[dict]]:
    found: dict[str, list[dict]] = {}
    for row in rows:
        names = set()
        for raw in (row.get('name_value', '') + '\n' + row.get('common_name', '')).splitlines():
            name = raw.strip().lower().removeprefix('*.').rstrip('.')
            if DOMAIN_RE.fullmatch(name):
                names.add(name)
        # A search hit alone is not evidence: require an explicit known name on the certificate.
        if not any(name == seed or name.endswith('.' + seed) for name in names):
            continue
        for name in sorted(names):
            found.setdefault(name, []).append({'kind': 'certificate-san', 'seed': seed,
                'certificate_id': row.get('id'), 'not_before': row.get('not_before'),
                'meaning': 'Co-occurring certificate name; ownership and Pegasus attribution unverified.'})
    return found


def publications(data: bytes, feed: str) -> list[dict]:
    root = ET.fromstring(data)
    found = []
    for item in root.findall('.//item'):
        title, link = item.findtext('title', ''), item.findtext('link', '')
        text = title + ' ' + item.findtext('description', '')
        if not any(term in text.lower() for term in ('pegasus', 'nso group')):
            continue
        parsed = urllib.parse.urlsplit(link)
        if parsed.scheme != 'https' or parsed.hostname != urllib.parse.urlsplit(feed).hostname:
            continue
        found.append({'title': title, 'url': link, 'published': item.findtext('pubDate', ''), 'feed': feed})
    return found


def research(known: set[str], allowed: set[str], seeds: list[str], deadline: float) -> dict:
    result = {'candidates': {}, 'observations': [], 'publications': [], 'errors': [], 'completed_queries': [], 'attempted_queries': []}
    tasks = [(f'news:{feed}', 'news', feed, feed) for feed in FEEDS]
    # Interleave services for each seed, so early seeds receive corroborating observations.
    for seed in seeds:
        tasks.extend([
            (f'ct:{seed}', 'ct', seed, 'https://crt.sh/?' + urllib.parse.urlencode({'q': '%.' + seed, 'output': 'json'})),
            (f'urlscan:{seed}', 'urlscan', seed, 'https://urlscan.io/api/v1/search/?' + urllib.parse.urlencode({'q': 'page.domain:' + seed, 'size': 100})),
            (f'dns:{seed}', 'dns', seed, 'https://cloudflare-dns.com/dns-query?' + urllib.parse.urlencode({'name': seed, 'type': 'CNAME'})),
        ])
    result['planned_queries'] = [task[0] for task in tasks]
    for index, (label, kind, seed, url) in enumerate(tasks):
        now = time.monotonic()
        if now >= deadline:
            result['errors'].append({'query': label, 'error': 'Overall research time budget reached; remaining queries unattempted.'})
            break
        # Reserve a fair share for every remaining query instead of letting CT starve DNS/news.
        query_deadline = min(deadline, now + max(0.1, (deadline - now) / (len(tasks) - index)))
        result['attempted_queries'].append(label)
        try:
            data = fetch(url, query_deadline, accept='application/dns-json' if kind == 'dns' else None)
            if kind == 'news':
                result['publications'].extend(publications(data, seed))
            elif kind == 'ct':
                for domain, evidence in certificate_names(json.loads(data), seed).items():
                    if domain not in known and domain not in allowed:
                        result['candidates'].setdefault(domain, []).extend(evidence)
            elif kind == 'urlscan':
                for row in json.loads(data).get('results', []):
                    page = row.get('page', {})
                    domain = page.get('domain', '').lower().rstrip('.')
                    # Do not turn publishers that loaded a resource into suspected infrastructure.
                    if DOMAIN_RE.fullmatch(domain) and (domain == seed or domain.endswith('.' + seed)):
                        result['observations'].append({'kind': 'existing-urlscan', 'seed': seed,
                            'domain': domain, 'ip': page.get('ip'), 'result': row.get('result')})
            else:
                answers = json.loads(data)
                if answers.get('Status') not in (0, 3):
                    raise ValueError('DNS resolver returned an error status')
                result['observations'].append({'kind': 'dns-cname', 'seed': seed,
                    'dns_status': answers.get('Status'), 'answers': answers.get('Answer', [])})
            result['completed_queries'].append(label)
        except (NETWORK_ERRORS + (ValueError, ET.ParseError)) as error:
            result['errors'].append({'query': label, 'error': f'{type(error).__name__}: {error}'})
        # Respect public-service pacing even on fast responses.
        time.sleep(min(1, max(0, deadline - time.monotonic())))
    return result


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--max-seconds', type=int, default=600)
    args = parser.parse_args()
    if not 1 <= args.max_seconds <= 900:
        parser.error('--max-seconds must be between 1 and 900')
    started = time.monotonic()
    now = dt.datetime.now(dt.timezone.utc)
    stamp = now.isoformat()
    source_errors = []
    try:
        count = sync_source(fetch(SOURCE_URL, started + min(30, args.max_seconds)), ROOT, stamp)
        source_state = {'status': 'checked', 'domains': count}
    except NETWORK_ERRORS as error:
        source_errors.append({'query': 'trusted-source', 'error': f'{type(error).__name__}: {error}'})
        source_state = {'status': 'unavailable; retained previous validated snapshot'}
    known = set(load_domains())
    seeds = select_seeds(sorted(known), now.date())
    report = research(known, set(parse(ALLOWLIST)), seeds, started + args.max_seconds)
    report['errors'] = source_errors + report['errors']
    report.update({'observed_at': stamp, 'source': source_state, 'seeds': seeds,
        'status': 'partial' if report['errors'] else 'completed',
        'unattempted_queries': sorted(set(report['planned_queries']) - set(report['attempted_queries'])),
        'limitations': 'At most 24 rotating seeds/day and first API result pages; a lead is not Pegasus attribution. Source age differs from build/observation time.'})
    (ROOT / 'candidates/latest.json').write_text(json.dumps(report, indent=2, sort_keys=True) + '\n', encoding='utf-8')
    print(f'{report["status"]}: {len(report["candidates"])} unapproved candidates; {len(report["publications"])} relevant publication links')
    if report['errors']:
        sys.exit(3)


if __name__ == '__main__':
    main()
