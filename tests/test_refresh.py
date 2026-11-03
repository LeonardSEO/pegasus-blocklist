import datetime as dt
import json
import pathlib
import tempfile
import time
import unittest
from unittest.mock import patch
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / 'scripts'))
import refresh


class RefreshTests(unittest.TestCase):
    def test_empty_or_non_domain_source_is_rejected(self):
        for data in [b'', b'# empty\n', b'0.0.0.0 example.org\n', b'https://example.org/path\n', b'192.0.2.1\n']:
            with self.subTest(data=data), self.assertRaises(ValueError):
                refresh.validate_feed(data)

    def test_invalid_source_does_not_overwrite_previous_snapshot(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            (root / 'sources').mkdir()
            refresh.sync_source(b'known.example.org\n', root, '2026-11-03')
            before = {p.name: p.read_bytes() for p in (root / 'sources').iterdir()}
            with self.assertRaises(ValueError):
                refresh.sync_source(b'known.example.org\n<script>\n', root, 'later')
            self.assertEqual(before, {p.name: p.read_bytes() for p in (root / 'sources').iterdir()})

    def test_unchanged_source_retains_snapshot_timestamp(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            (root / 'sources').mkdir()
            refresh.sync_source(b'KNOWN.example.org\nknown.example.org\n', root, 'first')
            refresh.sync_source(b'KNOWN.example.org\nknown.example.org\n', root, 'second')
            data = json.loads((root / 'sources/provenance.json').read_text())
            self.assertEqual(data['snapshot_updated_at'], 'first')
            self.assertEqual(data['domain_count'], 1)
            self.assertEqual(len(data['sha256']), 64)

    def test_source_byte_change_updates_digest_even_when_domains_are_identical(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            (root / 'sources').mkdir()
            refresh.sync_source(b'known.example.org\n', root, 'first')
            first = json.loads((root / 'sources/provenance.json').read_text())
            refresh.sync_source(b'known.example.org\n\n', root, 'second')
            second = json.loads((root / 'sources/provenance.json').read_text())
            self.assertNotEqual(first['sha256'], second['sha256'])
            self.assertEqual(second['snapshot_updated_at'], 'second')

    def test_network_outage_keeps_source_and_writes_partial_report(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            (root / 'sources').mkdir()
            (root / 'candidates').mkdir()
            refresh.sync_source(b'known.example.org\n', root, 'first')
            before = (root / 'sources/amnesty-pegasus.txt').read_bytes()
            result = {'candidates': {}, 'publications': [], 'errors': [], 'planned_queries': [], 'attempted_queries': []}
            with patch.object(refresh, 'ROOT', root), \
                 patch.object(sys, 'argv', ['refresh.py', '--max-seconds', '10']), \
                 patch.object(refresh, 'fetch', side_effect=TimeoutError('offline')), \
                 patch.object(refresh, 'load_domains', return_value={'known.example.org': 'pegasus'}), \
                 patch.object(refresh, 'research', return_value=result):
                with self.assertRaises(SystemExit) as error:
                    refresh.main()
            self.assertEqual(error.exception.code, 3)
            self.assertEqual((root / 'sources/amnesty-pegasus.txt').read_bytes(), before)
            report = json.loads((root / 'candidates/latest.json').read_text())
            self.assertEqual(report['status'], 'partial')
            self.assertEqual(report['source']['status'], 'unavailable; retained previous validated snapshot')

    def test_rotating_seeds_cover_full_dataset(self):
        domains = [f'd{i}.example.org' for i in range(50)]
        day = dt.date(2026, 11, 3)
        selected = set()
        for offset in range(3):
            seeds = refresh.select_seeds(domains, day + dt.timedelta(days=offset))
            self.assertEqual(len(seeds), 24)
            selected.update(seeds)
        self.assertEqual(selected, set(domains))
        self.assertEqual(refresh.select_seeds([], day), [])

    def test_san_pivot_discovers_new_unrelated_domain_but_requires_known_anchor(self):
        rows = [{'id': 1, 'name_value': '*.known.example.org\nnew-infrastructure.example.net'},
                {'id': 2, 'name_value': 'unrelated.example.com'}]
        found = refresh.certificate_names(rows, 'known.example.org')
        self.assertIn('new-infrastructure.example.net', found)
        self.assertNotIn('unrelated.example.com', found)
        self.assertIn('unverified', found['new-infrastructure.example.net'][0]['meaning'])

    def test_publications_filter_topic_and_trusted_host(self):
        data = b'<rss><channel><item><title>Pegasus research</title><link>https://citizenlab.ca/research/test/</link></item><item><title>Unrelated</title><link>https://citizenlab.ca/other/</link></item><item><title>NSO Group</title><link>https://evil.example/</link></item></channel></rss>'
        self.assertEqual(len(refresh.publications(data, 'https://citizenlab.ca/feed/')), 1)

    def test_research_preserves_errors_and_never_flags_publishers(self):
        def response(url, deadline, **kwargs):
            if 'crt.sh' in url:
                raise TimeoutError('offline')
            if 'urlscan.io' in url:
                return json.dumps({'results': [{'page': {'domain': 'innocent-publisher.example.net'}},
                                             {'page': {'domain': 'child.known.example.org'}}]}).encode()
            if 'dns-query' in url:
                self.assertEqual(kwargs['accept'], 'application/dns-json')
                return b'{"Status":0,"Answer":[]}'
            return b'<rss><channel/></rss>'
        with patch.object(refresh, 'fetch', side_effect=response), patch.object(refresh.time, 'sleep'):
            report = refresh.research({'known.example.org'}, set(), ['known.example.org'], time.monotonic()+20)
        self.assertEqual(len(report['errors']), 1)
        self.assertEqual(report['candidates'], {})
        self.assertEqual(report['observations'][0]['domain'], 'child.known.example.org')
        self.assertIn('dns:known.example.org', report['completed_queries'])

    def test_allowlist_and_known_names_are_not_candidates(self):
        def response(url, deadline, **kwargs):
            if 'crt.sh' in url:
                return b'[{"name_value":"known.example.org\\nshared.example.net\\nnew.example.net"}]'
            if 'urlscan.io' in url:
                return b'{"results":[]}'
            if 'dns-query' in url:
                return b'{"Status":0}'
            return b'<rss/>'
        with patch.object(refresh, 'fetch', side_effect=response), patch.object(refresh.time, 'sleep'):
            report = refresh.research({'known.example.org'}, {'shared.example.net'}, ['known.example.org'], time.monotonic()+20)
        self.assertEqual(set(report['candidates']), {'new.example.net'})

    def test_deadline_records_unattempted_coverage(self):
        report = refresh.research({'known.example.org'}, set(), ['known.example.org'], time.monotonic()-1)
        self.assertFalse(report['attempted_queries'])
        self.assertTrue(report['errors'])
        self.assertTrue(report['planned_queries'])


if __name__ == '__main__':
    unittest.main()
