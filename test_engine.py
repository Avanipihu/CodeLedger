"""
Unit test suite verifying multi-boundary OSV events, open ranges,
prereleases, explicit versions, and MySQL persistence.
"""
import unittest
from unittest.mock import patch, MagicMock
from matcher import is_vulnerable
from engine import evaluate_osv_events, run_matching_engine

class TestWeaverRemediation(unittest.TestCase):

    def test_prerelease_paradox(self):
        """Confirms 1.2.0a1 is caught as < 1.2.0."""
        self.assertTrue(is_vulnerable("1.2.0a1", "< 1.2.0"))
        self.assertFalse(is_vulnerable("1.2.0", "< 1.2.0"))

    def test_multi_boundary_events_no_cartesian_bleed(self):
        """
        Range has two distinct windows: [1.0.0, 1.2.0) and [2.0.0, 2.1.0).
        Version 1.5.0 lies between them and MUST be safe.
        """
        events = [
            {'event_type': 'introduced', 'event_value': '1.0.0'},
            {'event_type': 'fixed', 'event_value': '1.2.0'},
            {'event_type': 'introduced', 'event_value': '2.0.0'},
            {'event_type': 'fixed', 'event_value': '2.1.0'},
        ]
        self.assertTrue(evaluate_osv_events("1.1.0", events))
        self.assertFalse(evaluate_osv_events("1.5.0", events))
        self.assertTrue(evaluate_osv_events("2.0.5", events))

    def test_zero_intro_without_fix_and_last_affected(self):
        """Tests open-ended ranges starting at 0 and last_affected inclusive bounds."""
        open_events = [{'event_type': 'introduced', 'event_value': '0'}]
        self.assertTrue(evaluate_osv_events("0.0.1", open_events))
        self.assertTrue(evaluate_osv_events("9.9.9", open_events))

        last_aff_events = [
            {'event_type': 'introduced', 'event_value': '1.0.0'},
            {'event_type': 'last_affected', 'event_value': '1.4.2'}
        ]
        self.assertTrue(evaluate_osv_events("1.4.2", last_aff_events))
        self.assertFalse(evaluate_osv_events("1.4.3", last_aff_events))

    @patch('engine.get_mongo_collection')
    @patch('engine.get_mysql_connection')
    def test_end_to_end_engine_and_persistence(self, mock_mysql, mock_mongo):
        """Verifies finding generation from explicit versions and DB commit."""
        mock_conn = MagicMock()
        mock_cursor = MagicMock()
        mock_conn.cursor.return_value.__enter__.return_value = mock_cursor
        mock_mysql.return_value = mock_conn

        # FIX: Provide exactly 6 mock returns for the 6 fetchall() calls in the engine
        mock_cursor.fetchall.side_effect = [
            # 1. fetch_package_vulnerabilities
            [{'vulnerability_id': 'PYSEC-999', 'range_id': None, 'event_id': None, 'event_type': None, 'event_value': None}],
            # 2. _get_table_columns('projects')
            [{'Field': 'project_id'}, {'Field': 'project_name'}],
            # 3. _get_table_columns('scans')
            [{'Field': 'scan_id'}, {'Field': 'project_id'}, {'Field': 'status'}, {'Field': 'started_at'}, {'Field': 'completed_at'}],
            # 4. _get_table_columns('project_dependencies') -> Returns empty, triggers fallback
            [],
            # 5. _get_table_columns('project_dependency') -> The fallback table
            [{'Field': 'project_id'}, {'Field': 'package_name'}, {'Field': 'pinned_version'}],
            # 6. _get_table_columns('scan_findings')
            [{'Field': 'scan_id'}, {'Field': 'dependency_id'}, {'Field': 'vulnerability_id'}, {'Field': 'matched_range_id'}, {'Field': 'match_basis'}]
        ]
        
        mock_cursor.fetchone.return_value = {'project_id': 1}
        mock_cursor.lastrowid = 42

        mock_col = MagicMock()
        mock_mongo.return_value = mock_col
        mock_col.find_one.return_value = {
            "id": "PYSEC-999",
            "summary": "Explicit version vulnerability.",
            "severity": [{"score": "HIGH"}],
            "affected": [{"package": {"name": "flask"}, "versions": ["2.0.1"]}]
        }

        findings = run_matching_engine([("flask", "2.0.1")])
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]['match_basis'], "EXPLICIT_VERSION")
        self.assertTrue(mock_conn.commit.called)

if __name__ == "__main__":
    unittest.main()