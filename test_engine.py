"""
test_engine.py
Validates the Logic Weaver's cross-database engine offline.
"""
import unittest
from unittest.mock import patch, MagicMock
from engine import run_matching_engine

class TestMatchingEngine(unittest.TestCase):
    
    @patch('engine.get_mongo_collection')
    @patch('engine.get_mysql_connection')
    def test_vulnerable_package_detection(self, mock_mysql, mock_mongo):
        """Simulates a vulnerable hit requiring a dual-database lookup."""
        # 1. Mock the Relational Core (MySQL)
        mock_conn = MagicMock()
        mock_cursor = MagicMock()
        mock_conn.cursor.return_value.__enter__.return_value = mock_cursor
        mock_mysql.return_value = mock_conn
        
        # Fake a database row returning a vulnerable range (1.0 to 2.0)
        mock_cursor.fetchall.return_value = [{
            'vulnerability_id': 'GHSA-1234',
            'introduced_version': '1.0.0',
            'fixed_version': '2.0.0'
        }]
        
        # 2. Mock the Document Vault (MongoDB)
        mock_col = MagicMock()
        mock_mongo.return_value = mock_col
        mock_col.find_one.return_value = {
            "id": "GHSA-1234",
            "summary": "Mock vulnerability injected for testing.",
            "severity": [{"score": "CRITICAL"}]
        }
        
        # 3. Cast the spell with a known vulnerable version
        packages = [("requests", "1.5.0")]
        findings = run_matching_engine(packages)
        
        # 4. Validate the timeline
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]['package_name'], "requests")
        self.assertEqual(findings[0]['vulnerability_id'], "GHSA-1234")
        self.assertEqual(findings[0]['severity'], "CRITICAL")
        self.assertEqual(findings[0]['summary'], "Mock vulnerability injected for testing.")

    @patch('engine.get_mongo_collection')
    @patch('engine.get_mysql_connection')
    def test_safe_package_detection(self, mock_mysql, mock_mongo):
        """Simulates a safe version bypassing the MongoDB query."""
        mock_conn = MagicMock()
        mock_cursor = MagicMock()
        mock_conn.cursor.return_value.__enter__.return_value = mock_cursor
        mock_mysql.return_value = mock_conn
        
        mock_cursor.fetchall.return_value = [{
            'vulnerability_id': 'GHSA-1234',
            'introduced_version': '1.0.0',
            'fixed_version': '2.0.0'
        }]
        
        # Version 2.1.0 falls safely outside the dangerous < 2.0.0 boundary
        packages = [("requests", "2.1.0")]
        findings = run_matching_engine(packages)
        
        self.assertEqual(len(findings), 0)

if __name__ == '__main__':
    unittest.main()