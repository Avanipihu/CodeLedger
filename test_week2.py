"""
test_week2.py -- The Crucible
Exhaustive unit and integration testing for the Logic Weaver's engine.
Run via: uv run python test_week2.py
"""
import unittest
import mysql.connector
from engine import (
    parse_version, 
    is_vulnerable, 
    establish_relational_link, 
    extract_vulnerability_ranges, 
    write_finding
)

class TestVersionParser(unittest.TestCase):
    """Testing the semantic version string-to-tuple converter."""
    
    def test_standard_semantic_versions(self):
        self.assertEqual(parse_version("1.2.3"), (1, 2, 3))
        self.assertEqual(parse_version("10.0.50"), (10, 0, 50))
        
    def test_short_versions(self):
        self.assertEqual(parse_version("1.2"), (1, 2))
        self.assertEqual(parse_version("1"), (1,))
        
    def test_empty_and_null_versions(self):
        self.assertEqual(parse_version("0"), (0,))
        self.assertEqual(parse_version(""), (0,))
        self.assertEqual(parse_version(None), (0,))
        
    def test_leading_zeros(self):
        # 1.02.3 should evaluate mathematically as 1.2.3
        self.assertEqual(parse_version("1.02.3"), (1, 2, 3))
        self.assertEqual(parse_version("01.00.00"), (1, 0, 0))
        
    def test_malformed_fallback(self):
        # Strings that can't be parsed into pure integers should fallback safely
        self.assertEqual(parse_version("1.2.a"), ("1.2.a",))
        self.assertEqual(parse_version("latest"), ("latest",))

class TestVulnerabilityLogic(unittest.TestCase):
    """Testing the boundary mathematics of the matching engine."""
    
    def test_exact_boundary_matches(self):
        # Exactly on the introduced boundary (Vulnerable)
        self.assertTrue(is_vulnerable("1.0.0", "1.0.0", "2.0.0"))
        # Exactly on the fixed boundary (Safe - exclusive bound)
        self.assertFalse(is_vulnerable("2.0.0", "1.0.0", "2.0.0"))
        
    def test_interior_matches(self):
        # Safely inside the danger zone
        self.assertTrue(is_vulnerable("1.5.0", "1.0.0", "2.0.0"))
        self.assertTrue(is_vulnerable("1.9.9", "1.0.0", "2.0.0"))
        
    def test_exterior_matches(self):
        # Safely before the bug was introduced
        self.assertFalse(is_vulnerable("0.9.9", "1.0.0", "2.0.0"))
        # Safely after the patch
        self.assertFalse(is_vulnerable("2.0.1", "1.0.0", "2.0.0"))
        self.assertFalse(is_vulnerable("3.0.0", "1.0.0", "2.0.0"))
        
    def test_missing_fixed_bound(self):
        # Bug introduced, never fixed
        self.assertTrue(is_vulnerable("1.0.0", "1.0.0", ""))
        self.assertTrue(is_vulnerable("999.0.0", "1.0.0", None))
        self.assertFalse(is_vulnerable("0.5.0", "1.0.0", ""))
        
    def test_missing_introduced_bound(self):
        # Bug existed since the dawn of time (0)
        self.assertTrue(is_vulnerable("0.5.0", "", "1.0.0"))
        self.assertTrue(is_vulnerable("0.9.9", None, "1.0.0"))
        self.assertFalse(is_vulnerable("1.0.0", "", "1.0.0"))
        
    def test_asymmetrical_version_lengths(self):
        # Pinned 1.5 against range [1, 2)
        self.assertTrue(is_vulnerable("1.5", "1", "2"))
        # Pinned 1 against range [1.0.0, 2.0.0)
        self.assertFalse(is_vulnerable("1", "1.0.1", "2.0.0"))

class TestDatabaseIntegration(unittest.TestCase):
    """Testing the live relational hooks against the Architect's seed data."""
    
    @classmethod
    def setUpClass(cls):
        """Awaken the connection once for all DB tests."""
        cls.conn = establish_relational_link()
        
    @classmethod
    def tearDownClass(cls):
        """Sever the connection cleanly."""
        cls.conn.close()
        
    def test_connection_is_active(self):
        self.assertTrue(self.conn.is_connected())
        
    def test_extraction_finds_vulnerabilities(self):
        # demo-http-client has exactly 1 seeded vulnerability
        ranges = extract_vulnerability_ranges(self.conn, "demo-http-client")
        self.assertEqual(len(ranges), 1)
        self.assertEqual(ranges[0]['vulnerability_id'], 'SECUREDEP-DEMO-001')
        self.assertEqual(ranges[0]['introduced_version'], '1.0.0')
        
    def test_extraction_handles_disjoint_ranges(self):
        # demo-parser has 2 distinct ranges seeded (1.4.0-1.5.0, 2.0.0-2.1.0)
        ranges = extract_vulnerability_ranges(self.conn, "demo-parser")
        self.assertGreaterEqual(len(ranges), 2)
        
    def test_extraction_handles_safe_packages(self):
        # demo-safe-lib has no seeded vulnerabilities
        ranges = extract_vulnerability_ranges(self.conn, "demo-safe-lib")
        self.assertEqual(len(ranges), 0)
        
    def test_idempotent_write_does_not_crash(self):
        # We test if the INSERT IGNORE logic actually prevents crashes on duplicates.
        # This writes the exact same mock finding we inserted in Step 4.
        try:
            write_finding(self.conn, 'SECUREDEP-DEMO-001', 6001)
            crashed = False
        except mysql.connector.Error:
            crashed = True
            
        self.assertFalse(crashed, "Engine crashed on duplicate write instead of ignoring it!")

if __name__ == '__main__':
    # Setting verbosity=2 provides a beautiful, detailed output for every single test
    unittest.main(verbosity=2)