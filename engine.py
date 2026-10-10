"""
Evaluates simulated input and writes confirmed findings to the database.
"""
import os
import sys
import mysql.connector
from dotenv import load_dotenv

load_dotenv()

def establish_relational_link():
    """Forge a universal connection to the local MariaDB instance."""
    try:
        conn = mysql.connector.connect(
            user="root",
            password=os.getenv("DB_PASSWORD", ""), 
            host="127.0.0.1",
            port=3306,
            database="codeledger"
        )
        return conn
    except mysql.connector.Error as e:
        print(f"[-] Relational Error: {e}")
        sys.exit(1)

def extract_vulnerability_ranges(conn, package_name):
    """Retrieves all known vulnerability ranges and their specific IDs."""
    cursor = conn.cursor(dictionary=True)
    query = """
        SELECT 
            p.name AS package_name,
            v.vulnerability_id,
            ar.range_id,
            re_intro.event_value AS introduced_version,
            re_fixed.event_value AS fixed_version
        FROM packages p
        JOIN affected_package ap ON p.package_id = ap.package_id
        JOIN vulnerabilities v ON ap.vulnerability_id = v.vulnerability_id
        JOIN affected_range ar ON ap.affected_package_id = ar.affected_package_id
        LEFT JOIN range_event re_intro 
            ON ar.range_id = re_intro.range_id AND re_intro.event_type = 'introduced'
        LEFT JOIN range_event re_fixed 
            ON ar.range_id = re_fixed.range_id AND re_fixed.event_type = 'fixed'
        WHERE p.name = %s;
    """
    cursor.execute(query, (package_name,))
    results = cursor.fetchall()
    cursor.close()
    return results

def parse_version(version_string):
    """Converts a semantic version string into a mathematical tuple."""
    if not version_string or version_string == "0":
        return (0,)
    try:
        return tuple(int(part) for part in version_string.split('.'))
    except ValueError:
        return (version_string,)

def is_vulnerable(pinned_version, introduced, fixed):
    """Determines if a version lies strictly within the vulnerable range."""
    pinned = parse_version(pinned_version)
    intro = parse_version(introduced)
    
    if pinned < intro:
        return False
        
    if fixed:
        fix = parse_version(fixed)
        if pinned >= fix:
            return False
            
    return True

def write_finding(conn, vulnerability_id, range_id):
    """
    The Conclusive Write: Commits a confirmed vulnerability to MariaDB.
    Uses INSERT IGNORE to gracefully skip duplicate findings without crashing.
    """
    cursor = conn.cursor()
    # INSERT IGNORE tells MariaDB to skip this row if the unique constraint
    # (scan_id + dependency_id + vulnerability_id) is violated.
    query = """
        INSERT IGNORE INTO scan_findings
        (finding_id, scan_id, dependency_id, vulnerability_id, matched_range_id, match_basis)
        SELECT COALESCE(MAX(finding_id), 9000) + 1, 9101, 8001, %s, %s, 'RANGE'
        FROM scan_findings;
    """
    cursor.execute(query, (vulnerability_id, range_id))
    
    # We can check if MariaDB actually wrote a new row or ignored a duplicate
    if cursor.rowcount > 0:
        print("      -> [SUCCESS] New finding recorded in MariaDB.")
    else:
        print("      -> [SKIPPED] Finding already exists in this scan. Ignoring duplicate.")
        
    conn.commit()  # Seal the transaction
    cursor.close()

if __name__ == "__main__":
    print("[*] Igniting the Logic Weaver Engine - Conclusive Write...\n")
    db_connection = establish_relational_link()
    
    simulated_requirements = [
        ("demo-http-client", "1.0.0"),  # VULNERABLE -> triggers database write
        ("demo-safe-lib", "1.0.0"),     # SAFE -> ignored
        ("demo-parser", "1.4.5"),       # VULNERABLE -> triggers database write
        ("demo-parser", "2.1.0"),       # SAFE -> ignored
    ]
    
    print("[*] Processing requirements and writing findings to database...\n")
    
    findings_written = 0
    for pkg_name, pinned_version in simulated_requirements:
        print(f"> Evaluating {pkg_name} @ v{pinned_version}")
        ranges = extract_vulnerability_ranges(db_connection, pkg_name)
        
        if not ranges:
            print("  [+] SAFE: No known vulnerabilities in the database.\n")
            continue
            
        package_is_safe = True
        for vuln in ranges:
            if is_vulnerable(pinned_version, vuln['introduced_version'], vuln['fixed_version']):
                package_is_safe = False
                vuln_id = vuln['vulnerability_id']
                range_id = vuln['range_id']
                
                print(f"  [!] VULNERABLE: Matches {vuln_id}.")
                print(f"      -> Writing record to MariaDB (Range ID: {range_id})...")
                
                # Execute Step 4
                write_finding(db_connection, vuln_id, range_id)
                findings_written += 1
                
        if package_is_safe:
            print("  [+] SAFE: Version falls outside all known vulnerable ranges.")
        print("-" * 45)
        
    db_connection.close()
    print(f"\n[*] Engine execution complete. Successfully wrote {findings_written} findings to the database.")