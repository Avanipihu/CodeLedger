"""
engine.py
The restored Logic Weaver engine. Evaluates package versions against MySQL ranges 
using PEP 440 logic, retrieves MongoDB context, and returns findings to the Flask UI.
"""
import os
import pymysql
import pymongo
from dotenv import load_dotenv

# Restore the Interface Contract by importing your robust Week 1 logic
from matcher import is_vulnerable  

load_dotenv()

def get_mysql_connection():
    """Forges a connection to the MySQL relational core using environment variables."""
    return pymysql.connect(
        host=os.getenv('MYSQL_HOST', '127.0.0.1'),
        user=os.getenv('MYSQL_USER', 'root'),
        password=os.getenv('MYSQL_PASSWORD', ''),
        database=os.getenv('MYSQL_DB', 'codeledger'),
        cursorclass=pymysql.cursors.DictCursor
    )

def get_mongo_collection():
    """Summons the MongoDB document vault for raw advisory context."""
    client = pymongo.MongoClient(os.getenv('MONGO_URI', 'mongodb://localhost:27017/'))
    db = client[os.getenv('MONGO_DB', 'codeledger')]
    return db['vulnerabilities']

def extract_vulnerability_ranges(cursor, package_name):
    """Retrieves all known vulnerability boundaries from MySQL for a given package."""
    query = """
        SELECT 
            p.name AS package_name,
            v.vulnerability_id,
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
    return cursor.fetchall()

def run_matching_engine(packages: list[tuple[str, str]]) -> list[dict]:
    """
    The Missing Bridge. 
    Accepts: A list of tuples containing (package_name, pinned_version).
    Returns: A list of dictionaries representing confirmed vulnerabilities to be rendered.
    """
    findings = []
    
    # Establish dual-database connections
    mysql_conn = get_mysql_connection()
    mongo_col = get_mongo_collection()
    
    try:
        with mysql_conn.cursor() as cursor:
            for pkg_name, pinned_version in packages:
                
                # Step 1: Query MySQL for relational ranges
                ranges = extract_vulnerability_ranges(cursor, pkg_name)
                
                if not ranges:
                    continue  # Safe package, bypass logic
                    
                for vuln in ranges:
                    intro = vuln.get('introduced_version')
                    fixed = vuln.get('fixed_version')
                    
                    # Step 2: Dynamically construct a PEP 440 specifier string
                    range_str = ""
                    if intro and intro != "0":
                        range_str += f">= {intro}"
                    if fixed:
                        range_str += f", < {fixed}" if range_str else f"< {fixed}"
                        
                    if not range_str:
                        continue # Edge case fallback
                    
                    # Step 3: Invoke the robust matcher logic
                    try:
                        if is_vulnerable(pinned_version, range_str):
                            vuln_id = vuln['vulnerability_id']
                            
                            # Step 4: Query MongoDB for nested advisory context
                            raw_advisory = mongo_col.find_one({"id": vuln_id}) or {}
                            summary = raw_advisory.get("summary", "No summary available.")
                            
                            # Parse nested severity array if it exists
                            severity_data = raw_advisory.get("severity", [])
                            severity = severity_data[0].get("score", "UNKNOWN") if severity_data else "UNKNOWN"
                            
                            # Step 5: Append a structured dictionary for the Flask UI
                            findings.append({
                                "package_name": pkg_name,
                                "version": pinned_version,
                                "vulnerability_id": vuln_id,
                                "severity": severity,
                                "summary": summary
                            })
                            
                    except ValueError as e:
                        # Catch malformed strings without crashing the entire scan
                        print(f"[!] Evaluation error for {pkg_name} {pinned_version}: {e}")
                        
    finally:
        mysql_conn.close() # Ensure the relational link is properly severed
        
    return findings