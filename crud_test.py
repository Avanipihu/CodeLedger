"""
Integration test script for MongoDB NoSQL operations.
Validates PyMongo connectivity, schema-less document manipulation,
nested querying, and basic aggregation pipelines.
"""

from pymongo import MongoClient
from pymongo.errors import ConnectionFailure

def run_database_tests():
    # Initialize MongoDB client with standard local URI
    try:
        client = MongoClient("mongodb://localhost:27017/", serverSelectionTimeoutMS=2000)
        client.admin.command('ping')
    except ConnectionFailure:
        raise SystemExit("Database connection failed. Ensure MongoDB daemon is running.")

    db = client["codeledger_db"]

    # Ensure idempotency for test runs by dropping existing test collections
    db.drop_collection("vulnerability_documents")
    db.drop_collection("projects")
    db.drop_collection("scan_findings")

    # Initialize collections
    vuln_col = db["vulnerability_documents"]
    proj_col = db["projects"]
    finding_col = db["scan_findings"]

    print("--- 1. BATCH CREATION (INSERT) ---")
    
    # Insert a single project document
    project_doc = {
        "project_id": "PRJ-001",
        "name": "Auth-Service-Core",
        "dependencies": ["requests", "urllib3", "flask"]
    }
    proj_col.insert_one(project_doc)

    # Insert multiple nested vulnerability documents (Bulk Insert)
    osv_records = [
        {
            "osv_id": "GHSA-1111",
            "summary": "Improper input validation in requests.",
            "severity": "HIGH",
            "affected": [{"package": "requests", "ranges": ["< 2.20.0"]}]
        },
        {
            "osv_id": "GHSA-2222",
            "summary": "Header parsing denial of service.",
            "severity": "CRITICAL",
            "affected": [{"package": "urllib3", "ranges": ["< 1.25.0"]}]
        },
        {
            "osv_id": "GHSA-3333",
            "summary": "Minor timing side-channel.",
            "severity": "LOW",
            "affected": [{"package": "flask", "ranges": ["< 1.0.0"]}]
        }
    ]
    vuln_col.insert_many(osv_records)
    print(f"Initialized {vuln_col.count_documents({})} vulnerability records.")

    print("\n--- 2. ADVANCED QUERYING (READ) ---")
    
    # Query using exact match
    crit_vuln = vuln_col.find_one({"severity": "CRITICAL"})
    print(f"Critical Vuln Found: {crit_vuln['osv_id']} - {crit_vuln['summary']}")

    # Query using logical operators ($in)
    target_packages = ["requests", "urllib3"]
    # Dot notation used to query nested document arrays
    query = {"affected.package": {"$in": target_packages}}
    results = vuln_col.find(query)
    print(f"Vulnerabilities affecting {target_packages}:")
    for r in results:
        print(f"  -> {r['osv_id']} (Severity: {r['severity']})")

    print("\n--- 3. MUTATION AND ARRAY MANIPULATION (UPDATE) ---")
    
    # Update a specific field ($set) and push to a new array ($push)
    vuln_col.update_one(
        {"osv_id": "GHSA-1111"},
        {
            "$set": {"severity": "CRITICAL", "status": "REVIEWED"},
            "$push": {"aliases": "CVE-2018-18074"}
        }
    )
    updated_doc = vuln_col.find_one({"osv_id": "GHSA-1111"})
    print(f"Updated GHSA-1111. New Severity: {updated_doc['severity']}, Aliases: {updated_doc.get('aliases')}")

    print("\n--- 4. AGGREGATION PIPELINES ---")
    
    # Group vulnerabilities by severity count
    pipeline = [
        {"$group": {"_id": "$severity", "count": {"$sum": 1}}},
        {"$sort": {"count": -1}}
    ]
    agg_results = vuln_col.aggregate(pipeline)
    print("Vulnerability count by severity:")
    for agg in agg_results:
        print(f"  -> {agg['_id']}: {agg['count']}")

    print("\n--- 5. TEARDOWN (DELETE) ---")
    
    # Delete documents matching a specific condition
    delete_result = vuln_col.delete_many({"severity": "LOW"})
    print(f"Deleted {delete_result.deleted_count} LOW severity record(s).")
    print(f"Remaining records in collection: {vuln_col.count_documents({})}")

if __name__ == "__main__":
    run_database_tests()