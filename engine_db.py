"""
Infrastructure validation and database connection layer.
This replaces the hardcoded dictionaries in mock_data.py.
"""
import os
import sys
import mysql.connector
from dotenv import load_dotenv
from pymongo import MongoClient
from pymongo.errors import ConnectionFailure

# Awaken the environment variables
load_dotenv()

def establish_relational_link():
    """Forge a universal connection to either MariaDB or MySQL."""
    try:
        conn = mysql.connector.connect(
            user="root",
            password=os.getenv("DB_PASSWORD", ""), # Secure dynamic retrieval
            host="127.0.0.1",
            port=3306,
            database="codeledger"
        )
        print("[+] Relational Link: Universal database connection secured.")
        return conn
    except mysql.connector.Error as e:
        print(f"[-] Relational Error: {e}")
        sys.exit(1)

def establish_nosql_link():
    """Forge a connection to the local MongoDB instance."""
    try:
        client = MongoClient("mongodb://localhost:27017/", serverSelectionTimeoutMS=2000)
        client.admin.command('ping')
        print("[+] NoSQL Link: MongoDB connection secured.")
        return client["osv_database"]
    except ConnectionFailure as e:
        print(f"[-] NoSQL Error: MongoDB is unreachable. {e}")
        sys.exit(1)

def verify_seeded_data(conn):
    """Retrieve the Architect's seeded dummy packages to verify the schema."""
    cursor = conn.cursor()
    cursor.execute("SELECT package_id, name FROM packages LIMIT 5;")
    
    print("\n--- Relational Database Seeded Packages ---")
    for (pkg_id, name) in cursor:
        print(f"Package {pkg_id}: {name}")
    
    cursor.close()

if __name__ == "__main__":
    print("Initiating database summoning sequence...\n")
    
    # 1. Test Relational Bridge
    relational_connection = establish_relational_link()
    
    # 2. Test NoSQL Bridge
    mongo_db = establish_nosql_link()
    
    # 3. Verify Data integrity
    verify_seeded_data(relational_connection)
    
    relational_connection.close()
    print("\nInfrastructure validation complete. Daemons are sleeping.")