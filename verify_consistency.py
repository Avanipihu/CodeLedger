"""
Cross-database auditor ensuring absolute symmetry between the relational core 
and the document vault, fulfilling the Week 3 Story Arc Consistency mandate.
"""
import os
import sys
import pymysql
import pymongo
from dotenv import load_dotenv

load_dotenv()

def audit_databases():
    print("[*] Igniting the Auditor's Lens: Verifying Cross-Database Symmetery...\n")
    
    # 1. Connect to the Relational Core (MariaDB/MySQL)
    try:
        mysql_conn = pymysql.connect(
            host=os.getenv('MYSQL_HOST', '127.0.0.1'),
            user=os.getenv('MYSQL_USER', 'root'),
            password=os.getenv('MYSQL_PASSWORD', os.getenv('DB_PASSWORD', '')),
            database=os.getenv('MYSQL_DB', 'codeledger'),
            cursorclass=pymysql.cursors.DictCursor
        )
    except pymysql.Error as e:
        sys.exit(f"[-] Relational failure: {e}")

    # 2. Connect to the Document Vault (MongoDB)
    try:
        mongo_client = pymongo.MongoClient(os.getenv('MONGO_URI', 'mongodb://localhost:27017/'))
        mongo_db = mongo_client[os.getenv('MONGO_DB', 'codeledger')]
        mongo_col = mongo_db['vulnerabilities']
    except pymongo.errors.ConnectionFailure as e:
        sys.exit(f"[-] Document vault unreachable: {e}")

    try:
        # 3. Sweep MySQL
        print("    -> Sweeping MariaDB `vulnerabilities` table...")
        with mysql_conn.cursor() as cursor:
            cursor.execute("SELECT vulnerability_id FROM vulnerabilities;")
            mysql_ids = {row['vulnerability_id'] for row in cursor.fetchall()}
        
        # 4. Sweep MongoDB
        print("    -> Sweeping MongoDB `vulnerabilities` collection...")
        mongo_ids = {doc['id'] for doc in mongo_col.find({}, {"id": 1, "_id": 0})}
        
        # 5. The Mathematical Intersection
        orphans_in_mysql = mysql_ids - mongo_ids
        orphans_in_mongo = mongo_ids - mysql_ids
        
        # 6. The Verdict
        print(f"\n[+] Relational Record Count: {len(mysql_ids):,}")
        print(f"[+] Document Vault Record Count: {len(mongo_ids):,}\n")
        
        if not orphans_in_mysql and not orphans_in_mongo:
            print("[+] VERDICT: Flawless Symmetry. The Story Arc Consistency is absolute.")
            return True
        
        print("[-] VERDICT: Asymmetry Detected.")
        if orphans_in_mysql:
            print(f"    ! Found {len(orphans_in_mysql)} IDs in MariaDB missing from MongoDB.")
            print(f"      Samples: {list(orphans_in_mysql)[:5]}")
        if orphans_in_mongo:
            print(f"    ! Found {len(orphans_in_mongo)} IDs in MongoDB missing from MariaDB.")
            print(f"      Samples: {list(orphans_in_mongo)[:5]}")
        
        return False
        
    finally:
        mysql_conn.close()

if __name__ == "__main__":
    audit_databases()