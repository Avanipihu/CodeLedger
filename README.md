CodeLedgerAutomated Software Supply Chain Security & Local OSV Dependency AuditorCodeLedger is an enterprise-grade software supply chain security tool designed to audit application dependencies against open-source vulnerability datasets. By localizing Open Source Vulnerabilities (OSV) data from PyPI into a hybrid relational and document persistence layer, CodeLedger allows engineering teams to parse manifest files (requirements.txt), execute version range matching algorithms, and generate AI-ready contextual remediation intelligence—completely offline.   📋 Table of ContentsKey FeaturesSystem ArchitectureProject StructureTeam Roles & ResponsibilitiesInstallation & SetupUsage & Execution FlowAI Remediation IntegrationDevelopment RoadmapLicense🎯 Key FeaturesLocal Data Localization: Ingests PyPI vulnerability snapshots directly into local storage for air-gapped security auditing.   Hybrid Database Storage: Combines MySQL for relational schema constraints with MongoDB for rich, nested JSON vulnerability payloads.   Semantic Range Matching Engine: Evaluates exact version specifications and range operators against vulnerability fix bounds.   Interactive Web Interface: Modern Flask dashboard to upload manifest files, review vulnerability findings, and examine project risk histories.   LLM-Powered Remediation: Contextual prompt engineering pipelines that convert raw vulnerability IDs into actionable developer fix guides.   🏗️ System ArchitectureCodeLedger utilizes a dual-database architecture to strike a balance between fast, indexable relational lookups and unstructured document flexibility:                        ┌────────────────────────┐
                     │ OSV Data Source (PyPI) │
                     └───────────┬────────────┘
                                 │
                                 ▼
                     ┌────────────────────────┐
                     │ Ingestion Engine       │
                     │ (ingest.py / parser)   │
                     └───────────┬────────────┘
                                 │
                 ┌───────────────┴───────────────┐
                 ▼                               ▼
       ┌───────────────────┐           ┌───────────────────┐
       │   MySQL Server    │           │ MongoDB Database  │
       │ Relational Engine │           │ Document Store    │
       │  (Schema / Seed)  │           │   (Raw OSV JSON)  │
       └─────────┬─────────┘           └─────────┬─────────┘
                 │                               │
                 └───────────────┬───────────────┘
                                 │
                                 ▼
                    ┌─────────────────────────┐
                    │ Engine & Range Matcher  │
                    │ (engine.py / matcher)   │
                    └────────────┬────────────┘
                                 │
                                 ▼
                    ┌─────────────────────────┐
                    │ Flask Web UI (app.py)   │
                    │ & LLM Prompt Pipeline   │
                    └─────────────────────────┘
MySQL Relational Database: Stores canonical package indexes, normalized severity tags, explicit version boundaries, and execution metadata.   MongoDB Document Store: Preserves complete OSV schema documents, credit annotations, external link references, and detailed vulnerability notes.   📁 Project StructurePlaintextCodeLedger/
├── static/
│   └── style.css                 # Custom application UI styles
├── templates/
│   ├── base.html                 # Base layout template
│   ├── explorer.html             # Vulnerability database search interface
│   ├── finding.html              # Individual vulnerability finding page
│   ├── history.html              # Historical scan audit logs
│   ├── import.html               # Manifest file upload portal
│   ├── projects.html             # Project inventory view
│   ├── results.html              # Interactive scan results display
│   └── status.html               # Database health and status dashboard
├── prompts/
│   └── explanation_prompt.txt    # Prompt template for LLM integration
├── affected_packages.csv         # Standardized CSV dump of package mappings[cite: 2]
├── app.py                        # Primary Flask web server application
├── crud_test.py                  # Functional integration tests for database operations
├── download_snapshot.py          # OSV PyPI snapshot acquisition tool
├── engine.py                     # Main cross-database matching engine
├── ingest.py                     # Data ETL pipeline execution script
├── matcher.py                    # Semantic version comparison algorithms
├── osv_parser.py                 # PyPI JSON schema parser
├── requirements.txt              # Application python runtime dependencies
├── schema.sql                    # MySQL relational schema definitions[cite: 1, 2]
├── seed.sql                      # Baseline database seed records[cite: 1, 2]
└── vulnerabilities.csv           # Normalized vulnerability export file[cite: 2]
👥 Team Roles & ResponsibilitiesThe system was constructed using a modular four-persona development model[cite: 1, 2]:RolePersonaResponsibilities & Core ArtifactsData EngineerPioneerData pipeline acquisition, parsing scripts (osv_parser.py, download_snapshot.py), and full ETL database ingestion (ingest.py)[cite: 1, 2].Database ArchitectArchitectDatabase normalized schema design (schema.sql), seed fixtures (seed.sql), view constraints, and query indexing optimizations[cite: 1, 2].Backend CoreWeaverSemantic version matching logic (matcher.py), ID bridging, and cross-database correlation engine (engine.py)[cite: 1, 2].Frontend & AIAlchemistFlask web app routing (app.py), dynamic template rendering (templates/), and prompt engineering (prompts/explanation_prompt.txt)[cite: 1, 2].⚙️ Installation & SetupPrerequisitesPython: Version 3.9 or higherMySQL Server: Version 8.0 or higher (listening on default port 3306)MongoDB Server: Version 5.0 or higher (listening on default port 27017)Step 1: Clone RepositoryBashgit clone https://github.com/Avanipihu/CodeLedger.git
cd CodeLedger
Step 2: Environment SetupCreate and activate a isolated Python virtual environment:Bash# Linux/macOS
python3 -m venv venv
source venv/bin/activate

# Windows (Git Bash)
python -m venv venv
source venv/Scripts/activate
Install the dependencies:Bashpip install -r requirements.txt
Step 3: Database InitializationStart your local MySQL and MongoDB services.Initialize the MySQL database schema and seed data:Bashmysql -u root -p -e "CREATE DATABASE IF NOT EXISTS codeledger;"
mysql -u root -p codeledger < schema.sql
mysql -u root -p codeledger < seed.sql
Step 4: Run Data Ingestion PipelineExecute the ETL script to populate your local database store with vulnerability snapshot data:Bashpython ingest.py
🚀 Usage & Execution Flow1. Launch Web ApplicationRun the Flask development server:Bashpython app.py
Open your browser and navigate to [http://127.0.0.1:5000](http://127.0.0.1:5000)[cite: 2].2. Scanning Dependency ManifestsNavigate to the Import tab on the web UI[cite: 1, 2].Upload a standard target requirements.txt manifest file containing pinned package dependencies (e.g., requests==2.25.1)[cite: 1, 2].The platform executes engine.py, querying MySQL and MongoDB instances for matching vulnerabilities[cite: 1, 2].View the matched findings, severity rankings, and detailed vulnerability descriptions on the interactive Results screen[cite: 1, 2].🤖 AI Remediation IntegrationCodeLedger features a built-in context generator for LLM analysis[cite: 1, 2]. When vulnerability matches are generated, findings are formatted into the prompt template stored at prompts/explanation_prompt.txt[cite: 1, 2].The generated prompt provides an LLM with structured context including:Affected package name and active installed version[cite: 1, 2].CVE/OSV unique identifiers[cite: 1, 2].Relational fix version constraints[cite: 1, 2].This structure enables an LLM to generate plain-language explanations of underlying vulnerability risks along with exact upgrade command sequences without hallucinating data[cite: 1, 2].🏁 Development RoadmapWeek 1: Foundation (Decoupled Construction)Completed parser prototypes, baseline database schemas, unit matcher tests, and Flask web scaffold[cite: 1, 2].Week 2: Integration (Wiring the Grid)End-to-end integration between MySQL/MongoDB ingestion pipelines, matching engines, web UI routes, and AI prompt drafting[cite: 1, 2].Week 3: Hardening (The Crucible)Offline reproducibility validation, disjoint range handling, cross-database ID consistency, database indexing, and performance tuning[cite: 1, 2].
