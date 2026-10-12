# Alchemist – Week 2

Run without the real engine (fake data, UI only):

    pip install -r requirements.txt
    SECUREDEP_MOCK=1 python app.py          # Windows: set SECUREDEP_MOCK=1

Run for real (after `git pull` of the Weaver's engine.py and Architect's schema):

    export DB_HOST=localhost DB_USER=... DB_PASSWORD=... DB_NAME=securedep
    python app.py

Open http://127.0.0.1:5000, upload a requirements.txt.

## What to agree with teammates
- Weaver: `engine.run_scan(project_name, [(name, version), ...]) -> scan_id`
  (edit `_call_engine()` in engine_adapter.py if theirs differs).
- Architect: column names used in `db.py` (FINDINGS_SQL). Change them there only.

## Files
- app.py: routes, validation, severity banding
- req_parser.py: strict name==version parser (text only, never executed)
- engine_adapter.py: the only link to the Weaver's engine; mock mode
- db.py: parameterized read-only query for scan + findings
- templates/, static/style.css: UI
- prompts/: draft system + user prompts for the Finding Explanation AI (Week 3 wires the call)
