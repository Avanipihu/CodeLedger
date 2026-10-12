"""Parse a pinned requirements.txt (or pip freeze output) as plain text.

The file is never executed or passed to pip; every line is matched against a
strict regex. Returns (packages, problems).
"""
import re

LINE_RE = re.compile(
    r"^(?P<name>[A-Za-z0-9][A-Za-z0-9._-]*)"
    r"(?:\[[^\]]*\])?\s*==\s*"
    r"(?P<version>[A-Za-z0-9][A-Za-z0-9._+!-]*)\s*(?:;.*)?$"
)


def normalize_name(name: str) -> str:
    """PEP 503 normalization so 'Django_Rest.Framework' == 'django-rest-framework'."""
    return re.sub(r"[-_.]+", "-", name).lower()


def parse_requirements(text: str):
    packages, problems, seen = [], [], set()
    for lineno, raw in enumerate(text.splitlines(), start=1):
        line = re.sub(r"(^|\s)#.*$", "", raw).strip()
        if not line or line.startswith("-"):  # blank, comment, or pip option (-r, -e, --hash)
            continue
        m = LINE_RE.match(line)
        if not m:
            problems.append(f"Line {lineno}: '{raw.strip()[:60]}' is not a pinned requirement (use name==version).")
            continue
        name, version = normalize_name(m["name"]), m["version"]
        if name in seen:
            problems.append(f"Line {lineno}: '{name}' appears more than once; the first entry was kept.")
            continue
        seen.add(name)
        packages.append((name, version))
    return packages, problems
