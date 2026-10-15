"""
matcher.py
Deterministic PEP 440 version matching engine for CodeLedger.
Resolves the SpecifierSet prerelease exclusion quirk using direct Version math.
"""
import re
from packaging.version import Version, InvalidVersion
from packaging.specifiers import SpecifierSet, InvalidSpecifier

_SPEC_PATTERN = re.compile(r'^(==|!=|<=|>=|<|>|~=)\s*(.+)$')

def _eval_clause(target: Version, clause: str) -> bool:
    """Evaluates a single comparison clause using direct PEP 440 Version ordering."""
    match = _SPEC_PATTERN.match(clause.strip())
    if not match:
        raise InvalidSpecifier(f"Invalid clause: '{clause}'")
    
    op, ver_str = match.groups()
    ver_str = ver_str.lstrip("vV").strip()
    
    # In OSV, '0' represents the beginning of time (all versions >= 0)
    bound = Version("0.0.0a0") if ver_str == "0" else Version(ver_str)
    
    if op == "==": return target == bound
    if op == "!=": return target != bound
    if op == "<":  return target < bound
    if op == "<=": return target <= bound
    if op == ">":  return target > bound
    if op == ">=": return target >= bound
    if op == "~=": return SpecifierSet(clause).contains(target, prereleases=True)
    return False

def is_vulnerable(target_version: str, vulnerable_range: str) -> bool:
    """
    Evaluates if a target_version falls within a comma-separated vulnerable_range.
    Supports compound intervals (AND) and semicolon-separated disjoint intervals (OR).
    """
    target_clean = target_version.lstrip("vV").strip()
    range_clean = vulnerable_range.strip()

    try:
        parsed_target = Version(target_clean)
        
        # Support disjoint intervals separated by ';' (logical OR)
        for sub_range in range_clean.split(";"):
            if not sub_range.strip():
                continue
            clauses = [c.strip() for c in sub_range.split(",") if c.strip()]
            # Within a sub-range, all clauses must hold (logical AND)
            if clauses and all(_eval_clause(parsed_target, c) for c in clauses):
                return True
        return False

    except InvalidVersion as e:
        raise ValueError(f"Malformed version: '{target_version}'") from e
    except InvalidSpecifier as e:
        raise ValueError(f"Malformed range: '{vulnerable_range}'") from e


if __name__ == "__main__":
    assert is_vulnerable("1.5.0", "< 2.0.0") is True
    assert is_vulnerable("2.1.0", "< 2.0.0") is False
    assert is_vulnerable("1.10.0", "> 1.2.0") is True
    assert is_vulnerable("3.0.1", "== 3.0.1") is True
    assert is_vulnerable("5.02.15", ">= 5.02.13") is True
    assert is_vulnerable("1.2", "== 1.2.0") is True
    # The Prerelease Paradox resolved:
    assert is_vulnerable("1.2.0a1", "< 1.2.0") is True
    assert is_vulnerable("1.5.0.post2", "> 1.5.0") is True
    assert is_vulnerable("v2.1.3", "== 2.1.3") is True
    assert is_vulnerable("1.5.0", ">= 1.0.0, < 2.0.0") is True
    assert is_vulnerable("0.9.0", ">= 0") is True
    print("[+] All matcher assertions passed.")