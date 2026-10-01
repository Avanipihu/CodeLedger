"""
matcher.py
Core version matching engine for CodeLedger.
Evaluates dependency versions against vulnerability specifiers using PEP 440 standards.
"""

from packaging.version import Version, InvalidVersion
from packaging.specifiers import SpecifierSet, InvalidSpecifier

def is_vulnerable(target_version: str, vulnerable_range: str) -> bool:
    """
    Evaluates if a target version falls within a defined vulnerable range.
    Handles PEP 440 versioning, compound ranges, asymmetrical lengths, and pre-releases.
    
    Args:
        target_version (str): The exact version of the dependency (e.g., "1.2.0a1").
        vulnerable_range (str): The OSV affected range (e.g., ">= 1.0.0, < 2.0.0").
        
    Returns:
        bool: True if the version is vulnerable, False otherwise.
    """
    # Sanitize input: Defensively strip stray whitespace and common 'v' prefixes
    target_version = target_version.lstrip("vV").strip()
    vulnerable_range = vulnerable_range.strip()

    try:
        # Cast the target string into a PEP 440 mathematical Version object
        parsed_version = Version(target_version)
        
        # Cast the vulnerability range into a logical SpecifierSet object
        # This natively handles compound ranges (e.g., ">= 1.5, < 2.0")
        specifiers = SpecifierSet(vulnerable_range)
        
        # Evaluate inclusion. 
        # prereleases=True ensures alpha/beta builds are actively evaluated against the range.
        return specifiers.contains(parsed_version, prereleases=True)

    except InvalidVersion:
        # Standardize the error response for malformed dependency versions
        raise ValueError(f"Malformed target version detected: '{target_version}'")
    except InvalidSpecifier:
        # Standardize the error response for garbage OSV range data
        raise ValueError(f"Malformed vulnerability range detected: '{vulnerable_range}'")


# --- MILESTONE VALIDATION: EXHAUSTIVE EDGE CASE TESTS ---
if __name__ == "__main__":
    print("Running version matching tests...")
    
    # Test 1: Is 1.5.0 less than 2.0.0? (Should be True)
    assert is_vulnerable("1.5.0", "< 2.0.0") == True
    
    # Test 2: Is 2.1.0 less than 2.0.0? (Should be False)
    assert is_vulnerable("2.1.0", "< 2.0.0") == False
    
    # Test 3: The Alphabet Trap. Is 1.10.0 greater than 1.2.0? (Should be True)
    assert is_vulnerable("1.10.0", "> 1.2.0") == True
    
    # Test 4: Exact match
    assert is_vulnerable("3.0.1", "== 3.0.1") == True

    # Test 5: Inequality
    assert is_vulnerable("5.02.15",">= 5.02.13") == True
    assert is_vulnerable("5.02.10",">= 5.02.13") == False

    # Test 6: Asymmetrical Version Lengths
    assert is_vulnerable("1.2", "== 1.2.0") == True
    assert is_vulnerable("2.0.0.0", "== 2.0.0") == True
    assert is_vulnerable("3.1", "< 3.1.1") == True

    # Test 7: Pre-releases and Epochs
    assert is_vulnerable("1.2.0a1", "< 1.2.0") == True
    assert is_vulnerable("1.5.0.post2", "> 1.5.0") == True
    assert is_vulnerable("v2.1.3", "== 2.1.3") == True

    # test 8: Compound and Disjoint Ranges
    assert is_vulnerable("1.5.0", ">= 1.0.0, < 2.0.0") == True
    assert is_vulnerable("2.1.0", ">= 1.0.0, < 2.0.0") == False
    assert is_vulnerable("0.9.0", "< 1.2.0, != 0.9.1") == True
    
    print("All milestone tests passed! The Weaver's logic is sound.")