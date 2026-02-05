# testsmell 🧪

Zero-dependency Python test smell detector for pytest and unittest.

[![Python 3.9+](https://img.shields.io/badge/python-3.9+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](https://opensource.org/licenses/MIT)

## What are test smells?

Test smells are patterns in test code that indicate potential quality problems. Unlike code smells in production code, test smells specifically affect test maintainability, reliability, and effectiveness.

A test with smells might:
- Pass when it shouldn't (false positive)
- Fail intermittently (flaky)
- Be hard to understand or maintain
- Provide poor debugging information when it fails

## Installation

```bash
# Copy the single file
curl -O https://raw.githubusercontent.com/kriskimmerle/testsmell/main/testsmell.py

# Or clone and install
git clone https://github.com/kriskimmerle/testsmell
cd testsmell
pip install -e .
```

## Usage

```bash
# Scan a file
python testsmell.py test_app.py

# Scan a directory
python testsmell.py tests/

# JSON output for CI
python testsmell.py tests/ --json

# CI mode (exit 1 if smells found)
python testsmell.py tests/ --check

# Verbose mode with suggestions
python testsmell.py tests/ --verbose

# Ignore specific rules
python testsmell.py tests/ --ignore TS06 --ignore TS10
```

## Test Smells Detected

| Rule | Name | Severity | Description |
|------|------|----------|-------------|
| TS01 | Assertion Roulette | Warning | Multiple assertions without explanatory messages |
| TS02 | Conditional Test Logic | Warning | if/for/while statements in test methods |
| TS03 | Empty Test | Error | Test with no executable statements |
| TS04 | Duplicate Assert | Warning | Same assertion statement repeated |
| TS05 | Redundant Assertion | Error | Tautological assertions (assert True, assert 1==1) |
| TS06 | Magic Number Test | Info | Numeric literals in assertions without context |
| TS07 | Exception Handling | Error | Bare except swallowing errors |
| TS08 | Obscure Inline Setup | Warning | Too many local variables (>10) |
| TS09 | Sleepy Test | Warning | time.sleep() calls making tests slow |
| TS10 | Redundant Print | Info | print() statements left in tests |
| TS11 | Suboptimal Assert | Info | assertEqual(x, True) instead of assertTrue(x) |
| TS12 | Eager Test | Info | Test calling too many production methods |
| TS13 | Assertion-Free | Error | Test with no assertions |
| TS14 | Long Test Method | Warning | Test method over 50 lines |

## Examples

### TS01: Assertion Roulette

```python
# Bad - which assertion failed?
def test_user_creation():
    user = create_user("john", "john@example.com")
    assert user.name == "john"
    assert user.email == "john@example.com"
    assert user.active == True

# Good - clear failure messages
def test_user_creation():
    user = create_user("john", "john@example.com")
    assert user.name == "john", "Name should be set"
    assert user.email == "john@example.com", "Email should be set"
    assert user.active == True, "User should be active by default"
```

### TS05: Redundant Assertion

```python
# Bad - always passes
def test_always_true():
    assert True

# Bad - compares value to itself
def test_tautology():
    x = get_value()
    assert x == x
```

### TS07: Exception Handling

```python
# Bad - swallows errors
def test_risky_operation():
    try:
        risky_operation()
    except:
        pass

# Good - use pytest.raises
def test_risky_operation():
    with pytest.raises(ValueError):
        risky_operation()
```

### TS11: Suboptimal Assert

```python
# Bad - verbose
self.assertEqual(result, True)
self.assertEqual(value, None)
self.assertTrue(isinstance(obj, MyClass))

# Good - idiomatic
self.assertTrue(result)
self.assertIsNone(value)
self.assertIsInstance(obj, MyClass)
```

## Output

### Text Output (default)

```
tests/test_app.py
  ⚠ Line 15 (test_login): [TS01] Assertion roulette - 3 assertions without messages
  ✗ Line 42 (test_empty): [TS03] Empty test - no executable statements
  ℹ Line 67 (test_calc): [TS06] Magic number in assertion: 42

──────────────────────────────────────────────────
Grade: C (72/100)
Files scanned: 1
Tests analyzed: 12
Smells: 3 (1 errors, 1 warnings, 1 info)
```

### JSON Output

```json
{
  "version": "0.1.0",
  "grade": "C",
  "score": 72,
  "files_scanned": 1,
  "tests_analyzed": 12,
  "total_smells": 3,
  "smells": [
    {
      "rule": "TS01",
      "message": "Assertion roulette - 3 assertions without messages",
      "file": "tests/test_app.py",
      "line": 15,
      "severity": "warning",
      "test_name": "test_login",
      "suggestion": "Add descriptive messages to assertions for better debugging"
    }
  ]
}
```

## CI Integration

### GitHub Actions

```yaml
- name: Check test quality
  run: python testsmell.py tests/ --check --min-score 70
```

### Pre-commit

```yaml
repos:
  - repo: local
    hooks:
      - id: testsmell
        name: testsmell
        entry: python testsmell.py
        language: python
        types: [python]
        files: ^tests/
```

## Grading

testsmell calculates a quality grade (A-F) based on detected smells:

- **Error** (-15 points): Critical issues that likely indicate broken tests
- **Warning** (-5 points): Issues that reduce test quality
- **Info** (-2 points): Minor issues worth addressing

| Grade | Score |
|-------|-------|
| A | 90-100 |
| B | 80-89 |
| C | 70-79 |
| D | 60-69 |
| F | 0-59 |

## Comparison with Other Tools

| Feature | testsmell | PyNose | Pytest-Smell |
|---------|-----------|--------|--------------|
| Zero dependencies | ✅ | ❌ (PyCharm) | ❌ |
| CLI tool | ✅ | ❌ | ✅ |
| pytest support | ✅ | ✅ | ✅ |
| unittest support | ✅ | ✅ | ❌ |
| JSON output | ✅ | ❌ | ❌ |
| CI mode | ✅ | ❌ | ❌ |

## References

- [PyNose: A Test Smell Detector For Python](https://stairs.ics.uci.edu/papers/2021/PyNose_A_Test_Smell_Detector_For_Python.pdf) (ASE 2021)
- [Pytest-Smell: a smell detection tool for Python unit tests](https://dl.acm.org/doi/10.1145/3533767.3543290) (ISSTA 2022)
- [TEMPY: Test Smell Detector for Python](https://dl.acm.org/doi/10.1145/3555228.3555280) (SBES 2022)
- [Test Smells - The Coding Craftsman](https://testsmells.org/)

## License

MIT
