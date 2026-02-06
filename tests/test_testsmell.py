#!/usr/bin/env python3
"""Tests for testsmell."""

import ast
import sys
import tempfile
import textwrap
from pathlib import Path

# Add parent dir for import
sys.path.insert(0, str(Path(__file__).parent.parent))

from testsmell import (
    SmellDetector,
    scan_file,
    scan_path,
    calculate_grade,
    Severity,
    Smell,
    ScanResult,
)


def analyze_code(code: str, filename: str = "test_example.py") -> list[Smell]:
    """Helper to analyze code string and return smells."""
    code = textwrap.dedent(code)
    detector = SmellDetector(filename, code)
    tree = ast.parse(code, filename=filename)
    detector.visit(tree)
    return detector.smells


class TestEmptyTest:
    """TS03: Empty test detection."""
    
    def test_detects_empty_test(self):
        code = """
        def test_empty():
            pass
        """
        smells = analyze_code(code)
        assert any(s.rule == "TS03" for s in smells)
    
    def test_detects_ellipsis_only(self):
        code = """
        def test_only_ellipsis():
            ...
        """
        smells = analyze_code(code)
        assert any(s.rule == "TS03" for s in smells)
    
    def test_non_empty_test_ok(self):
        code = """
        def test_has_content():
            x = 1
            assert x == 1
        """
        smells = analyze_code(code)
        assert not any(s.rule == "TS03" for s in smells)


class TestAssertionFreeTest:
    """TS13: Assertion-free test detection."""
    
    def test_detects_no_assertions(self):
        code = """
        def test_no_assertions():
            x = 1
            y = 2
            z = x + y
        """
        smells = analyze_code(code)
        assert any(s.rule == "TS13" for s in smells)
    
    def test_pytest_assert_ok(self):
        code = """
        def test_with_assert():
            x = 1
            assert x == 1
        """
        smells = analyze_code(code)
        assert not any(s.rule == "TS13" for s in smells)
    
    def test_pytest_raises_ok(self):
        code = """
        import pytest
        
        def test_with_raises():
            with pytest.raises(ValueError):
                int("not a number")
        """
        smells = analyze_code(code)
        assert not any(s.rule == "TS13" for s in smells)


class TestAssertionRoulette:
    """TS01: Multiple assertions without messages."""
    
    def test_detects_multiple_assertions_no_msg(self):
        code = """
        def test_roulette():
            assert 1 == 1
            assert 2 == 2
            assert 3 == 3
        """
        smells = analyze_code(code)
        assert any(s.rule == "TS01" for s in smells)
    
    def test_single_assertion_ok(self):
        code = """
        def test_single():
            assert 1 == 1
        """
        smells = analyze_code(code)
        assert not any(s.rule == "TS01" for s in smells)
    
    def test_assertions_with_messages_ok(self):
        code = """
        def test_with_messages():
            assert 1 == 1, "first check"
            assert 2 == 2, "second check"
        """
        smells = analyze_code(code)
        assert not any(s.rule == "TS01" for s in smells)


class TestConditionalLogic:
    """TS02: Conditional logic in tests."""
    
    def test_detects_if_statement(self):
        code = """
        def test_conditional():
            x = get_value()
            if x > 5:
                assert x > 5
            else:
                assert x <= 5
        """
        smells = analyze_code(code)
        assert any(s.rule == "TS02" for s in smells)
    
    def test_detects_for_loop(self):
        code = """
        def test_with_loop():
            for i in range(10):
                assert i >= 0
        """
        smells = analyze_code(code)
        assert any(s.rule == "TS02" for s in smells)
    
    def test_detects_while_loop(self):
        code = """
        def test_with_while():
            i = 0
            while i < 10:
                assert i >= 0
                i += 1
        """
        smells = analyze_code(code)
        assert any(s.rule == "TS02" for s in smells)


class TestDuplicateAssert:
    """TS04: Duplicate assertion detection."""
    
    def test_detects_duplicate_asserts(self):
        code = """
        def test_duplicates():
            x = 1
            assert x == 1
            assert x == 1
        """
        smells = analyze_code(code)
        assert any(s.rule == "TS04" for s in smells)
    
    def test_different_asserts_ok(self):
        code = """
        def test_different():
            x = 1
            assert x == 1
            assert x > 0
        """
        smells = analyze_code(code)
        assert not any(s.rule == "TS04" for s in smells)


class TestRedundantAssertion:
    """TS05: Tautological assertions."""
    
    def test_detects_assert_true(self):
        code = """
        def test_always_true():
            assert True
        """
        smells = analyze_code(code)
        assert any(s.rule == "TS05" for s in smells)
    
    def test_detects_assert_false(self):
        code = """
        def test_always_false():
            assert False
        """
        smells = analyze_code(code)
        assert any(s.rule == "TS05" for s in smells)
    
    def test_detects_literal_equality(self):
        code = """
        def test_literal_eq():
            assert 1 == 1
        """
        smells = analyze_code(code)
        assert any(s.rule == "TS05" for s in smells)
    
    def test_detects_same_var_comparison(self):
        code = """
        def test_same_var():
            x = get_value()
            assert x == x
        """
        smells = analyze_code(code)
        assert any(s.rule == "TS05" for s in smells)
    
    def test_valid_assertion_ok(self):
        code = """
        def test_valid():
            x = calculate()
            assert x == expected
        """
        smells = analyze_code(code)
        assert not any(s.rule == "TS05" for s in smells)


class TestMagicNumber:
    """TS06: Magic numbers in assertions."""
    
    def test_detects_magic_number(self):
        code = """
        def test_magic():
            result = calculate()
            assert result == 42
        """
        smells = analyze_code(code)
        assert any(s.rule == "TS06" for s in smells)
    
    def test_common_values_ok(self):
        code = """
        def test_common_values():
            assert len(items) == 0
            assert count == 1
            assert index == -1
        """
        smells = analyze_code(code)
        assert not any(s.rule == "TS06" for s in smells)


class TestExceptionHandling:
    """TS07: Bare except swallowing errors."""
    
    def test_detects_bare_except(self):
        code = """
        def test_swallows():
            try:
                risky_operation()
            except:
                pass
        """
        smells = analyze_code(code)
        assert any(s.rule == "TS07" for s in smells)
    
    def test_detects_exception_pass(self):
        code = """
        def test_exception_pass():
            try:
                risky_operation()
            except Exception:
                pass
        """
        smells = analyze_code(code)
        assert any(s.rule == "TS07" for s in smells)
    
    def test_specific_exception_ok(self):
        code = """
        def test_specific():
            try:
                risky_operation()
            except ValueError:
                assert True
        """
        smells = analyze_code(code)
        assert not any(s.rule == "TS07" for s in smells)


class TestObscureSetup:
    """TS08: Too many local variables."""
    
    def test_detects_many_variables(self):
        code = """
        def test_obscure():
            a = 1
            b = 2
            c = 3
            d = 4
            e = 5
            f = 6
            g = 7
            h = 8
            i = 9
            j = 10
            k = 11
            assert a + b + c + d + e + f + g + h + i + j + k > 0
        """
        smells = analyze_code(code)
        assert any(s.rule == "TS08" for s in smells)
    
    def test_few_variables_ok(self):
        code = """
        def test_simple():
            a = 1
            b = 2
            assert a + b == 3
        """
        smells = analyze_code(code)
        assert not any(s.rule == "TS08" for s in smells)


class TestSleepyTest:
    """TS09: time.sleep() calls."""
    
    def test_detects_sleep(self):
        code = """
        import time
        
        def test_sleepy():
            start_process()
            time.sleep(5)
            assert is_done()
        """
        smells = analyze_code(code)
        assert any(s.rule == "TS09" for s in smells)


class TestRedundantPrint:
    """TS10: print() in tests."""
    
    def test_detects_print(self):
        code = """
        def test_prints():
            result = calculate()
            print(f"Debug: {result}")
            assert result > 0
        """
        smells = analyze_code(code)
        assert any(s.rule == "TS10" for s in smells)


class TestSuboptimalAssert:
    """TS11: Suboptimal unittest assertions."""
    
    def test_detects_assertEqual_true(self):
        code = """
        import unittest
        
        class TestSuboptimal(unittest.TestCase):
            def test_suboptimal(self):
                self.assertEqual(is_valid(), True)
        """
        smells = analyze_code(code)
        assert any(s.rule == "TS11" for s in smells)
    
    def test_detects_assertEqual_none(self):
        code = """
        import unittest
        
        class TestSuboptimal(unittest.TestCase):
            def test_suboptimal(self):
                self.assertEqual(get_value(), None)
        """
        smells = analyze_code(code)
        assert any(s.rule == "TS11" for s in smells)
    
    def test_detects_assertTrue_isinstance(self):
        code = """
        import unittest
        
        class TestSuboptimal(unittest.TestCase):
            def test_suboptimal(self):
                self.assertTrue(isinstance(obj, MyClass))
        """
        smells = analyze_code(code)
        assert any(s.rule == "TS11" for s in smells)


class TestLongTest:
    """TS14: Long test methods."""
    
    def test_detects_long_test(self):
        # Generate a test with many lines
        lines = ["def test_long():"]
        for i in range(60):
            lines.append(f"    x{i} = {i}")
        lines.append("    assert True")
        code = "\n".join(lines)
        
        smells = analyze_code(code)
        assert any(s.rule == "TS14" for s in smells)


class TestEagerTest:
    """TS12: Tests calling many production methods."""
    
    def test_detects_eager_test(self):
        code = """
        def test_eager():
            obj = create_object()
            obj.setup()
            obj.configure()
            obj.initialize()
            obj.validate()
            obj.process()
            obj.finalize()
            assert obj.is_complete()
        """
        smells = analyze_code(code)
        assert any(s.rule == "TS12" for s in smells)


class TestGrading:
    """Test grade calculation."""
    
    def test_perfect_score(self):
        smells = []
        grade, score = calculate_grade(smells)
        assert grade == "A"
        assert score == 100
    
    def test_error_penalty(self):
        smells = [Smell("TS03", "test", "file.py", 1, severity=Severity.ERROR)]
        grade, score = calculate_grade(smells)
        assert score == 85
    
    def test_warning_penalty(self):
        smells = [Smell("TS01", "test", "file.py", 1, severity=Severity.WARNING)]
        grade, score = calculate_grade(smells)
        assert score == 95
    
    def test_info_penalty(self):
        smells = [Smell("TS06", "test", "file.py", 1, severity=Severity.INFO)]
        grade, score = calculate_grade(smells)
        assert score == 98
    
    def test_grade_boundaries(self):
        # A: 90-100
        _, score = calculate_grade([])
        grade, _ = calculate_grade([])
        assert grade == "A"
        
        # F: <60
        many_errors = [
            Smell("TS03", "test", "file.py", i, severity=Severity.ERROR)
            for i in range(10)
        ]
        grade, score = calculate_grade(many_errors)
        assert grade == "F"
        assert score == 0  # 100 - 150 = -50, clamped to 0


class TestFileScanning:
    """Test file scanning functionality."""
    
    def test_scan_test_file(self):
        code = textwrap.dedent("""
        def test_example():
            assert True
        """)
        
        with tempfile.NamedTemporaryFile(
            mode="w",
            suffix=".py",
            prefix="test_",
            delete=False
        ) as f:
            f.write(code)
            f.flush()
            
            result = scan_file(f.name)
            assert result.files_scanned == 1
            assert result.tests_analyzed == 1
            # assert True is redundant
            assert any(s.rule == "TS05" for s in result.smells)
    
    def test_skip_non_test_file(self):
        code = textwrap.dedent("""
        def some_function():
            return 42
        """)
        
        with tempfile.NamedTemporaryFile(
            mode="w",
            suffix=".py",
            prefix="app_",
            delete=False
        ) as f:
            f.write(code)
            f.flush()
            
            result = scan_file(f.name)
            assert result.files_scanned == 0


class TestUnittestPatterns:
    """Test unittest-specific patterns."""
    
    def test_detects_unittest_assertions(self):
        code = """
        import unittest
        
        class TestExample(unittest.TestCase):
            def test_something(self):
                self.assertEqual(1, 1)
                self.assertEqual(2, 2)
        """
        smells = analyze_code(code)
        # Should detect assertion roulette (2 assertions no messages)
        assert any(s.rule == "TS01" for s in smells)
    
    def test_testcase_inheritance(self):
        code = """
        import unittest
        
        class TestExample(unittest.TestCase):
            def test_empty(self):
                pass
        """
        smells = analyze_code(code)
        assert any(s.rule == "TS03" for s in smells)


class TestPytestPatterns:
    """Test pytest-specific patterns."""
    
    def test_fixture_usage_ok(self):
        code = """
        import pytest
        
        @pytest.fixture
        def sample_data():
            return [1, 2, 3]
        
        def test_with_fixture(sample_data):
            assert len(sample_data) == 3
        """
        smells = analyze_code(code)
        # Should not flag for fixture usage
        assert not any(s.rule == "TS11" for s in smells)


if __name__ == "__main__":
    import pytest
    pytest.main([__file__, "-v"])
