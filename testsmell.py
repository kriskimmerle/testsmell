#!/usr/bin/env python3
"""
testsmell - Python Test Smell Detector

Zero-dependency static analysis tool that detects test smells in Python test code.
Supports pytest and unittest test files.

Usage:
    python testsmell.py <path>           # Scan file or directory
    python testsmell.py <path> --json    # JSON output
    python testsmell.py <path> --check   # CI mode (exit 1 if smells found)
    python testsmell.py <path> --verbose # Show smell details

Test Smells Detected:
    TS01: Assertion Roulette - Multiple assertions without messages
    TS02: Conditional Test Logic - if/for/while in test methods
    TS03: Empty Test - Test with no executable statements
    TS04: Duplicate Assert - Same assertion repeated
    TS05: Redundant Assertion - Tautological assertions (assert True)
    TS06: Magic Number Test - Numeric literals in assertions
    TS07: Exception Handling - Bare try/except swallowing errors
    TS08: Obscure Inline Setup - Too many local variables (>10)
    TS09: Sleepy Test - time.sleep() calls in tests
    TS10: Redundant Print - print() statements in tests
    TS11: Suboptimal Assert - assertEqual(x, True) → assertTrue(x)
    TS12: Eager Test - Test calling multiple production methods
    TS13: Assertion-Free Test - Test with no assertions
    TS14: Long Test Method - Test method too long (>50 lines)
"""

from __future__ import annotations

import argparse
import ast
import json
import os
import sys
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Iterator


__version__ = "0.1.0"


class Severity(Enum):
    """Smell severity levels."""
    INFO = "info"
    WARNING = "warning"
    ERROR = "error"


@dataclass
class Smell:
    """A detected test smell."""
    rule: str
    message: str
    file: str
    line: int
    column: int = 0
    severity: Severity = Severity.WARNING
    test_name: str = ""
    suggestion: str = ""


@dataclass
class TestMethod:
    """Represents a test method for analysis."""
    name: str
    node: ast.FunctionDef
    file: str
    line: int
    is_pytest: bool = False


@dataclass
class ScanResult:
    """Results from scanning a file or directory."""
    smells: list[Smell] = field(default_factory=list)
    files_scanned: int = 0
    tests_analyzed: int = 0
    
    def add(self, smell: Smell) -> None:
        self.smells.append(smell)
    
    def merge(self, other: "ScanResult") -> None:
        self.smells.extend(other.smells)
        self.files_scanned += other.files_scanned
        self.tests_analyzed += other.tests_analyzed


# Assertion method patterns
PYTEST_ASSERTIONS = {"assert"}
UNITTEST_ASSERTIONS = {
    "assertEqual", "assertNotEqual", "assertTrue", "assertFalse",
    "assertIs", "assertIsNot", "assertIsNone", "assertIsNotNone",
    "assertIn", "assertNotIn", "assertIsInstance", "assertNotIsInstance",
    "assertRaises", "assertRaisesRegex", "assertWarns", "assertWarnsRegex",
    "assertLogs", "assertNoLogs", "assertAlmostEqual", "assertNotAlmostEqual",
    "assertGreater", "assertGreaterEqual", "assertLess", "assertLessEqual",
    "assertRegex", "assertNotRegex", "assertCountEqual",
    "assertMultiLineEqual", "assertSequenceEqual", "assertListEqual",
    "assertTupleEqual", "assertSetEqual", "assertDictEqual",
    "fail", "failIf", "failUnless",
}

# Suboptimal assertion patterns (what to use instead)
SUBOPTIMAL_PATTERNS = {
    ("assertEqual", "True"): ("assertTrue", "Use assertTrue(x) instead of assertEqual(x, True)"),
    ("assertEqual", "False"): ("assertFalse", "Use assertFalse(x) instead of assertEqual(x, False)"),
    ("assertEqual", "None"): ("assertIsNone", "Use assertIsNone(x) instead of assertEqual(x, None)"),
    ("assertNotEqual", "None"): ("assertIsNotNone", "Use assertIsNotNone(x) instead of assertNotEqual(x, None)"),
    ("assertTrue", "isinstance"): ("assertIsInstance", "Use assertIsInstance(x, type) instead of assertTrue(isinstance(x, type))"),
    ("assertTrue", "in"): ("assertIn", "Use assertIn(a, b) instead of assertTrue(a in b)"),
    ("assertFalse", "in"): ("assertNotIn", "Use assertNotIn(a, b) instead of assertFalse(a in b)"),
    ("assertTrue", "=="): ("assertEqual", "Use assertEqual(a, b) instead of assertTrue(a == b)"),
    ("assertTrue", "!="): ("assertNotEqual", "Use assertNotEqual(a, b) instead of assertTrue(a != b)"),
    ("assertEqual", "len"): ("assertCountEqual", "Consider assertCountEqual for length comparisons"),
}


class SmellDetector(ast.NodeVisitor):
    """AST visitor that detects test smells."""
    
    def __init__(self, file_path: str, source: str):
        self.file_path = file_path
        self.source = source
        self.source_lines = source.splitlines()
        self.smells: list[Smell] = []
        self.current_test: TestMethod | None = None
        self.is_test_file = self._is_test_file(file_path)
        self.uses_pytest = False
        self.uses_unittest = False
        self.tests_analyzed = 0
        self._in_test_class = False  # Track if we're inside a test class
        
    def _is_test_file(self, path: str) -> bool:
        """Check if file is a test file by name convention."""
        name = os.path.basename(path).lower()
        return (
            name.startswith("test_") or 
            name.endswith("_test.py") or 
            name == "tests.py" or
            name.startswith("test") and name.endswith(".py")
        )
    
    def _add_smell(
        self,
        rule: str,
        message: str,
        line: int,
        column: int = 0,
        severity: Severity = Severity.WARNING,
        suggestion: str = ""
    ) -> None:
        """Add a smell to the results."""
        test_name = self.current_test.name if self.current_test else ""
        self.smells.append(Smell(
            rule=rule,
            message=message,
            file=self.file_path,
            line=line,
            column=column,
            severity=severity,
            test_name=test_name,
            suggestion=suggestion,
        ))
    
    def _is_test_method(self, node: ast.FunctionDef) -> bool:
        """Check if a function is a test method."""
        name = node.name
        # pytest: test_* functions
        if name.startswith("test_") or name.startswith("test"):
            return True
        # unittest: test* methods in TestCase classes
        if name.startswith("test"):
            return True
        return False
    
    def _is_test_class(self, node: ast.ClassDef) -> bool:
        """Check if a class is a test class."""
        name = node.name
        # Check name pattern
        if name.startswith("Test") or name.endswith("Test") or name.endswith("Tests"):
            return True
        # Check inheritance from TestCase
        for base in node.bases:
            if isinstance(base, ast.Attribute):
                if base.attr in ("TestCase", "IsolatedAsyncioTestCase"):
                    return True
            elif isinstance(base, ast.Name):
                if base.id in ("TestCase", "IsolatedAsyncioTestCase"):
                    return True
        return False
    
    def _count_assertions(self, node: ast.AST) -> int:
        """Count assertion statements in a node."""
        count = 0
        for child in ast.walk(node):
            if isinstance(child, ast.Assert):
                count += 1
            elif isinstance(child, ast.Call):
                if isinstance(child.func, ast.Attribute):
                    if child.func.attr in UNITTEST_ASSERTIONS:
                        count += 1
                elif isinstance(child.func, ast.Name):
                    if child.func.id in UNITTEST_ASSERTIONS:
                        count += 1
        return count
    
    def _get_assertion_messages(self, node: ast.AST) -> list[tuple[int, bool]]:
        """Get assertion locations and whether they have messages."""
        assertions = []
        for child in ast.walk(node):
            if isinstance(child, ast.Assert):
                has_msg = child.msg is not None
                assertions.append((child.lineno, has_msg))
            elif isinstance(child, ast.Call):
                if isinstance(child.func, ast.Attribute):
                    if child.func.attr in UNITTEST_ASSERTIONS:
                        # Check if last arg is a message (string)
                        has_msg = (
                            len(child.args) > self._expected_args(child.func.attr) or
                            "msg" in [kw.arg for kw in child.keywords]
                        )
                        assertions.append((child.lineno, has_msg))
        return assertions
    
    def _expected_args(self, method: str) -> int:
        """Get expected number of args for assertion method (excluding msg)."""
        single_arg = {"assertTrue", "assertFalse", "assertIsNone", "assertIsNotNone", "fail"}
        if method in single_arg:
            return 1
        return 2
    
    def _has_control_flow(self, node: ast.AST) -> list[ast.AST]:
        """Find control flow statements in a node."""
        control_nodes = []
        for child in ast.walk(node):
            if isinstance(child, (ast.If, ast.For, ast.While)):
                # Skip pytest.raises context managers
                if isinstance(child, ast.If):
                    control_nodes.append(child)
                elif isinstance(child, (ast.For, ast.While)):
                    control_nodes.append(child)
        return control_nodes
    
    def _count_local_variables(self, node: ast.FunctionDef) -> int:
        """Count local variable assignments in a function."""
        count = 0
        for child in ast.walk(node):
            if isinstance(child, ast.Assign):
                for target in child.targets:
                    if isinstance(target, ast.Name):
                        count += 1
                    elif isinstance(target, ast.Tuple):
                        count += len(target.elts)
            elif isinstance(child, ast.AnnAssign) and child.target:
                count += 1
        return count
    
    def _find_sleep_calls(self, node: ast.AST) -> list[ast.Call]:
        """Find time.sleep() calls."""
        sleeps = []
        for child in ast.walk(node):
            if isinstance(child, ast.Call):
                if isinstance(child.func, ast.Attribute):
                    if child.func.attr == "sleep":
                        if isinstance(child.func.value, ast.Name):
                            if child.func.value.id == "time":
                                sleeps.append(child)
        return sleeps
    
    def _find_print_calls(self, node: ast.AST) -> list[ast.Call]:
        """Find print() calls."""
        prints = []
        for child in ast.walk(node):
            if isinstance(child, ast.Call):
                if isinstance(child.func, ast.Name):
                    if child.func.id == "print":
                        prints.append(child)
        return prints
    
    def _find_bare_except(self, node: ast.AST) -> list[ast.ExceptHandler]:
        """Find bare except handlers that swallow errors."""
        handlers = []
        for child in ast.walk(node):
            if isinstance(child, ast.ExceptHandler):
                # Bare except or except Exception with pass/...
                if child.type is None:
                    handlers.append(child)
                elif isinstance(child.type, ast.Name):
                    if child.type.id == "Exception":
                        # Check if body just passes
                        if len(child.body) == 1:
                            if isinstance(child.body[0], ast.Pass):
                                handlers.append(child)
                            elif isinstance(child.body[0], ast.Expr):
                                if isinstance(child.body[0].value, ast.Constant):
                                    if child.body[0].value.value is ...:
                                        handlers.append(child)
        return handlers
    
    def _check_redundant_assertion(self, node: ast.Assert) -> str | None:
        """Check if assertion is redundant/tautological."""
        test = node.test
        
        # assert True / assert False
        if isinstance(test, ast.Constant):
            if test.value is True:
                return "assert True is always true"
            if test.value is False:
                return "assert False always fails"
        
        # assert 1 == 1, assert x == x
        if isinstance(test, ast.Compare):
            if len(test.ops) == 1 and len(test.comparators) == 1:
                left = test.left
                right = test.comparators[0]
                op = test.ops[0]
                
                # Literal == Literal
                if isinstance(left, ast.Constant) and isinstance(right, ast.Constant):
                    if isinstance(op, ast.Eq) and left.value == right.value:
                        return f"assert {left.value} == {right.value} is always true"
                    if isinstance(op, ast.NotEq) and left.value == right.value:
                        return f"assert {left.value} != {right.value} is always false"
                
                # x == x
                if isinstance(left, ast.Name) and isinstance(right, ast.Name):
                    if left.id == right.id:
                        if isinstance(op, ast.Eq):
                            return f"assert {left.id} == {left.id} is always true"
                        if isinstance(op, ast.Is):
                            return f"assert {left.id} is {left.id} is always true"
        
        # assert not False
        if isinstance(test, ast.UnaryOp) and isinstance(test.op, ast.Not):
            if isinstance(test.operand, ast.Constant):
                if test.operand.value is False:
                    return "assert not False is always true"
        
        return None
    
    def _check_magic_numbers(self, node: ast.Assert) -> list[tuple[int, ast.Constant]]:
        """Find magic numbers in assertions."""
        magic = []
        
        def check_node(n: ast.AST) -> None:
            if isinstance(n, ast.Constant):
                if isinstance(n.value, (int, float)):
                    # Skip common non-magic values
                    if n.value not in (0, 1, -1, 2, 0.0, 1.0, -1.0):
                        magic.append((n.lineno, n))
            for child in ast.iter_child_nodes(n):
                check_node(child)
        
        check_node(node.test)
        return magic
    
    def _check_suboptimal_unittest(self, node: ast.Call) -> str | None:
        """Check for suboptimal unittest assertions."""
        if not isinstance(node.func, ast.Attribute):
            return None
        
        method = node.func.attr
        
        # assertEqual(x, True) → assertTrue(x)
        if method == "assertEqual" and len(node.args) >= 2:
            second = node.args[1]
            if isinstance(second, ast.Constant):
                if second.value is True:
                    return "Use assertTrue(x) instead of assertEqual(x, True)"
                if second.value is False:
                    return "Use assertFalse(x) instead of assertEqual(x, False)"
                if second.value is None:
                    return "Use assertIsNone(x) instead of assertEqual(x, None)"
        
        # assertNotEqual(x, None) → assertIsNotNone(x)
        if method == "assertNotEqual" and len(node.args) >= 2:
            second = node.args[1]
            if isinstance(second, ast.Constant) and second.value is None:
                return "Use assertIsNotNone(x) instead of assertNotEqual(x, None)"
        
        # assertTrue(isinstance(x, Y)) → assertIsInstance(x, Y)
        if method == "assertTrue" and len(node.args) >= 1:
            arg = node.args[0]
            if isinstance(arg, ast.Call):
                if isinstance(arg.func, ast.Name) and arg.func.id == "isinstance":
                    return "Use assertIsInstance(x, type) instead of assertTrue(isinstance(x, type))"
            # assertTrue(a in b) → assertIn(a, b)
            if isinstance(arg, ast.Compare):
                if len(arg.ops) == 1 and isinstance(arg.ops[0], ast.In):
                    return "Use assertIn(a, b) instead of assertTrue(a in b)"
                if len(arg.ops) == 1 and isinstance(arg.ops[0], ast.Eq):
                    return "Use assertEqual(a, b) instead of assertTrue(a == b)"
        
        # assertFalse(a in b) → assertNotIn(a, b)
        if method == "assertFalse" and len(node.args) >= 1:
            arg = node.args[0]
            if isinstance(arg, ast.Compare):
                if len(arg.ops) == 1 and isinstance(arg.ops[0], ast.In):
                    return "Use assertNotIn(a, b) instead of assertFalse(a in b)"
        
        return None
    
    def _count_production_calls(self, node: ast.FunctionDef) -> int:
        """Count calls to non-test, non-assertion methods."""
        count = 0
        for child in ast.walk(node):
            if isinstance(child, ast.Call):
                if isinstance(child.func, ast.Attribute):
                    method = child.func.attr
                    # Skip assertions, setup, internal
                    if method not in UNITTEST_ASSERTIONS and not method.startswith("_"):
                        if not method.startswith("assert"):
                            count += 1
                elif isinstance(child.func, ast.Name):
                    if child.func.id not in UNITTEST_ASSERTIONS:
                        count += 1
        return count
    
    def _get_duplicate_assertions(self, node: ast.FunctionDef) -> list[tuple[int, str]]:
        """Find duplicate assertion statements."""
        seen: dict[str, int] = {}
        duplicates = []
        
        for child in ast.walk(node):
            if isinstance(child, ast.Assert):
                # Get source representation
                try:
                    src = ast.unparse(child)
                    if src in seen:
                        duplicates.append((child.lineno, src[:50]))
                    else:
                        seen[src] = child.lineno
                except Exception:
                    pass
            elif isinstance(child, ast.Expr) and isinstance(child.value, ast.Call):
                call = child.value
                if isinstance(call.func, ast.Attribute):
                    if call.func.attr in UNITTEST_ASSERTIONS:
                        try:
                            src = ast.unparse(child)
                            if src in seen:
                                duplicates.append((child.lineno, src[:50]))
                            else:
                                seen[src] = child.lineno
                        except Exception:
                            pass
        
        return duplicates
    
    def _analyze_test_method(self, node: ast.FunctionDef) -> None:
        """Analyze a single test method for smells."""
        self.current_test = TestMethod(
            name=node.name,
            node=node,
            file=self.file_path,
            line=node.lineno,
        )
        self.tests_analyzed += 1
        
        # Calculate test length
        test_lines = node.end_lineno - node.lineno + 1 if node.end_lineno else 0
        
        # TS03: Empty Test
        body_stmts = [s for s in node.body if not isinstance(s, ast.Pass) and 
                     not (isinstance(s, ast.Expr) and isinstance(s.value, ast.Constant))]
        if len(body_stmts) == 0:
            self._add_smell(
                "TS03", "Empty test - no executable statements",
                node.lineno, severity=Severity.ERROR,
                suggestion="Add test logic or remove the empty test"
            )
            self.current_test = None
            return
        
        # TS13: Assertion-Free Test
        assertion_count = self._count_assertions(node)
        if assertion_count == 0:
            # Check for pytest.raises context manager
            has_raises = False
            for child in ast.walk(node):
                if isinstance(child, ast.With):
                    for item in child.items:
                        if isinstance(item.context_expr, ast.Call):
                            call = item.context_expr
                            if isinstance(call.func, ast.Attribute):
                                if call.func.attr == "raises":
                                    has_raises = True
            
            if not has_raises:
                self._add_smell(
                    "TS13", "Test has no assertions",
                    node.lineno, severity=Severity.ERROR,
                    suggestion="Add assertions to verify expected behavior"
                )
        
        # TS01: Assertion Roulette
        assertions = self._get_assertion_messages(node)
        if len(assertions) > 1:
            without_msg = [a for a in assertions if not a[1]]
            if len(without_msg) > 1:
                self._add_smell(
                    "TS01", f"Assertion roulette - {len(without_msg)} assertions without messages",
                    node.lineno, severity=Severity.WARNING,
                    suggestion="Add descriptive messages to assertions for better debugging"
                )
        
        # TS02: Conditional Test Logic
        control_nodes = self._has_control_flow(node)
        for ctrl in control_nodes:
            self._add_smell(
                "TS02", f"Conditional logic in test ({type(ctrl).__name__})",
                ctrl.lineno, severity=Severity.WARNING,
                suggestion="Consider parameterized tests instead of conditionals"
            )
        
        # TS04: Duplicate Assert
        duplicates = self._get_duplicate_assertions(node)
        for line, src in duplicates:
            self._add_smell(
                "TS04", f"Duplicate assertion",
                line, severity=Severity.WARNING,
                suggestion="Remove duplicate assertion or verify it's intentional"
            )
        
        # TS05: Redundant Assertion
        for child in ast.walk(node):
            if isinstance(child, ast.Assert):
                redundant = self._check_redundant_assertion(child)
                if redundant:
                    self._add_smell(
                        "TS05", f"Redundant assertion - {redundant}",
                        child.lineno, severity=Severity.ERROR,
                        suggestion="Remove tautological assertion"
                    )
        
        # TS06: Magic Number Test
        for child in ast.walk(node):
            if isinstance(child, ast.Assert):
                magic = self._check_magic_numbers(child)
                for line, const in magic:
                    self._add_smell(
                        "TS06", f"Magic number in assertion: {const.value}",
                        line, severity=Severity.INFO,
                        suggestion="Use named constants or variables for clarity"
                    )
        
        # TS07: Exception Handling
        bare_excepts = self._find_bare_except(node)
        for handler in bare_excepts:
            self._add_smell(
                "TS07", "Bare except clause swallows errors",
                handler.lineno, severity=Severity.ERROR,
                suggestion="Use pytest.raises or assertRaises for expected exceptions"
            )
        
        # TS08: Obscure Inline Setup
        var_count = self._count_local_variables(node)
        if var_count > 10:
            self._add_smell(
                "TS08", f"Obscure inline setup - {var_count} local variables",
                node.lineno, severity=Severity.WARNING,
                suggestion="Extract setup to fixtures or setup methods"
            )
        
        # TS09: Sleepy Test
        sleeps = self._find_sleep_calls(node)
        for sleep_call in sleeps:
            self._add_smell(
                "TS09", "time.sleep() call makes test slow",
                sleep_call.lineno, severity=Severity.WARNING,
                suggestion="Use mocking or async patterns instead of sleep"
            )
        
        # TS10: Redundant Print
        prints = self._find_print_calls(node)
        for print_call in prints:
            self._add_smell(
                "TS10", "print() statement in test",
                print_call.lineno, severity=Severity.INFO,
                suggestion="Use logging or remove debug prints"
            )
        
        # TS11: Suboptimal Assert (unittest)
        for child in ast.walk(node):
            if isinstance(child, ast.Call):
                suboptimal = self._check_suboptimal_unittest(child)
                if suboptimal:
                    self._add_smell(
                        "TS11", f"Suboptimal assertion",
                        child.lineno, severity=Severity.INFO,
                        suggestion=suboptimal
                    )
        
        # TS12: Eager Test (many production calls)
        prod_calls = self._count_production_calls(node)
        if prod_calls > 5:
            self._add_smell(
                "TS12", f"Eager test - {prod_calls} production method calls",
                node.lineno, severity=Severity.INFO,
                suggestion="Consider splitting into multiple focused tests"
            )
        
        # TS14: Long Test Method
        if test_lines > 50:
            self._add_smell(
                "TS14", f"Long test method - {test_lines} lines",
                node.lineno, severity=Severity.WARNING,
                suggestion="Split into smaller, focused tests"
            )
        
        self.current_test = None
    
    def visit_Import(self, node: ast.Import) -> None:
        """Track imports to detect test framework."""
        for alias in node.names:
            if alias.name == "pytest":
                self.uses_pytest = True
            elif alias.name == "unittest":
                self.uses_unittest = True
        self.generic_visit(node)
    
    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        """Track imports to detect test framework."""
        if node.module == "pytest":
            self.uses_pytest = True
        elif node.module and node.module.startswith("unittest"):
            self.uses_unittest = True
        self.generic_visit(node)
    
    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        """Visit test classes."""
        if self._is_test_class(node):
            self._in_test_class = True
            for item in node.body:
                if isinstance(item, ast.FunctionDef) and self._is_test_method(item):
                    self._analyze_test_method(item)
            self._in_test_class = False
            # Don't call generic_visit for test classes - we manually handled them
            return
        self.generic_visit(node)
    
    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        """Visit top-level test functions (pytest style)."""
        # Only process top-level functions (not methods inside classes)
        if self._is_test_method(node) and not self._in_test_class:
            self._analyze_test_method(node)
        self.generic_visit(node)
    
    visit_AsyncFunctionDef = visit_FunctionDef


def scan_file(file_path: str) -> ScanResult:
    """Scan a single Python file for test smells."""
    result = ScanResult()
    
    try:
        with open(file_path, "r", encoding="utf-8", errors="replace") as f:
            source = f.read()
    except Exception as e:
        return result
    
    # Check if it looks like a test file
    detector = SmellDetector(file_path, source)
    if not detector.is_test_file:
        return result
    
    try:
        tree = ast.parse(source, filename=file_path)
    except SyntaxError:
        return result
    
    result.files_scanned = 1
    detector.visit(tree)
    result.smells = detector.smells
    result.tests_analyzed = detector.tests_analyzed
    
    return result


def scan_directory(dir_path: str, exclude_patterns: list[str] | None = None) -> ScanResult:
    """Recursively scan a directory for test files."""
    result = ScanResult()
    exclude = exclude_patterns or []
    
    for root, dirs, files in os.walk(dir_path):
        # Skip excluded directories
        dirs[:] = [d for d in dirs if d not in exclude and not d.startswith(".")]
        
        for file in files:
            if file.endswith(".py"):
                file_path = os.path.join(root, file)
                file_result = scan_file(file_path)
                result.merge(file_result)
    
    return result


def scan_path(path: str) -> ScanResult:
    """Scan a file or directory."""
    if os.path.isfile(path):
        return scan_file(path)
    elif os.path.isdir(path):
        return scan_directory(path)
    else:
        return ScanResult()


def calculate_grade(smells: list[Smell]) -> tuple[str, int]:
    """Calculate letter grade based on smells."""
    score = 100
    
    for smell in smells:
        if smell.severity == Severity.ERROR:
            score -= 15
        elif smell.severity == Severity.WARNING:
            score -= 5
        elif smell.severity == Severity.INFO:
            score -= 2
    
    score = max(0, score)
    
    if score >= 90:
        return "A", score
    elif score >= 80:
        return "B", score
    elif score >= 70:
        return "C", score
    elif score >= 60:
        return "D", score
    else:
        return "F", score


def format_text_output(result: ScanResult, verbose: bool = False) -> str:
    """Format results as text."""
    lines = []
    
    if not result.smells:
        lines.append("✓ No test smells detected")
        lines.append(f"  Files scanned: {result.files_scanned}")
        lines.append(f"  Tests analyzed: {result.tests_analyzed}")
        return "\n".join(lines)
    
    # Group by file
    by_file: dict[str, list[Smell]] = {}
    for smell in result.smells:
        by_file.setdefault(smell.file, []).append(smell)
    
    for file_path, smells in sorted(by_file.items()):
        lines.append(f"\n{file_path}")
        for smell in sorted(smells, key=lambda s: s.line):
            severity_icon = {
                Severity.ERROR: "✗",
                Severity.WARNING: "⚠",
                Severity.INFO: "ℹ",
            }[smell.severity]
            
            test_info = f" ({smell.test_name})" if smell.test_name else ""
            lines.append(f"  {severity_icon} Line {smell.line}{test_info}: [{smell.rule}] {smell.message}")
            
            if verbose and smell.suggestion:
                lines.append(f"      → {smell.suggestion}")
    
    # Summary
    grade, score = calculate_grade(result.smells)
    error_count = sum(1 for s in result.smells if s.severity == Severity.ERROR)
    warning_count = sum(1 for s in result.smells if s.severity == Severity.WARNING)
    info_count = sum(1 for s in result.smells if s.severity == Severity.INFO)
    
    lines.append(f"\n{'─' * 50}")
    lines.append(f"Grade: {grade} ({score}/100)")
    lines.append(f"Files scanned: {result.files_scanned}")
    lines.append(f"Tests analyzed: {result.tests_analyzed}")
    lines.append(f"Smells: {len(result.smells)} ({error_count} errors, {warning_count} warnings, {info_count} info)")
    
    return "\n".join(lines)


def format_json_output(result: ScanResult) -> str:
    """Format results as JSON."""
    grade, score = calculate_grade(result.smells)
    
    output = {
        "version": __version__,
        "grade": grade,
        "score": score,
        "files_scanned": result.files_scanned,
        "tests_analyzed": result.tests_analyzed,
        "total_smells": len(result.smells),
        "smells": [
            {
                "rule": s.rule,
                "message": s.message,
                "file": s.file,
                "line": s.line,
                "column": s.column,
                "severity": s.severity.value,
                "test_name": s.test_name,
                "suggestion": s.suggestion,
            }
            for s in result.smells
        ],
    }
    
    return json.dumps(output, indent=2)


def main() -> int:
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="Detect test smells in Python test code",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Test Smell Rules:
  TS01  Assertion Roulette     Multiple assertions without messages
  TS02  Conditional Logic      if/for/while in test methods
  TS03  Empty Test             No executable statements
  TS04  Duplicate Assert       Same assertion repeated
  TS05  Redundant Assertion    Tautological (assert True)
  TS06  Magic Number           Numeric literals without context
  TS07  Exception Handling     Bare except swallowing errors
  TS08  Obscure Inline Setup   Too many local variables
  TS09  Sleepy Test            time.sleep() calls
  TS10  Redundant Print        print() in tests
  TS11  Suboptimal Assert      assertEqual(x, True) etc
  TS12  Eager Test             Too many production calls
  TS13  Assertion-Free         No assertions in test
  TS14  Long Test Method       Over 50 lines

Examples:
  testsmell tests/
  testsmell test_app.py --verbose
  testsmell . --json --check
        """
    )
    parser.add_argument("path", help="File or directory to scan")
    parser.add_argument("--json", action="store_true", help="Output JSON")
    parser.add_argument("--verbose", "-v", action="store_true", help="Show suggestions")
    parser.add_argument("--check", action="store_true", help="Exit 1 if smells found")
    parser.add_argument("--min-score", type=int, default=0, help="Minimum score for --check")
    parser.add_argument("--ignore", action="append", default=[], help="Rules to ignore (e.g. TS06)")
    parser.add_argument("--version", action="version", version=f"testsmell {__version__}")
    
    args = parser.parse_args()
    
    # Scan
    result = scan_path(args.path)
    
    # Filter ignored rules
    if args.ignore:
        result.smells = [s for s in result.smells if s.rule not in args.ignore]
    
    # Output
    if args.json:
        print(format_json_output(result))
    else:
        print(format_text_output(result, verbose=args.verbose))
    
    # Check mode
    if args.check:
        grade, score = calculate_grade(result.smells)
        if score < args.min_score:
            return 1
        if result.smells:
            return 1
    
    return 0


if __name__ == "__main__":
    sys.exit(main())
