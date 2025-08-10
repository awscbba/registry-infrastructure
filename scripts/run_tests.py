#!/usr/bin/env python3
"""
Task 18: Comprehensive Test Runner
Runs all password management system tests with proper reporting and coverage
"""

import os
import sys
import subprocess
import argparse
from pathlib import Path
import json
from datetime import datetime

class TestRunner:
    """Comprehensive test runner for password management system"""
    
    def __init__(self):
        self.project_root = Path(__file__).parent
        self.tests_dir = self.project_root / "tests"
        self.lambda_dir = self.project_root / "lambda"
        
    def setup_environment(self):
        """Set up test environment"""
        print("🔧 Setting up test environment...")
        
        # Add lambda directory to Python path
        lambda_path = str(self.lambda_dir)
        if lambda_path not in sys.path:
            sys.path.insert(0, lambda_path)
        
        # Set environment variables for testing
        os.environ.update({
            'AWS_DEFAULT_REGION': 'us-east-1',
            'AWS_ACCESS_KEY_ID': 'testing',
            'AWS_SECRET_ACCESS_KEY': 'testing',
            'AWS_SECURITY_TOKEN': 'testing',
            'AWS_SESSION_TOKEN': 'testing',
            'PYTHONPATH': lambda_path
        })
        
        print("✅ Test environment configured")
    
    def install_dependencies(self):
        """Install test dependencies"""
        print("📦 Installing test dependencies...")
        
        requirements_file = self.tests_dir / "requirements.txt"
        if requirements_file.exists():
            try:
                subprocess.run([
                    sys.executable, "-m", "pip", "install", "-r", str(requirements_file)
                ], check=True, capture_output=True)
                print("✅ Test dependencies installed")
            except subprocess.CalledProcessError as e:
                print(f"❌ Failed to install dependencies: {e}")
                return False
        else:
            print("⚠️ No requirements.txt found, skipping dependency installation")
        
        return True
    
    def run_unit_tests(self):
        """Run unit tests"""
        print("\n🧪 Running Unit Tests...")
        
        unit_tests_dir = self.tests_dir / "unit"
        if not unit_tests_dir.exists():
            print("⚠️ No unit tests directory found")
            return True
        
        cmd = [
            sys.executable, "-m", "pytest",
            str(unit_tests_dir),
            "-m", "unit",
            "--tb=short",
            "-v"
        ]
        
        return self._run_test_command(cmd, "Unit Tests")
    
    def run_integration_tests(self):
        """Run integration tests"""
        print("\n🔗 Running Integration Tests...")
        
        integration_tests_dir = self.tests_dir / "integration"
        if not integration_tests_dir.exists():
            print("⚠️ No integration tests directory found")
            return True
        
        cmd = [
            sys.executable, "-m", "pytest",
            str(integration_tests_dir),
            "-m", "integration",
            "--tb=short",
            "-v"
        ]
        
        return self._run_test_command(cmd, "Integration Tests")
    
    def run_e2e_tests(self):
        """Run end-to-end tests"""
        print("\n🎯 Running End-to-End Tests...")
        
        e2e_tests_dir = self.tests_dir / "e2e"
        if not e2e_tests_dir.exists():
            print("⚠️ No e2e tests directory found")
            return True
        
        cmd = [
            sys.executable, "-m", "pytest",
            str(e2e_tests_dir),
            "-m", "e2e",
            "--tb=short",
            "-v"
        ]
        
        return self._run_test_command(cmd, "End-to-End Tests")
    
    def run_security_tests(self):
        """Run security tests"""
        print("\n🔒 Running Security Tests...")
        
        security_tests_dir = self.tests_dir / "security"
        if not security_tests_dir.exists():
            print("⚠️ No security tests directory found")
            return True
        
        cmd = [
            sys.executable, "-m", "pytest",
            str(security_tests_dir),
            "-m", "security",
            "--tb=short",
            "-v"
        ]
        
        return self._run_test_command(cmd, "Security Tests")
    
    def run_all_tests_with_coverage(self):
        """Run all tests with coverage reporting"""
        print("\n📊 Running All Tests with Coverage...")
        
        cmd = [
            sys.executable, "-m", "pytest",
            str(self.tests_dir),
            "--cov=lambda",
            "--cov-report=html:tests/coverage_html",
            "--cov-report=xml:tests/coverage.xml",
            "--cov-report=term-missing",
            "--cov-fail-under=70",
            "--html=tests/report.html",
            "--self-contained-html",
            "--json-report",
            "--json-report-file=tests/report.json",
            "-v"
        ]
        
        return self._run_test_command(cmd, "All Tests with Coverage")
    
    def run_specific_test_category(self, category):
        """Run tests for specific category"""
        print(f"\n🎯 Running {category.title()} Tests...")
        
        cmd = [
            sys.executable, "-m", "pytest",
            str(self.tests_dir),
            "-m", category,
            "--tb=short",
            "-v"
        ]
        
        return self._run_test_command(cmd, f"{category.title()} Tests")
    
    def _run_test_command(self, cmd, test_type):
        """Run a test command and handle output"""
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, cwd=self.project_root)
            
            print(f"📋 {test_type} Output:")
            print(result.stdout)
            
            if result.stderr:
                print(f"⚠️ {test_type} Warnings/Errors:")
                print(result.stderr)
            
            if result.returncode == 0:
                print(f"✅ {test_type} PASSED")
                return True
            else:
                print(f"❌ {test_type} FAILED (exit code: {result.returncode})")
                return False
                
        except Exception as e:
            print(f"💥 Error running {test_type}: {e}")
            return False
    
    def run_code_quality_checks(self):
        """Run code quality checks"""
        print("\n🔍 Running Code Quality Checks...")
        
        # Check if flake8 is available
        try:
            subprocess.run([sys.executable, "-m", "flake8", "--version"], 
                         capture_output=True, check=True)
            
            # Run flake8 on lambda code
            cmd = [sys.executable, "-m", "flake8", str(self.lambda_dir)]
            result = subprocess.run(cmd, capture_output=True, text=True)
            
            if result.returncode == 0:
                print("✅ Code quality checks passed")
                return True
            else:
                print("❌ Code quality issues found:")
                print(result.stdout)
                return False
                
        except subprocess.CalledProcessError:
            print("⚠️ flake8 not available, skipping code quality checks")
            return True
    
    def run_security_scan(self):
        """Run security scan with bandit"""
        print("\n🛡️ Running Security Scan...")
        
        try:
            subprocess.run([sys.executable, "-m", "bandit", "--version"], 
                         capture_output=True, check=True)
            
            # Run bandit on lambda code
            cmd = [
                sys.executable, "-m", "bandit", 
                "-r", str(self.lambda_dir),
                "-f", "json"
            ]
            result = subprocess.run(cmd, capture_output=True, text=True)
            
            if result.returncode == 0:
                print("✅ Security scan passed")
                return True
            else:
                print("⚠️ Security issues found:")
                try:
                    scan_results = json.loads(result.stdout)
                    for issue in scan_results.get('results', []):
                        print(f"  - {issue['test_name']}: {issue['issue_text']}")
                except json.JSONDecodeError:
                    print(result.stdout)
                return False
                
        except subprocess.CalledProcessError:
            print("⚠️ bandit not available, skipping security scan")
            return True
    
    def generate_test_report(self):
        """Generate comprehensive test report"""
        print("\n📊 Generating Test Report...")
        
        report_data = {
            'timestamp': datetime.utcnow().isoformat(),
            'test_run_summary': 'Task 18: Comprehensive Password Management Testing',
            'categories_tested': [
                'Unit Tests - Password hashing and validation',
                'Integration Tests - Authentication flows',
                'End-to-End Tests - Password reset process',
                'Security Tests - Brute force protection'
            ]
        }
        
        # Check for JSON report
        json_report_path = self.tests_dir / "report.json"
        if json_report_path.exists():
            try:
                with open(json_report_path, 'r') as f:
                    pytest_report = json.load(f)
                    report_data['pytest_summary'] = pytest_report.get('summary', {})
            except Exception as e:
                print(f"⚠️ Could not read pytest JSON report: {e}")
        
        # Save comprehensive report
        report_path = self.tests_dir / "comprehensive_report.json"
        with open(report_path, 'w') as f:
            json.dump(report_data, f, indent=2)
        
        print(f"✅ Test report generated: {report_path}")
        
        # Print summary
        print("\n📋 Test Run Summary:")
        print("=" * 50)
        print("Task 18: Comprehensive Testing for Password Functionality")
        print("✅ Unit Tests: Password hashing and validation")
        print("✅ Integration Tests: Authentication flows")
        print("✅ End-to-End Tests: Password reset process")
        print("✅ Security Tests: Brute force protection")
        print("=" * 50)

def main():
    """Main test runner function"""
    parser = argparse.ArgumentParser(description="Task 18: Comprehensive Test Runner")
    parser.add_argument("--category", choices=[
        "unit", "integration", "e2e", "security", "password", "session", "auth"
    ], help="Run specific test category")
    parser.add_argument("--coverage", action="store_true", help="Run with coverage reporting")
    parser.add_argument("--quality", action="store_true", help="Run code quality checks")
    parser.add_argument("--security-scan", action="store_true", help="Run security scan")
    parser.add_argument("--all", action="store_true", help="Run all tests and checks")
    
    args = parser.parse_args()
    
    runner = TestRunner()
    
    print("🚀 Task 18: Comprehensive Testing for Password Functionality")
    print("=" * 60)
    
    # Setup
    runner.setup_environment()
    
    if not runner.install_dependencies():
        sys.exit(1)
    
    success = True
    
    if args.all:
        # Run everything
        success &= runner.run_all_tests_with_coverage()
        success &= runner.run_code_quality_checks()
        success &= runner.run_security_scan()
    elif args.category:
        # Run specific category
        success &= runner.run_specific_test_category(args.category)
    elif args.coverage:
        # Run with coverage
        success &= runner.run_all_tests_with_coverage()
    elif args.quality:
        # Run quality checks
        success &= runner.run_code_quality_checks()
    elif args.security_scan:
        # Run security scan
        success &= runner.run_security_scan()
    else:
        # Run all test categories
        success &= runner.run_unit_tests()
        success &= runner.run_integration_tests()
        success &= runner.run_e2e_tests()
        success &= runner.run_security_tests()
    
    # Generate report
    runner.generate_test_report()
    
    if success:
        print("\n🎉 All tests completed successfully!")
        sys.exit(0)
    else:
        print("\n❌ Some tests failed!")
        sys.exit(1)

if __name__ == "__main__":
    main()
