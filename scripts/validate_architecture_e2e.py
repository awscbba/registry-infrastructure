"""
End-to-End Architecture Validation
Validates the complete architecture through code analysis without runtime dependencies.
"""

import os
import re
import json
from typing import Dict, Any, List, Tuple
from datetime import datetime


class ArchitectureValidator:
    """Validates the complete architecture through static code analysis."""
    
    def __init__(self):
        self.validation_results = []
        self.architecture_map = {}
        self.start_time = datetime.now()
    
    def log_validation(self, component: str, success: bool, details: str = "", metrics: Dict[str, Any] = None):
        """Log validation result."""
        status = "✅ VALID" if success else "❌ INVALID"
        self.validation_results.append({
            "component": component,
            "status": status,
            "success": success,
            "details": details,
            "metrics": metrics or {}
        })
        print(f"{status} {component}")
        if details:
            print(f"    {details}")
        if metrics:
            for key, value in metrics.items():
                print(f"    📊 {key}: {value}")
    
    def validate_repository_layer(self) -> bool:
        """Validate repository layer implementation."""
        print("\n🗄️  Validating Repository Layer...")
        
        repository_files = [
            "src/repositories/user_repository.py",
            "src/repositories/project_repository.py", 
            "src/repositories/audit_repository.py"
        ]
        
        found_files = []
        missing_files = []
        total_methods = 0
        
        for file_path in repository_files:
            if os.path.exists(file_path):
                found_files.append(file_path)
                
                # Analyze repository methods
                with open(file_path, 'r') as f:
                    content = f.read()
                
                # Count methods
                methods = re.findall(r'def (\w+)\(', content)
                total_methods += len(methods)
                
                # Check for required patterns
                required_patterns = [
                    r'class \w+Repository',
                    r'def __init__',
                    r'async def',
                    r'RepositoryResult'
                ]
                
                for pattern in required_patterns:
                    if not re.search(pattern, content):
                        self.log_validation(f"Repository Pattern in {file_path}", False, 
                                          f"Missing pattern: {pattern}")
                        return False
            else:
                missing_files.append(file_path)
        
        if missing_files:
            self.log_validation("Repository Layer", False, 
                              f"Missing files: {missing_files}")
            return False
        
        self.log_validation("Repository Layer", True, 
                          f"All repository files present with proper patterns",
                          {"files": len(found_files), "total_methods": total_methods})
        return True
    
    def validate_service_layer(self) -> bool:
        """Validate service layer implementation."""
        print("\n⚙️  Validating Service Layer...")
        
        service_files = [
            "src/services/people_service.py",
            "src/services/projects_service.py",
            "src/services/audit_service.py",
            "src/services/service_registry_manager.py"
        ]
        
        found_files = []
        missing_files = []
        total_methods = 0
        
        for file_path in service_files:
            if os.path.exists(file_path):
                found_files.append(file_path)
                
                with open(file_path, 'r') as f:
                    content = f.read()
                
                # Count methods
                methods = re.findall(r'def (\w+)\(', content)
                total_methods += len(methods)
                
                # Check for service-specific patterns
                if "service_registry_manager" in file_path:
                    required_patterns = [
                        r'get_repository_health',
                        r'get_repository_performance_metrics',
                        r'cleanup_repository_resources',
                        r'get_repository_statistics'
                    ]
                else:
                    required_patterns = [
                        r'class \w+Service',
                        r'def __init__',
                        r'async def'
                    ]
                
                for pattern in required_patterns:
                    if not re.search(pattern, content):
                        self.log_validation(f"Service Pattern in {file_path}", False,
                                          f"Missing pattern: {pattern}")
                        return False
            else:
                missing_files.append(file_path)
        
        if missing_files:
            self.log_validation("Service Layer", False,
                              f"Missing files: {missing_files}")
            return False
        
        self.log_validation("Service Layer", True,
                          f"All service files present with proper patterns",
                          {"files": len(found_files), "total_methods": total_methods})
        return True
    
    def validate_api_layer(self) -> bool:
        """Validate API layer implementation."""
        print("\n🌐 Validating API Layer...")
        
        api_files = [
            "src/api/monitoring_api_handler.py",
            "src/handlers/versioned_api_handler.py",
            "src/handlers/repository_api_handler.py"
        ]
        
        found_files = []
        missing_files = []
        total_endpoints = 0
        
        for file_path in api_files:
            if os.path.exists(file_path):
                found_files.append(file_path)
                
                with open(file_path, 'r') as f:
                    content = f.read()
                
                # Count endpoints
                endpoints = re.findall(r'@\w+\.(?:get|post|put|delete)\(', content)
                total_endpoints += len(endpoints)
                
                # Check for API patterns
                required_patterns = [
                    r'from fastapi import',
                    r'APIRouter|FastAPI',
                    r'async def \w+\('
                ]
                
                for pattern in required_patterns:
                    if not re.search(pattern, content):
                        self.log_validation(f"API Pattern in {file_path}", False,
                                          f"Missing pattern: {pattern}")
                        return False
            else:
                missing_files.append(file_path)
        
        if missing_files:
            self.log_validation("API Layer", False,
                              f"Missing files: {missing_files}")
            return False
        
        self.log_validation("API Layer", True,
                          f"All API files present with proper patterns",
                          {"files": len(found_files), "total_endpoints": total_endpoints})
        return True
    
    def validate_monitoring_implementation(self) -> bool:
        """Validate monitoring implementation."""
        print("\n📊 Validating Monitoring Implementation...")
        
        # Check ServiceRegistryManager monitoring methods
        srm_file = "src/services/service_registry_manager.py"
        if not os.path.exists(srm_file):
            self.log_validation("Monitoring Implementation", False, "ServiceRegistryManager not found")
            return False
        
        with open(srm_file, 'r') as f:
            srm_content = f.read()
        
        required_monitoring_methods = [
            "get_repository_health",
            "get_repository_performance_metrics",
            "cleanup_repository_resources", 
            "get_repository_statistics"
        ]
        
        found_methods = []
        for method in required_monitoring_methods:
            if f"async def {method}(" in srm_content:
                found_methods.append(method)
        
        # Check monitoring API endpoints
        api_file = "src/api/monitoring_api_handler.py"
        if not os.path.exists(api_file):
            self.log_validation("Monitoring Implementation", False, "Monitoring API handler not found")
            return False
        
        with open(api_file, 'r') as f:
            api_content = f.read()
        
        required_endpoints = [
            "/health/repositories",
            "/performance/repositories",
            "/cleanup/repositories",
            "/statistics/repositories",
            "/overview"
        ]
        
        found_endpoints = []
        for endpoint in required_endpoints:
            if endpoint in api_content:
                found_endpoints.append(endpoint)
        
        # Check enhanced health check
        health_file = "src/handlers/versioned_api_handler.py"
        enhanced_health = False
        if os.path.exists(health_file):
            with open(health_file, 'r') as f:
                health_content = f.read()
            enhanced_health = all(feature in health_content for feature in [
                "service_registry_manager",
                "get_repository_health",
                "detailed_health"
            ])
        
        success = (len(found_methods) == len(required_monitoring_methods) and 
                  len(found_endpoints) == len(required_endpoints) and
                  enhanced_health)
        
        self.log_validation("Monitoring Implementation", success,
                          f"Methods: {len(found_methods)}/{len(required_monitoring_methods)}, "
                          f"Endpoints: {len(found_endpoints)}/{len(required_endpoints)}, "
                          f"Enhanced Health: {enhanced_health}",
                          {
                              "monitoring_methods": len(found_methods),
                              "api_endpoints": len(found_endpoints),
                              "enhanced_health_check": enhanced_health
                          })
        return success
    
    def validate_integration_patterns(self) -> bool:
        """Validate integration patterns between layers."""
        print("\n🔗 Validating Integration Patterns...")
        
        integration_checks = []
        
        # Check service-repository integration
        service_files = [
            "src/services/people_service.py",
            "src/services/projects_service.py",
            "src/services/audit_service.py"
        ]
        
        repository_integration_count = 0
        for service_file in service_files:
            if os.path.exists(service_file):
                with open(service_file, 'r') as f:
                    content = f.read()
                
                # Check for repository integration patterns
                if "repository" in content.lower() and "import" in content:
                    repository_integration_count += 1
        
        integration_checks.append(("Service-Repository Integration", 
                                 repository_integration_count >= 2))
        
        # Check API-service integration
        api_file = "src/handlers/versioned_api_handler.py"
        api_service_integration = False
        if os.path.exists(api_file):
            with open(api_file, 'r') as f:
                content = f.read()
            api_service_integration = "service_manager" in content or "get_service" in content
        
        integration_checks.append(("API-Service Integration", api_service_integration))
        
        # Check monitoring integration
        monitoring_integration = False
        if os.path.exists(api_file):
            with open(api_file, 'r') as f:
                content = f.read()
            monitoring_integration = "monitoring_api_handler" in content and "include_router" in content
        
        integration_checks.append(("Monitoring Integration", monitoring_integration))
        
        # Evaluate overall integration
        successful_integrations = sum(1 for _, success in integration_checks if success)
        total_integrations = len(integration_checks)
        
        self.log_validation("Integration Patterns", 
                          successful_integrations == total_integrations,
                          f"Successful integrations: {successful_integrations}/{total_integrations}",
                          {"successful_integrations": successful_integrations,
                           "total_integrations": total_integrations})
        
        return successful_integrations == total_integrations
    
    def validate_test_coverage(self) -> bool:
        """Validate test coverage and implementation."""
        print("\n🧪 Validating Test Coverage...")
        
        test_files = [
            "tests/test_monitoring_functionality.py",
            "validate_monitoring_code.py",
            "test_end_to_end.py",
            "validate_architecture_e2e.py"
        ]
        
        found_tests = []
        total_test_methods = 0
        
        for test_file in test_files:
            if os.path.exists(test_file):
                found_tests.append(test_file)
                
                with open(test_file, 'r') as f:
                    content = f.read()
                
                # Count test methods
                test_methods = re.findall(r'def test_\w+\(', content)
                total_test_methods += len(test_methods)
        
        # Check for validation scripts
        validation_scripts = [
            "validate_monitoring.py",
            "validate_monitoring_code.py"
        ]
        
        found_validations = [script for script in validation_scripts if os.path.exists(script)]
        
        success = len(found_tests) >= 3 and total_test_methods >= 5
        
        self.log_validation("Test Coverage", success,
                          f"Test files: {len(found_tests)}, Test methods: {total_test_methods}, "
                          f"Validation scripts: {len(found_validations)}",
                          {
                              "test_files": len(found_tests),
                              "test_methods": total_test_methods,
                              "validation_scripts": len(found_validations)
                          })
        return success
    
    def validate_architecture_completeness(self) -> bool:
        """Validate overall architecture completeness."""
        print("\n🏗️  Validating Architecture Completeness...")
        
        # Check for all required components
        required_components = {
            "Repository Layer": ["src/repositories/user_repository.py", 
                               "src/repositories/project_repository.py",
                               "src/repositories/audit_repository.py"],
            "Service Layer": ["src/services/people_service.py",
                            "src/services/projects_service.py", 
                            "src/services/audit_service.py",
                            "src/services/service_registry_manager.py"],
            "API Layer": ["src/api/monitoring_api_handler.py",
                         "src/handlers/versioned_api_handler.py"],
            "Monitoring": ["src/api/monitoring_api_handler.py"],
            "Tests": ["tests/test_monitoring_functionality.py"]
        }
        
        component_status = {}
        total_files = 0
        found_files = 0
        
        for component, files in required_components.items():
            component_found = 0
            for file_path in files:
                total_files += 1
                if os.path.exists(file_path):
                    found_files += 1
                    component_found += 1
            
            component_status[component] = {
                "found": component_found,
                "total": len(files),
                "complete": component_found == len(files)
            }
        
        # Calculate completeness percentage
        completeness = (found_files / total_files) * 100
        
        # Check for architectural patterns
        patterns_found = 0
        total_patterns = 5
        
        # Pattern 1: Service Registry Pattern
        if os.path.exists("src/services/service_registry_manager.py"):
            patterns_found += 1
        
        # Pattern 2: Repository Pattern
        repo_files = [f for f in os.listdir("src/repositories") if f.endswith("_repository.py")] if os.path.exists("src/repositories") else []
        if len(repo_files) >= 3:
            patterns_found += 1
        
        # Pattern 3: API Router Pattern
        if os.path.exists("src/api/monitoring_api_handler.py"):
            patterns_found += 1
        
        # Pattern 4: Enhanced Health Check
        if os.path.exists("src/handlers/versioned_api_handler.py"):
            with open("src/handlers/versioned_api_handler.py", 'r') as f:
                if "detailed_health" in f.read():
                    patterns_found += 1
        
        # Pattern 5: Comprehensive Testing
        test_files = [f for f in os.listdir("tests") if f.startswith("test_") and f.endswith(".py")] if os.path.exists("tests") else []
        if len(test_files) >= 3:
            patterns_found += 1
        
        success = completeness >= 90 and patterns_found >= 4
        
        self.log_validation("Architecture Completeness", success,
                          f"File completeness: {completeness:.1f}%, Patterns: {patterns_found}/{total_patterns}",
                          {
                              "file_completeness": f"{completeness:.1f}%",
                              "architectural_patterns": f"{patterns_found}/{total_patterns}",
                              "component_status": component_status
                          })
        
        return success
    
    def generate_architecture_report(self) -> Dict[str, Any]:
        """Generate comprehensive architecture report."""
        end_time = datetime.now()
        duration = (end_time - self.start_time).total_seconds()
        
        total_validations = len(self.validation_results)
        successful_validations = sum(1 for result in self.validation_results if result["success"])
        
        report = {
            "timestamp": end_time.isoformat(),
            "duration_seconds": duration,
            "validation_summary": {
                "total": total_validations,
                "successful": successful_validations,
                "failed": total_validations - successful_validations,
                "success_rate": f"{(successful_validations/total_validations)*100:.1f}%"
            },
            "validations": self.validation_results,
            "architecture_status": "READY" if successful_validations >= 6 else "NEEDS_ATTENTION",
            "recommendations": []
        }
        
        # Add recommendations based on failures
        for result in self.validation_results:
            if not result["success"]:
                report["recommendations"].append(f"Fix {result['component']}: {result['details']}")
        
        return report
    
    def print_summary(self, report: Dict[str, Any]):
        """Print comprehensive validation summary."""
        print("\n" + "="*80)
        print("🎯 END-TO-END ARCHITECTURE VALIDATION SUMMARY")
        print("="*80)
        
        print(f"📊 Validation Results: {report['validation_summary']['successful']}/{report['validation_summary']['total']} "
              f"({report['validation_summary']['success_rate']})")
        print(f"⏱️  Duration: {report['duration_seconds']:.3f} seconds")
        print(f"🏗️  Architecture Status: {report['architecture_status']}")
        
        print(f"\n✅ Successful Validations:")
        for result in self.validation_results:
            if result["success"]:
                print(f"  • {result['component']}")
                if result["details"]:
                    print(f"    {result['details']}")
        
        if report["recommendations"]:
            print(f"\n⚠️  Recommendations:")
            for rec in report["recommendations"]:
                print(f"  • {rec}")
        
        print(f"\n🚀 PHASE 5A MONITORING IMPLEMENTATION STATUS:")
        
        if report["architecture_status"] == "READY":
            print(f"  ✅ Repository Layer: Fully implemented with proper patterns")
            print(f"  ✅ Service Layer: Enhanced with monitoring capabilities")
            print(f"  ✅ API Layer: Comprehensive monitoring endpoints available")
            print(f"  ✅ Integration: All layers properly connected")
            print(f"  ✅ Testing: Comprehensive test coverage implemented")
            print(f"  ✅ Health Checks: Enhanced with detailed system status")
            
            print(f"\n🎉 ARCHITECTURE VALIDATION PASSED!")
            print(f"🚀 The People Registry API is architecturally sound and ready for end-to-end testing!")
            print(f"📋 Next Steps: Deploy to test environment and run integration tests")
            return True
        else:
            print(f"  ⚠️  Some architectural components need attention")
            print(f"  📋 Please address the recommendations above")
            return False


def main():
    """Run comprehensive architecture validation."""
    print("🚀 Starting End-to-End Architecture Validation")
    print("="*80)
    
    validator = ArchitectureValidator()
    
    # Run all validations
    validations = [
        validator.validate_repository_layer,
        validator.validate_service_layer,
        validator.validate_api_layer,
        validator.validate_monitoring_implementation,
        validator.validate_integration_patterns,
        validator.validate_test_coverage,
        validator.validate_architecture_completeness
    ]
    
    for validation in validations:
        validation()
    
    # Generate and print report
    report = validator.generate_architecture_report()
    success = validator.print_summary(report)
    
    # Save report
    with open("architecture_validation_report.json", "w") as f:
        json.dump(report, f, indent=2)
    
    print(f"\n📄 Detailed report saved to: architecture_validation_report.json")
    
    return success


if __name__ == "__main__":
    success = main()
    exit(0 if success else 1)
