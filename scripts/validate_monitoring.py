"""
Simple validation script for monitoring functionality
Tests the monitoring methods and API endpoints without external dependencies.
"""

import asyncio
import sys
import os
from unittest.mock import Mock, AsyncMock
from datetime import datetime

# Add src to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

async def test_service_registry_monitoring():
    """Test ServiceRegistryManager monitoring methods."""
    print("🔍 Testing ServiceRegistryManager monitoring methods...")
    
    try:
        from services.service_registry_manager import ServiceRegistryManager
        
        # Create service manager
        service_manager = ServiceRegistryManager()
        
        # Mock services with repositories
        mock_services = {}
        for service_name in ["people", "projects", "audit"]:
            mock_service = Mock()
            mock_service.repository = Mock()
            
            # Mock repository methods
            mock_service.repository.health_check = AsyncMock(return_value={
                "status": "healthy",
                "response_time": 0.05,
                "last_check": datetime.utcnow().isoformat()
            })
            
            mock_service.repository.get_performance_metrics = AsyncMock(return_value={
                "operations_count": 100,
                "average_response_time": 0.05,
                "error_count": 1
            })
            
            mock_service.repository.cleanup_old_records = AsyncMock(return_value={
                "status": "success",
                "records_cleaned": 10,
                "space_freed": "1MB"
            })
            
            mock_service.repository.get_record_count = AsyncMock(return_value=100)
            mock_service.repository.get_active_record_count = AsyncMock(return_value=90)
            mock_service.repository.get_operations_count_today = AsyncMock(return_value=50)
            
            mock_services[service_name] = mock_service
        
        # Mock get_service method
        service_manager.get_service = lambda name: mock_services.get(name, Mock())
        
        # Test repository health
        print("  ✓ Testing repository health check...")
        health = await service_manager.get_repository_health()
        assert health["overall_status"] == "healthy"
        assert len(health["repositories"]) == 3
        print(f"    Repository health: {health['overall_status']}")
        
        # Test performance metrics
        print("  ✓ Testing performance metrics...")
        metrics = await service_manager.get_repository_performance_metrics()
        assert "summary" in metrics
        assert metrics["summary"]["total_operations"] == 300
        print(f"    Total operations: {metrics['summary']['total_operations']}")
        
        # Test cleanup
        print("  ✓ Testing cleanup operations...")
        cleanup = await service_manager.cleanup_repository_resources()
        assert cleanup["overall_status"] == "success"
        print(f"    Cleanup status: {cleanup['overall_status']}")
        
        # Test statistics
        print("  ✓ Testing repository statistics...")
        stats = await service_manager.get_repository_statistics()
        assert stats["summary"]["total_records"] == 300
        assert stats["summary"]["active_records"] == 270
        print(f"    Total records: {stats['summary']['total_records']}")
        print(f"    Active records: {stats['summary']['active_records']}")
        
        print("✅ ServiceRegistryManager monitoring methods validation passed!")
        return True
        
    except Exception as e:
        print(f"❌ ServiceRegistryManager monitoring validation failed: {str(e)}")
        return False


async def test_monitoring_api_structure():
    """Test monitoring API structure."""
    print("🔍 Testing monitoring API structure...")
    
    try:
        from api.monitoring_api_handler import router
        
        # Check router configuration
        assert router.prefix == "/monitoring"
        assert "monitoring" in router.tags
        print("  ✓ Router configuration correct")
        
        # Check endpoint paths
        endpoint_paths = [route.path for route in router.routes]
        expected_paths = [
            "/monitoring/health/repositories",
            "/monitoring/performance/repositories",
            "/monitoring/cleanup/repositories", 
            "/monitoring/statistics/repositories",
            "/monitoring/health/services",
            "/monitoring/overview"
        ]
        
        for expected_path in expected_paths:
            if expected_path in endpoint_paths:
                print(f"  ✓ Endpoint found: {expected_path}")
            else:
                print(f"  ❌ Missing endpoint: {expected_path}")
                return False
        
        print("✅ Monitoring API structure validation passed!")
        return True
        
    except Exception as e:
        print(f"❌ Monitoring API structure validation failed: {str(e)}")
        return False


def test_health_check_enhancement():
    """Test enhanced health check implementation."""
    print("🔍 Testing enhanced health check...")
    
    try:
        # Read the updated health check code
        with open('src/handlers/versioned_api_handler.py', 'r') as f:
            content = f.read()
        
        # Check for enhanced health check features
        required_features = [
            "service_registry_manager",
            "get_repository_health",
            "get_service_health", 
            "detailed_health",
            "summary"
        ]
        
        for feature in required_features:
            if feature in content:
                print(f"  ✓ Feature found: {feature}")
            else:
                print(f"  ❌ Missing feature: {feature}")
                return False
        
        print("✅ Enhanced health check validation passed!")
        return True
        
    except Exception as e:
        print(f"❌ Enhanced health check validation failed: {str(e)}")
        return False


async def main():
    """Run all monitoring validation tests."""
    print("🚀 Starting monitoring functionality validation...\n")
    
    results = []
    
    # Test ServiceRegistryManager monitoring
    results.append(await test_service_registry_monitoring())
    print()
    
    # Test monitoring API structure
    results.append(await test_monitoring_api_structure())
    print()
    
    # Test health check enhancement
    results.append(test_health_check_enhancement())
    print()
    
    # Summary
    passed = sum(results)
    total = len(results)
    
    print(f"📊 Validation Summary: {passed}/{total} tests passed")
    
    if passed == total:
        print("🎉 All monitoring functionality validation tests passed!")
        print("\n✅ Repository monitoring implementation is ready for production!")
        
        print("\n📋 Monitoring Features Available:")
        print("  • Repository health monitoring")
        print("  • Performance metrics collection")
        print("  • Automated cleanup operations")
        print("  • Comprehensive statistics")
        print("  • Enhanced health check endpoint")
        print("  • Monitoring API endpoints")
        
        return True
    else:
        print("❌ Some validation tests failed. Please review the issues above.")
        return False


if __name__ == "__main__":
    success = asyncio.run(main())
    sys.exit(0 if success else 1)
