#!/usr/bin/env python3
"""
Comprehensive test script for TLS intercepting proxies:
- Direct (no proxy)
- Squid (with SSL bumping)
- mitmproxy (with TLS interception)

This script tests each proxy and collects JA4 signatures for analysis.
"""

from datetime import datetime
from pathlib import Path
import os
import sys
import json
import requests
import urllib3

# Disable SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Add project root to path
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

# Test configuration
TEST_HOSTS = [
    "https://github.com",
    "https://httpbin.org/get",
    "https://ipinfo.io",
    "https://example.com"
]

PROXIES = [
    {
        "name": "direct",
        "proxy_port": None,
        "description": "Direct connection (no proxy)"
    },
    {
        "name": "squid",
        "proxy_port": 3128,
        "description": "Squid proxy with SSL bump"
    },
    {
        "name": "mitmproxy",
        "proxy_port": 8080,
        "description": "mitmproxy with TLS interception"
    }
]

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LOGDIR = os.path.join(PROJECT_ROOT, "logs")
LOGFILE = os.path.join(LOGDIR, "test_all_proxies.log")

def log(msg):
    if not os.path.exists(LOGDIR):
        os.makedirs(LOGDIR)
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with open(LOGFILE, "a") as f:
        f.write(f"[{timestamp}] {msg}\n")
        print(f"[{timestamp}] {msg}")

def check_proxy_health(proxy_name, port):
    """Check if proxy is healthy"""
    try:
        response = requests.get(f"http://127.0.0.1:{port}", timeout=5, verify=False)
        log(f"{proxy_name} health check response: {response.status_code}")
        return response.status_code < 500
    except Exception as e:
        log(f"{proxy_name} health check failed: {e}")
        return False

def test_proxy(proxy_config):
    """Test a single proxy configuration"""
    proxy_name = proxy_config["name"]
    log(f"Testing {proxy_name}: {proxy_config['description']}")
    
    results = []
    
    # Check proxy health first
    if proxy_name != "direct":
        if not check_proxy_health(proxy_name, proxy_config["proxy_port"]):
            log(f"Warning: {proxy_name} health check failed, but continuing with test")
    
    # Test each host
    for host in TEST_HOSTS:
        log(f"Testing connection to {host} through {proxy_name} proxy.")
        if proxy_name == "direct":
            try:
                response = requests.get(host)
                log(f"Received response code: {response.status_code}")
            except Exception as e:
                log(f"{proxy_name} test failed: {e}")
        else:
            port = proxy_config["proxy_port"]
            try:
                response = requests.get(host, proxies={"https": f"127.0.0.1:{port}"}, verify=False)
                log(f"Received response code: {response.status_code}")
            except Exception as e:
                log(f"{proxy_name} test failed: {e}")
        
        results.append({
            "proxy": proxy_name,
            "url": host,
            "success": response.status_code < 500,
            "return_code": response.status_code,
            "timestamp": datetime.now().isoformat()
        })
    
    return results     

def save_results(all_results):
    """Save results to a file"""
    results_file = project_root / "captures" / "comprehensive_test_results.json"
    results_file.parent.mkdir(exist_ok=True)
    
    with open(results_file, 'w') as f:
        json.dump({
            "test_run": {
                "timestamp": datetime.now().isoformat(),
                "total_proxies": len(PROXIES),
                "total_tests": len(all_results),
                "successful_tests": sum(1 for r in all_results if r["success"])
            },
            "proxy_configs": PROXIES,
            "test_hosts": TEST_HOSTS,
            "results": all_results
        }, f, indent=2)
    
    log(f"\nDetailed results saved to: {results_file}")
    log("Test suite completed!")

def run_all_tests():
    """Run tests for all proxies"""
    log("Starting comprehensive proxy test suite")
    log(f"Testing {len(PROXIES)} proxy configurations")
    log(f"Testing {len(TEST_HOSTS)} hosts per proxy")
    
    all_results = []
    
    for proxy_config in PROXIES:
        proxy_results = test_proxy(proxy_config)
        all_results.extend(proxy_results)
        
        # Summary for this proxy
        success_count = sum(1 for r in proxy_results if r["success"])
        total_count = len(proxy_results)
        log(f"Proxy {proxy_config['name']}: {success_count}/{total_count} tests passed")
    
    
    for proxy_config in PROXIES:
        proxy_name = proxy_config["name"]
        proxy_results = [r for r in all_results if r["proxy"] == proxy_name]
        success_count = sum(1 for r in proxy_results if r["success"])
        total_count = len(proxy_results)
        log(f"{proxy_name:12}: {success_count:2}/{total_count} tests passed")
        
    return all_results

def main():
    """Main entry point"""
    if len(sys.argv) > 1 and sys.argv[1] == "--help":
        log(__doc__)
        log("Usage: python test_all_proxies.py")
        log("This script will test all configured proxies and save results.")
        return
    
    try:
        results = run_all_tests()
        
        # Exit with error code if any tests failed
        failed_tests = sum(1 for r in results if not r["success"])
        if failed_tests > 0:
            log(f"Warning: {failed_tests} tests failed")
            sys.exit(1)
        else:
            log("All tests passed successfully!")
            
    except KeyboardInterrupt:
        log("\nTest interrupted by user")
        sys.exit(1)
    except Exception as e:
        log(f"Test suite failed with error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
