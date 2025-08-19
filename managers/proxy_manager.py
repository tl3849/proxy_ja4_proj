#!/usr/bin/env python3
"""
Proxy Manager - Automated proxy testing and JA4 signature collection
"""
import os
import json
import subprocess
import time
import requests
from pathlib import Path
from typing import Dict, List, Optional
import logging

# Configure logging to both file and console
def setup_logging():
    project_root = Path(__file__).parent.parent
    log_dir = project_root / "logs"
    log_dir.mkdir(exist_ok=True)
    
    log_file = log_dir / "proxy_manager.log"
    
    # Configure logging
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler(log_file),
            logging.StreamHandler()
        ]
    )

setup_logging()
logger = logging.getLogger(__name__)

class ProxyManager:
    def __init__(self, project_root: str):
        self.project_root = Path(project_root)
        self.configs_dir = self.project_root / "configs"
        self.captures_dir = self.project_root / "captures"
        self.results_file = self.captures_dir / "proxy_signatures.json"
        
        # Ensure directories exist
        self.captures_dir.mkdir(exist_ok=True)
        
        # Proxy definitions with version information
        self.proxy_definitions = {
            "squid": {
                "name": "Squid",
                "versions": ["6.10", "6.9", "6.8", "6.7"],
                "dockerfile_template": "docker/squid/Dockerfile",
                "config_template": "configs/squid/templates/squid.conf",
                "port": 3128,
                "health_check": "nc -z localhost 3128"
            },
            "mitmproxy": {
                "name": "mitmproxy",
                "versions": ["latest", "10.1.5", "10.0.1", "9.0.1"],
                "docker_image": "mitmproxy/mitmproxy",
                "port": 8080,
                "health_check": "nc -z localhost 8080"
            },


        }
        
        # Load existing results
        self.load_results()
    
    def load_results(self):
        """Load existing JA4 signature results"""
        if self.results_file.exists():
            try:
                with open(self.results_file, 'r') as f:
                    self.results = json.load(f)
            except Exception as e:
                logger.warning(f"Could not load existing results: {e}")
                self.results = {"signatures": [], "metadata": {}}
        else:
            self.results = {"signatures": [], "metadata": {}}
    
    def save_results(self):
        """Save JA4 signature results"""
        with open(self.results_file, 'w') as f:
            json.dump(self.results, f, indent=2)
        logger.info(f"Results saved to {self.results_file}")
    
    def check_proxy_versions(self) -> Dict[str, List[str]]:
        """Check for available versions of each proxy"""
        available_versions = {}
        
        for proxy_id, proxy_info in self.proxy_definitions.items():
            if "docker_image" in proxy_info:
                # For Docker Hub images, check available tags
                available_versions[proxy_id] = self._get_docker_tags(proxy_info["docker_image"])
            else:
                # For built images, use predefined versions
                available_versions[proxy_id] = proxy_info.get("versions", [])
        
        return available_versions
    
    def _get_docker_tags(self, image_name: str) -> List[str]:
        """Get available Docker tags for an image"""
        try:
            # This is a simplified version - in production you might want to use Docker Hub API
            result = subprocess.run(
                ["docker", "search", image_name, "--limit", "10"],
                capture_output=True, text=True, check=True
            )
            # Parse output to get versions (simplified)
            return ["latest"]  # Placeholder
        except Exception as e:
            logger.warning(f"Could not check Docker tags for {image_name}: {e}")
            return ["latest"]
    
    def build_proxy_container(self, proxy_id: str, version: str) -> bool:
        """Build a proxy container with specific version"""
        try:
            if proxy_id == "squid":
                return self._build_squid_container(version)
            elif proxy_id == "mitmproxy":
                return self._build_mitmproxy_container(version)
            else:
                logger.warning(f"Building {proxy_id} not implemented yet")
                return False
        except Exception as e:
            logger.error(f"Failed to build {proxy_id}:{version}: {e}")
            return False
    
    def _build_squid_container(self, version: str) -> bool:
        """Build Squid container with specific version"""
        try:
            # Update Dockerfile with version
            dockerfile_path = self.project_root / "docker" / "squid" / "Dockerfile"
            if dockerfile_path.exists():
                with open(dockerfile_path, 'r') as f:
                    content = f.read()
                
                # Update version
                content = content.replace(f'ENV SQUID_VERSION={version}', f'ENV SQUID_VERSION={version}')
                
                with open(dockerfile_path, 'w') as f:
                    f.write(content)
            
            # Build container
            result = subprocess.run(
                ["docker", "compose", "build", "--no-cache", "squid"],
                cwd=self.project_root, check=True
            )
            
            logger.info(f"Successfully built Squid {version}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to build Squid {version}: {e}")
            return False
    
    def _build_mitmproxy_container(self, version: str) -> bool:
        """Build mitmproxy container with specific version"""
        try:
            # Update docker-compose.yml with version
            compose_file = self.project_root / "docker-compose.yml"
            if compose_file.exists():
                with open(compose_file, 'r') as f:
                    content = f.read()
                
                # Update mitmproxy image tag
                if version == "latest":
                    content = content.replace(
                        'mitmproxy/mitmproxy:${MITMPROXY_TAG:-latest}',
                        'mitmproxy/mitmproxy:latest'
                    )
                else:
                    content = content.replace(
                        'mitmproxy/mitmproxy:${MITMPROXY_TAG:-latest}',
                        f'mitmproxy/mitmproxy:{version}'
                    )
                
                with open(compose_file, 'w') as f:
                    f.write(content)
            
            logger.info(f"Updated mitmproxy to version {version}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to update mitmproxy to {version}: {e}")
            return False
    
    def run_proxy_test(self, proxy_id: str, version: str) -> Dict:
        """Run a test through a specific proxy version"""
        test_result = {
            "proxy_id": proxy_id,
            "version": version,
            "timestamp": time.time(),
            "status": "unknown",
            "ja4_signatures": [],
            "errors": []
        }
        
        try:
            # Start the proxy
            logger.info(f"Starting {proxy_id}:{version}")
            subprocess.run(
                ["docker", "compose", "up", "-d", proxy_id],
                cwd=self.project_root, check=True
            )
            
            # Wait for proxy to be healthy
            if not self._wait_for_proxy_health(proxy_id):
                test_result["status"] = "failed"
                test_result["errors"].append("Proxy failed health check")
                return test_result
            
            # Run test traffic
            logger.info(f"Running test traffic through {proxy_id}:{version}")
            test_traffic_result = self._run_test_traffic(proxy_id)
            
            if test_traffic_result["success"]:
                test_result["status"] = "success"
                # Parse JA4 signatures from captured traffic
                ja4_signatures = self._parse_ja4_signatures()
                test_result["ja4_signatures"] = ja4_signatures
            else:
                test_result["status"] = "failed"
                test_result["errors"].extend(test_traffic_result["errors"])
            
        except Exception as e:
            test_result["status"] = "error"
            test_result["errors"].append(str(e))
            logger.error(f"Error testing {proxy_id}:{version}: {e}")
        
        finally:
            # Stop the proxy
            try:
                subprocess.run(
                    ["docker", "compose", "stop", proxy_id],
                    cwd=self.project_root
                )
            except Exception as e:
                logger.warning(f"Could not stop {proxy_id}: {e}")
        
        return test_result
    
    def _wait_for_proxy_health(self, proxy_id: str, timeout: int = 60) -> bool:
        """Wait for proxy to be healthy"""
        start_time = time.time()
        proxy_info = self.proxy_definitions.get(proxy_id, {})
        
        while time.time() - start_time < timeout:
            try:
                # Check if container is running
                result = subprocess.run(
                    ["docker", "compose", "ps", proxy_id],
                    cwd=self.project_root, capture_output=True, text=True, check=True
                )
                
                if "Up" in result.stdout:
                    logger.info(f"{proxy_id} is running")
                    return True
                
            except Exception as e:
                logger.debug(f"Health check failed: {e}")
            
            time.sleep(5)
        
        logger.warning(f"{proxy_id} failed health check after {timeout}s")
        return False
    
    def _run_test_traffic(self, proxy_id: str) -> Dict:
        """Run test traffic through the proxy"""
        result = {"success": False, "errors": []}
        
        try:
            # Start packet capture
            subprocess.run(
                ["python", "scripts/capture.py", "--start"],
                cwd=self.project_root, check=True
            )
            
            # Wait for capture to start
            time.sleep(5)
            
            # Run test requests
            test_urls = [
                "https://www.google.com",
                "https://www.cloudflare.com",
                "https://httpbin.org/get"
            ]
            
            proxy_info = self.proxy_definitions.get(proxy_id, {})
            proxy_port = proxy_info.get("port", 8080)
            
            for url in test_urls:
                try:
                    # Make request through proxy
                    cmd = [
                        "curl", "-s", "--proxy", f"http://localhost:{proxy_port}",
                        "--max-time", "10", url
                    ]
                    
                    subprocess.run(cmd, check=True, timeout=15)
                    logger.debug(f"Successfully requested {url} through {proxy_id}")
                    
                except Exception as e:
                    result["errors"].append(f"Failed to request {url}: {e}")
            
            # Stop capture
            time.sleep(5)  # Allow time for traffic to complete
            subprocess.run(
                ["python", "scripts/capture.py", "--stop"],
                cwd=self.project_root, check=True
            )
            
            result["success"] = True
            
        except Exception as e:
            result["errors"].append(f"Test traffic failed: {e}")
        
        return result
    

    

    
    def _parse_ja4_signatures(self) -> List[Dict]:
        """Parse JA4 signatures from captured traffic"""
        try:
            # Run JA4 analysis
            result = subprocess.run(
                ["python", "scripts/parse_ja4.py"],
                cwd=self.project_root, capture_output=True, text=True, check=True
            )
            
            # Parse output for JA4 signatures
            # This is a simplified version - you'll need to implement proper parsing
            ja4_signatures = []
            
            # Look for JA4 results file
            ja4_results_file = self.captures_dir / "ja4_results.json"
            if ja4_results_file.exists():
                with open(ja4_results_file, 'r') as f:
                    ja4_data = json.load(f)
                    ja4_signatures = ja4_data.get("signatures", [])
            
            return ja4_signatures
            
        except Exception as e:
            logger.error(f"Failed to parse JA4 signatures: {e}")
            return []
    
    def run_full_test_suite(self):
        """Run tests for all proxy versions"""
        logger.info("Starting full proxy test suite")
        
        available_versions = self.check_proxy_versions()
        
        for proxy_id, versions in available_versions.items():
            logger.info(f"Testing {proxy_id} with versions: {versions}")
            
            for version in versions:
                logger.info(f"Testing {proxy_id}:{version}")
                
                # Build container if needed
                if not self.build_proxy_container(proxy_id, version):
                    logger.error(f"Failed to build {proxy_id}:{version}, skipping")
                    continue
                
                # Run test
                test_result = self.run_proxy_test(proxy_id, version)
                
                # Store result
                self.results["signatures"].append(test_result)
                
                # Save after each test
                self.save_results()
                
                logger.info(f"Completed test for {proxy_id}:{version} - Status: {test_result['status']}")
        
        logger.info("Full test suite completed")
        return self.results

def main():
    """Main entry point"""
    import argparse
    
    parser = argparse.ArgumentParser(description="Proxy Manager for JA4 Signature Collection")
    parser.add_argument("--test-all", action="store_true", help="Run full test suite")
    parser.add_argument("--proxy", help="Test specific proxy (e.g., squid, mitmproxy)")
    parser.add_argument("--version", help="Test specific version")
    parser.add_argument("--list-versions", action="store_true", help="List available versions")
    
    args = parser.parse_args()
    
    # Initialize proxy manager
    project_root = Path(__file__).parent.parent
    manager = ProxyManager(str(project_root))
    
    if args.list_versions:
        versions = manager.check_proxy_versions()
        print("Available proxy versions:")
        for proxy_id, proxy_versions in versions.items():
            print(f"  {proxy_id}: {proxy_versions}")
    
    elif args.test_all:
        results = manager.run_full_test_suite()
        print(f"Test suite completed. Results saved to {manager.results_file}")
    
    elif args.proxy:
        if args.version:
            test_result = manager.run_proxy_test(args.proxy, args.version)
            print(f"Test result: {test_result}")
        else:
            print(f"Please specify a version for {args.proxy}")
    
    else:
        parser.print_help()

if __name__ == "__main__":
    main()
