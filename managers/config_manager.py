#!/usr/bin/env python3
"""
Configuration Manager - Handle different proxy configurations and track changes
"""
import os
import json
import hashlib
import shutil
import time
from pathlib import Path
from typing import Dict, List, Optional
import logging

# Configure logging to both file and console
def setup_logging():
    project_root = Path(__file__).parent.parent
    log_dir = project_root / "logs"
    log_dir.mkdir(exist_ok=True)
    
    log_file = log_dir / "config_manager.log"
    
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

class ConfigManager:
    def __init__(self, project_root: str):
        self.project_root = Path(project_root)
        self.configs_dir = self.project_root / "configs"
        self.configs_dir.mkdir(exist_ok=True)
        
        # Configuration templates - updated to use configs directory
        self.config_templates = {
            "squid": {
                "default": "configs/squid/runtime/squid_no_ssl.conf",
                "variants": {
                    "ssl_bump_only": "configs/squid/templates/ssl_bump_only.conf",
                    "ssl_bump_with_auth": "configs/squid/templates/ssl_bump_with_auth.conf",
                    "ssl_bump_with_caching": "configs/squid/templates/ssl_bump_with_caching.conf"
                }
            },
            "mitmproxy": {
                "default": "configs/mitmproxy/runtime/mitmproxy.conf",
                "variants": {
                    "regular": "configs/mitmproxy/templates/regular.conf",
                    "transparent": "configs/mitmproxy/templates/transparent.conf",
                    "socks": "configs/mitmproxy/templates/socks.conf"
                }
            }
        }
        
        # Initialize configuration variants
        self._init_config_variants()
    
    def _init_config_variants(self):
        """Initialize configuration variants"""
        for proxy_id, proxy_configs in self.config_templates.items():
            proxy_config_dir = self.configs_dir / proxy_id
            proxy_config_dir.mkdir(exist_ok=True)
            
            # Copy default config if it exists
            default_config = self.project_root / proxy_configs["default"]
            if default_config.exists():
                for variant_name in proxy_configs["variants"].keys():
                    variant_path = proxy_config_dir / f"{variant_name}.conf"
                    if not variant_path.exists():
                        shutil.copy2(default_config, variant_path)
                        logger.info(f"Created {variant_name} config for {proxy_id}")
    
    def get_config_hash(self, config_path: str) -> str:
        """Calculate hash of configuration file"""
        try:
            with open(config_path, 'rb') as f:
                content = f.read()
            return hashlib.sha256(content).hexdigest()[:16]
        except Exception as e:
            logger.error(f"Failed to calculate hash for {config_path}: {e}")
            return "unknown"
    
    def get_all_configs(self) -> Dict[str, Dict]:
        """Get all available configurations with their hashes"""
        configs = {}
        
        for proxy_id, proxy_configs in self.config_templates.items():
            configs[proxy_id] = {
                "default": {
                    "path": str(proxy_configs["default"]),
                    "hash": self.get_config_hash(self.project_root / proxy_configs["default"])
                },
                "variants": {}
            }
            
            for variant_name, variant_path in proxy_configs["variants"].items():
                full_path = self.project_root / variant_path
                if full_path.exists():
                    configs[proxy_id]["variants"][variant_name] = {
                        "path": str(variant_path),
                        "hash": self.get_config_hash(full_path)
                    }
        
        return configs
    
    def apply_config(self, proxy_id: str, config_name: str) -> bool:
        """Apply a specific configuration to a proxy"""
        try:
            if config_name == "default":
                config_path = self.config_templates[proxy_id]["default"]
            else:
                config_path = self.config_templates[proxy_id]["variants"].get(config_name)
            
            if not config_path:
                logger.error(f"Unknown configuration {config_name} for {proxy_id}")
                return False
            
            source_path = self.project_root / config_path
            if not source_path.exists():
                logger.error(f"Configuration file {source_path} does not exist")
                return False
            
            # Determine target path based on proxy - updated to use configs directory
            if proxy_id == "squid":
                target_path = self.project_root / "configs/squid/runtime/squid.conf"
            elif proxy_id == "mitmproxy":
                target_path = self.project_root / "configs/mitmproxy/runtime/mitmproxy.conf"
            else:
                logger.error(f"Unknown proxy {proxy_id}")
                return False
            
            # Backup current config
            if target_path.exists():
                backup_path = target_path.with_suffix(f".conf.backup.{int(time.time())}")
                shutil.copy2(target_path, backup_path)
                logger.info(f"Backed up current config to {backup_path}")
            
            # Apply new config
            shutil.copy2(source_path, target_path)
            logger.info(f"Applied {config_name} configuration to {proxy_id}")
            
            return True
            
        except Exception as e:
            logger.error(f"Failed to apply {config_name} config to {proxy_id}: {e}")
            return False
    
    def create_custom_config(self, proxy_id: str, config_name: str, 
                           modifications: Dict[str, str]) -> bool:
        """Create a custom configuration with specific modifications"""
        try:
            # Get base config
            base_config = self.config_templates[proxy_id]["default"]
            base_path = self.project_root / base_config
            
            if not base_path.exists():
                logger.error(f"Base configuration {base_path} does not exist")
                return False
            
            # Read base config
            with open(base_path, 'r') as f:
                content = f.read()
            
            # Apply modifications
            for old_value, new_value in modifications.items():
                content = content.replace(old_value, new_value)
            
            # Save custom config
            custom_config_dir = self.configs_dir / proxy_id
            custom_config_dir.mkdir(exist_ok=True)
            
            custom_config_path = custom_config_dir / f"{config_name}.conf"
            with open(custom_config_path, 'w') as f:
                f.write(content)
            
            # Add to templates
            if "variants" not in self.config_templates[proxy_id]:
                self.config_templates[proxy_id]["variants"] = {}
            
            self.config_templates[proxy_id]["variants"][config_name] = str(custom_config_path)
            
            logger.info(f"Created custom configuration {config_name} for {proxy_id}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to create custom config {config_name} for {proxy_id}: {e}")
            return False
    
    def validate_config(self, proxy_id: str, config_name: str) -> Dict:
        """Validate a proxy configuration"""
        validation_result = {
            "valid": False,
            "errors": [],
            "warnings": []
        }
        
        try:
            if config_name == "default":
                config_path = self.config_templates[proxy_id]["default"]
            else:
                config_path = self.config_templates[proxy_id]["variants"].get(config_name)
            
            if not config_path:
                validation_result["errors"].append(f"Configuration {config_name} not found")
                return validation_result
            
            full_path = self.project_root / config_path
            if not full_path.exists():
                validation_result["errors"].append(f"Configuration file {full_path} does not exist")
                return validation_result
            
            # Read and validate config
            with open(full_path, 'r') as f:
                content = f.read()
            
            # Basic validation based on proxy type
            if proxy_id == "squid":
                validation_result = self._validate_squid_config(content)
            elif proxy_id == "mitmproxy":
                validation_result = self._validate_mitmproxy_config(content)
            else:
                validation_result["errors"].append(f"Unknown proxy type {proxy_id}")
            
        except Exception as e:
            validation_result["errors"].append(f"Validation failed: {e}")
        
        return validation_result
    
    def _validate_squid_config(self, content: str) -> Dict:
        """Validate Squid configuration"""
        result = {"valid": True, "errors": [], "warnings": []}
        
        # Check for required SSL bumping settings
        if "ssl_bump" in content:
            if "ssl_bump peek" not in content:
                result["warnings"].append("SSL bump peek rule not found")
            if "ssl_bump bump" not in content:
                result["warnings"].append("SSL bump bump rule not found")
            if "sslcrtd_program" not in content:
                result["warnings"].append("SSL certificate generation program not configured")
        
        # Check for basic security settings
        if "http_access deny all" not in content:
            result["warnings"].append("Default deny rule not found")
        
        return result
    
    def _validate_mitmproxy_config(self, content: str) -> Dict:
        """Validate mitmproxy configuration"""
        result = {"valid": True, "errors": [], "warnings": []}
        
        # Check for basic settings
        if "block_global" not in content:
            result["warnings"].append("block_global setting not found")
        
        return result
    
    def export_configs(self, output_file: str):
        """Export all configurations to a JSON file"""
        try:
            configs = self.get_all_configs()
            
            export_data = {
                "exported_at": time.time(),
                "configs": configs,
                "templates": self.config_templates
            }
            
            with open(output_file, 'w') as f:
                json.dump(export_data, f, indent=2)
            
            logger.info(f"Configurations exported to {output_file}")
            
        except Exception as e:
            logger.error(f"Failed to export configurations: {e}")
    
    def import_configs(self, import_file: str):
        """Import configurations from a JSON file"""
        try:
            with open(import_file, 'r') as f:
                import_data = json.load(f)
            
            # Import configuration variants
            for proxy_id, proxy_configs in import_data.get("configs", {}).items():
                for variant_name, variant_info in proxy_configs.get("variants", {}).items():
                    source_path = Path(variant_info["path"])
                    if source_path.exists():
                        target_path = self.configs_dir / proxy_id / f"{variant_name}.conf"
                        target_path.parent.mkdir(exist_ok=True)
                        shutil.copy2(source_path, target_path)
            
            logger.info(f"Configurations imported from {import_file}")
            
        except Exception as e:
            logger.error(f"Failed to import configurations: {e}")

def main():
    """Main entry point"""
    import argparse
    import time
    
    parser = argparse.ArgumentParser(description="Configuration Manager for Proxy JA4 Project")
    parser.add_argument("--list", action="store_true", help="List all configurations")
    parser.add_argument("--apply", nargs=2, metavar=("PROXY", "CONFIG"), 
                       help="Apply configuration CONFIG to proxy PROXY")
    parser.add_argument("--validate", nargs=2, metavar=("PROXY", "CONFIG"),
                       help="Validate configuration CONFIG for proxy PROXY")
    parser.add_argument("--create", nargs=3, metavar=("PROXY", "NAME", "MODIFICATIONS"),
                       help="Create custom configuration with modifications")
    parser.add_argument("--export", metavar="FILE", help="Export all configurations to FILE")
    parser.add_argument("--import", metavar="FILE", dest="import_file", help="Import configurations from FILE")
    
    args = parser.parse_args()
    
    # Initialize config manager
    project_root = Path(__file__).parent.parent
    manager = ConfigManager(str(project_root))
    
    if args.list:
        configs = manager.get_all_configs()
        print("Available configurations:")
        for proxy_id, proxy_configs in configs.items():
            print(f"  {proxy_id}:")
            print(f"    default: {proxy_configs['default']['hash']}")
            for variant_name, variant_info in proxy_configs['variants'].items():
                print(f"    {variant_name}: {variant_info['hash']}")
    
    elif args.apply:
        proxy_id, config_name = args.apply
        if manager.apply_config(proxy_id, config_name):
            print(f"Successfully applied {config_name} to {proxy_id}")
        else:
            print(f"Failed to apply {config_name} to {proxy_id}")
    
    elif args.validate:
        proxy_id, config_name = args.validate
        result = manager.validate_config(proxy_id, config_name)
        if result["valid"]:
            print(f"Configuration {config_name} for {proxy_id} is valid")
        else:
            print(f"Configuration {config_name} for {proxy_id} has issues:")
            for error in result["errors"]:
                print(f"  ERROR: {error}")
            for warning in result["warnings"]:
                print(f"  WARNING: {warning}")
    
    elif args.create:
        proxy_id, name, modifications_file = args.create
        try:
            with open(modifications_file, 'r') as f:
                modifications = json.load(f)
            if manager.create_custom_config(proxy_id, name, modifications):
                print(f"Successfully created custom configuration {name} for {proxy_id}")
            else:
                print(f"Failed to create custom configuration {name} for {proxy_id}")
        except Exception as e:
            print(f"Error reading modifications file: {e}")
    
    elif args.export:
        manager.export_configs(args.export)
    
    elif args.import_file:
        manager.import_configs(args.import_file)
    
    else:
        parser.print_help()

if __name__ == "__main__":
    main()
