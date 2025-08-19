import shutil
import os
import time
import sys
from datetime import datetime, timezone
import platform

from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LOGDIR = os.path.join(PROJECT_ROOT, "logs")
LOGFILE = os.path.join(LOGDIR, "setup_script.log")
SHARED_CA_DIR = os.path.join(PROJECT_ROOT, "certificates")
CA_KEY = os.path.join(SHARED_CA_DIR, "proxy-ca.key.pem")
CA_CERT = os.path.join(SHARED_CA_DIR, "proxy-ca.cert.pem")

def log(msg):
    if not os.path.exists(LOGDIR):
        os.makedirs(LOGDIR)
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with open(LOGFILE, "a") as f:
        f.write(f"[{timestamp}] {msg}\n")
        print(f"[{timestamp}] {msg}")

def ensure_directory_structure():
    """Ensure all necessary directories and configuration files exist"""
    # Create necessary directories
    directories_to_create = [
        LOGDIR,
        SHARED_CA_DIR,
        os.path.join(PROJECT_ROOT, "captures"),
        os.path.join(PROJECT_ROOT, "captures", "mitmproxy"),
        os.path.join(PROJECT_ROOT, "captures", "squid"),
        os.path.join(PROJECT_ROOT, "configs", "squid", "runtime"),
        os.path.join(PROJECT_ROOT, "configs", "squid", "templates"),
        os.path.join(PROJECT_ROOT, "configs", "mitmproxy", "runtime"),
        os.path.join(PROJECT_ROOT, "configs", "mitmproxy", "templates"),
        os.path.join(PROJECT_ROOT, "configs", "burp", "runtime"),
        os.path.join(PROJECT_ROOT, "configs", "burp", "templates")
    ]
    
    for directory in directories_to_create:
        if not os.path.exists(directory):
            try:
                os.makedirs(directory)
                log(f"Created directory: {directory}")
            except Exception as e:
                log(f"ERROR: Could not create directory {directory}: {e}")
                return False

    return True

def generate_ca():
    """Generate a new CA key and certificate"""
    if not (os.path.exists(CA_KEY) and os.path.exists(CA_CERT)):
        log("Generating new CA key and certificate using cryptography...")
        try:
            key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=4096,
                backend=default_backend()
            )
            subject = issuer = x509.Name([
                x509.NameAttribute(NameOID.COMMON_NAME, u"ProxyJA4CA"),
            ])
            now = datetime.now(timezone.utc)
            cert = x509.CertificateBuilder().subject_name(
                subject
            ).issuer_name(
                issuer
            ).public_key(
                key.public_key()
            ).serial_number(
                x509.random_serial_number()
            ).not_valid_before(
                now
            ).not_valid_after(
                now.replace(year=now.year + 10)
            ).add_extension(
                x509.BasicConstraints(ca=True, path_length=None), critical=True,
            ).sign(key, hashes.SHA256(), default_backend())

            with open(CA_KEY, "wb") as f:
                f.write(key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.TraditionalOpenSSL,
                    encryption_algorithm=serialization.NoEncryption()
                ))
            with open(CA_CERT, "wb") as f:
                f.write(cert.public_bytes(serialization.Encoding.PEM))
            log(f"Generated CA key: {CA_KEY}")
            log(f"Generated CA cert: {CA_CERT}")
        except Exception as e:
            log(f"ERROR: Failed to generate CA key/cert: {e}")
    else:
        log("CA key and certificate already exist.")

def is_valid_pem_cert(cert_path):
    """Check if a PEM certificate is valid"""
    if not os.path.exists(cert_path):
        return False
    try:
        with open(cert_path, "rb") as f:
            data = f.read()
            if not data.strip():
                return False
            x509.load_pem_x509_certificate(data, default_backend())
        return True
    except Exception as e:
        log(f"PEM certificate validation failed for {cert_path}: {e}")
        return False

def install_ca(src, dst_name):
    if os.path.exists(src):
        dst_dir = "/usr/local/share/ca-certificates"
        if not os.path.exists(dst_dir):
            try:
                os.makedirs(dst_dir)
            except Exception as e:
                log(f"Failed to create {dst_dir}: {e}")
                return False
        dst = os.path.join(dst_dir, dst_name)
        shutil.copy(src, dst)
        log(f"Copied {src} to {dst}")
        return True
    else:
        log(f"CA candidate not found: {src}")
    return False

def wait_for_file(file_path, max_wait=60):
    """Wait for a file to exist"""
    log(f"Waiting for {file_path}...")
    start_time = time.time()
    
    while not os.path.exists(file_path):
        if time.time() - start_time > max_wait:
            log(f"Timeout waiting for {file_path}")
            return False
        time.sleep(2)
    
    log(f"Found {file_path}")
    return True

def auto_install_all_cas():
    """Automatically install all CA certificates with waiting"""
    log("Starting automatic CA certificate installation...")
    
    # Wait for and install mitmproxy CA
    mitm_ca_path = "/mitm_ca/mitmproxy-ca-cert.pem"
    if wait_for_file(mitm_ca_path):
        if install_ca(mitm_ca_path, "mitmproxy-ca.crt"):
            log("mitmproxy CA certificate installed successfully")
        else:
            log("Failed to install mitmproxy CA certificate")
    else:
        log("mitmproxy CA certificate not found within timeout")
    
    # Wait for and install Squid CA
    squid_ca_path = "/shared_ca_cert.pem"
    if wait_for_file(squid_ca_path):
        if install_ca(squid_ca_path, "squid-ca.crt"):
            log("Squid CA certificate installed successfully")
        else:
            log("Failed to install Squid CA certificate")
    else:
        log("Squid CA certificate not found within timeout")
    
    # Update CA certificates if we're on Linux
    if platform.system() == "Linux":
        try:
            import subprocess
            subprocess.run(["update-ca-certificates"], check=True)
            log("CA certificates updated successfully")
        except subprocess.CalledProcessError as e:
            log(f"Failed to update CA certificates: {e}")
    
    log("Automatic CA installation complete!")

def main():
    """Main function to run the setup script"""

    # Step 1: Ensure Directory Structure
    log("Ensuring directory structure...")
    ensure_directory_structure()

    # Step 2: Generate CA key and cert
    log("Starting CA generation process...")
    generate_ca()
    log("CA generation completed")

    # Step 3: Validate CA cert
    log("Validating CA certificate...")
    if not os.path.exists(CA_CERT) or not os.path.exists(CA_KEY):
        log(f"ERROR: CA certificate or key not found in {SHARED_CA_DIR}. Check directory permissions and rerun this script.")
    elif not is_valid_pem_cert(CA_CERT):
        log(f"ERROR: CA certificate {CA_CERT} is missing or invalid.")
    else:
        log(f"CA certificate {CA_CERT} is valid.")

    # Step 4: Check our run-mode
    if len(sys.argv) > 1 and sys.argv[1] == "--install":
        log("Running in install mode, installing proxy CA certificates into containers...")
        auto_install_all_cas()
        
        # Keep the script running to maintain the container
        log("CA installation complete. Container ready for testing.")
        while True:
            time.sleep(3600)  # Sleep for 1 hour
    else:
        # Manual mode - verify CA files were generated
        log("Running in manual mode - verifying CA files...")
        
        # Check if our generated CA files exist
        if os.path.exists(CA_CERT) and os.path.exists(CA_KEY):
            log(f"CA files generated successfully:")
            log(f"   Key: {CA_KEY}")
            log(f"   Cert: {CA_CERT}")
            log("Ready to start containers!")
        else:
            log(f"CA files missing. Expected:")
            log(f"   Key: {CA_KEY}")
            log(f"   Cert: {CA_CERT}")
            log("Please check the generate_ca() function output above.")

if __name__ == "__main__":
    main()
