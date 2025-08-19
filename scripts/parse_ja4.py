import subprocess
import sys
import os
from datetime import datetime
import shutil
import json

LOGDIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "logs")
LOGFILE = os.path.join(LOGDIR, "parse_ja4.log")
PCAP_FILE = "./captures/test.pcap"
JA4_JSON = "./captures/ja4_results.json"

def log(msg):
    if not os.path.exists(LOGDIR):
        os.makedirs(LOGDIR)
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with open(LOGFILE, "a") as f:
        f.write(f"[{timestamp}] {msg}\n")
    # Removed direct print to standard output; rely on logfile

def get_ja4_command():
    # Try to find 'ja4' or 'ja4.py' in PATH
    ja4_path = shutil.which("ja4")
    ja4py_path = shutil.which("ja4.py")
    if ja4_path:
        log(f"Found ja4 CLI at {ja4_path}")
        return [ja4_path]
    elif ja4py_path:
        log(f"Found ja4.py CLI at {ja4py_path}")
        return [sys.executable, ja4py_path]
    # Fallback: check for ja4.py in current directory
    elif os.path.exists("ja4.py"):
        log("Found ja4.py in current directory")
        return [sys.executable, "ja4.py"]
    log("ja4 CLI not found. Install from https://github.com/salesforce/ja4 and ensure 'ja4' or 'ja4.py' is on PATH or in your project directory.")
    sys.exit(1)

def is_python_ja4(cmd):
    # Try to detect if this is the Python version by running --help and looking for 'usage: ja4.py'
    try:
        result = subprocess.run(cmd + ["--help"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        help_text = result.stdout.decode() + result.stderr.decode()
        return "usage: ja4.py" in help_text
    except Exception as e:
        log(f"Error detecting ja4 CLI type: {e}")
        return False

def load_manifest():
    try:
        with open("./captures/manifest.json", "r") as f:
            return json.load(f)
    except Exception:
        return {}

def parse_ja4():
    if not os.path.exists(PCAP_FILE):
        log(f"{PCAP_FILE} not found.")
        sys.exit(1)
    ja4_cmd = get_ja4_command()
    if is_python_ja4(ja4_cmd):
        # Python version: no subcommand
        cmd = ja4_cmd + [PCAP_FILE, "--json"]
    else:
        # Go version: use parse-pcap subcommand
        cmd = ja4_cmd + ["parse-pcap", PCAP_FILE, "--json"]
    result = subprocess.run(
        cmd,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE
    )
    if result.returncode != 0:
        log("ja4 parse failed.")
        log(result.stderr.decode())
        sys.exit(1)
    
    # Parse JSON Lines output from ja4 CLI
    ja4_data = []
    stdout_text = result.stdout.decode()
    
    # Split by lines and parse each complete JSON object
    lines = stdout_text.strip().split('\n')
    current_json = ""
    
    for line in lines:
        line = line.strip()
        if not line:
            continue
            
        current_json += line
        
        # Try to parse the accumulated JSON
        try:
            session_data = json.loads(current_json)
            ja4_data.append(session_data)
            current_json = ""  # Reset for next object
        except json.JSONDecodeError:
            # Incomplete JSON, continue accumulating
            continue
    
    # Add proxy info to JA4 results
    manifest = load_manifest()
    try:
        for sess in ja4_data:
            # Try to match session to manifest entry by IP/port or other means if possible
            # For now, just attach manifest meta globally
            sess["manifest"] = manifest
        
        with open(JA4_JSON, "w") as f:
            json.dump(ja4_data, f, indent=2)
        log("JA4 results annotated with manifest info.")
    except Exception as e:
        log(f"Could not annotate JA4 results: {e}")
    
    log(f"JA4 results written to {JA4_JSON}")
    log(f"parse_ja4.py finished. See {LOGFILE} for details.")

if __name__ == "__main__":
    parse_ja4()
