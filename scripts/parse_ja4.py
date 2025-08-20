import subprocess
import sys
import os
from datetime import datetime
import shutil
import json

LOGDIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "logs")
LOGFILE = os.path.join(LOGDIR, "parse_ja4.log")
CAPTURES_DIR = "./captures"
JA4_JSON = os.path.join(CAPTURES_DIR, "ja4_results.json")

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

def list_pcap_files():
    try:
        if not os.path.isdir(CAPTURES_DIR):
            log(f"Captures directory not found: {CAPTURES_DIR}")
            return []
        files = []
        for name in os.listdir(CAPTURES_DIR):
            path = os.path.join(CAPTURES_DIR, name)
            if os.path.isfile(path) and name.lower().endswith((".pcap", ".pcapng")):
                files.append(path)
        return sorted(files)
    except Exception as e:
        log(f"Error listing pcap files: {e}")
        return []

def load_manifest():
    try:
        with open("./captures/manifest.json", "r") as f:
            return json.load(f)
    except Exception:
        return {}

def parse_stdout_json_objects(stdout_text):
    ja4_objects = []
    lines = stdout_text.strip().split('\n')
    current_json = ""
    for line in lines:
        line = line.strip()
        if not line:
            continue
        current_json += line
        try:
            obj = json.loads(current_json)
            ja4_objects.append(obj)
            current_json = ""
        except json.JSONDecodeError:
            continue
    return ja4_objects

def parse_ja4():
    pcap_files = list_pcap_files()
    if not pcap_files:
        log("No .pcap files found to parse.")
        sys.exit(1)

    ja4_cmd = get_ja4_command()
    python_cli = is_python_ja4(ja4_cmd)

    all_results = []
    manifest = load_manifest()

    for pcap_path in pcap_files:
        base_name = os.path.basename(pcap_path)
        log(f"Parsing JA4 for {base_name}")
        if python_cli:
            cmd = ja4_cmd + [pcap_path, "--json"]
        else:
            cmd = ja4_cmd + ["parse-pcap", pcap_path, "--json"]

        result = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )
        if result.returncode != 0:
            log(f"ja4 parse failed for {base_name}.")
            log(result.stderr.decode())
            continue

        stdout_text = result.stdout.decode()
        sessions = parse_stdout_json_objects(stdout_text)

        parsed_at_utc = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
        try:
            mtime = os.path.getmtime(pcap_path)
            capture_mtime_utc = datetime.utcfromtimestamp(mtime).strftime("%Y-%m-%dT%H:%M:%SZ")
        except Exception:
            capture_mtime_utc = None

        for sess in sessions:
            sess["source_pcap"] = base_name
            sess["source_pcap_path"] = pcap_path
            sess["parsed_at_utc"] = parsed_at_utc
            if capture_mtime_utc:
                sess["capture_file_mtime_utc"] = capture_mtime_utc
            sess["manifest"] = manifest
            all_results.append(sess)

    try:
        with open(JA4_JSON, "w") as f:
            json.dump(all_results, f, indent=2)
        log("JA4 results annotated and written for all pcaps.")
    except Exception as e:
        log(f"Failed writing JA4 results: {e}")

    log(f"JA4 results written to {JA4_JSON}")
    log(f"parse_ja4.py finished. See {LOGFILE} for details.")

if __name__ == "__main__":
    parse_ja4()
