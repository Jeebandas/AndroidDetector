#!/usr/bin/env python3
"""
APK Security Analyzer (Advanced)

This script performs an in-depth static analysis of an Android APK file.
It decompiles the APK, scans Smali code, analyzes the AndroidManifest.xml,
and inspects native libraries to identify a wide range of security vulnerabilities.

Key Features:
- Decompiles APKs using Apktool.
- Scans for vulnerabilities with severity levels (High, Medium, Low).
- Analyzes native libraries (.so files) for insecure functions.
- Performs comprehensive analysis of AndroidManifest.xml misconfigurations.
- Detects weak cryptographic algorithms and hardcoded secrets.
- Generates reports in both console and JSON format.
"""

import os
import subprocess
import shutil
import sys
import argparse
import re
import json
from xml.etree import ElementTree as ET
from tqdm import tqdm

try:
    from termcolor import colored
    from colorama import init
    init(autoreset=True)
except ImportError:
    print("Required libraries 'termcolor', 'colorama', 'tqdm' not found. Installing...")
    subprocess.check_call([sys.executable, "-m", "pip", "install", "termcolor", "colorama", "tqdm"])
    from termcolor import colored
    from colorama import init
    init(autoreset=True)

# === BANNER ===
def print_banner():
    banner = r"""
     ██████╗ ███████╗████████╗███████╗ ██████╗ ████████╗ ██████╗ ██████╗ 
    ██╔═══██╗██╔════╝╚══██╔══╝██╔════╝██╔═══██╗╚══██╔══╝██╔═══██╗██╔══██╗
    ██║   ██║█████╗     ██║   █████╗  ██║         ██║   ██║   ██║██████╔╝
    ██║   ██║██╔══╝     ██║   ██╔══╝  ██║         ██║   ██║   ██║██╔═══╝ 
    ╚██████╔╝███████╗   ██║   ███████╗╚██████╔╝   ██║   ╚██████╔╝██║ ██   
     ╚═════╝ ╚══════╝   ╚═╝   ╚══════╝ ╚═════╝    ╚═╝    ╚═════╝ ╚═╝   ██╗
    """
    print(colored(banner, "green", attrs=["bold"]))
    print(colored("                  Developed by Jeeban JD", "yellow", attrs=["bold"]))
    print(colored("                  APK Security Analyzer", "green", attrs=["bold"]))
    print(colored("="*72, "magenta", attrs=["bold"]))
    
print_banner()

# === CONFIGURATION ===
APKTOOL_PATH = "apktool"
STRINGS_PATH = "strings" # Utility to scan native libraries

# Permission Classifications
SECURE_PERMS = {
    "INTERNET", "ACCESS_NETWORK_STATE", "ACCESS_WIFI_STATE", "VIBRATE",
    "WAKE_LOCK", "RECEIVE_BOOT_COMPLETED", "POST_NOTIFICATIONS", "FOREGROUND_SERVICE"
}
INSECURE_PERMS = {
    "READ_SMS", "RECEIVE_SMS", "SEND_SMS", "READ_PHONE_STATE", "WRITE_SETTINGS",
    "READ_EXTERNAL_STORAGE", "WRITE_EXTERNAL_STORAGE", "SYSTEM_ALERT_WINDOW",
    "REQUEST_INSTALL_PACKAGES", "MANAGE_EXTERNAL_STORAGE", "QUERY_ALL_PACKAGES",
    "BIND_ACCESSIBILITY_SERVICE", "USE_BIOMETRIC", "ACCESS_FINE_LOCATION",
    "ACCESS_COARSE_LOCATION", "READ_CONTACTS", "WRITE_CONTACTS", "GET_ACCOUNTS"
}

# Mapping of check names to severity levels
SEVERITY = {
    "Hardcoded Secrets": "High",
    "Insecure WebView": "Low",
    "Cleartext Traffic Allowed": "Low",
    "Debug Mode Enabled": "Low",
    "Root Detection": "Low",
    "Insecure Native Functions": "Low",
    "Exported Components": "Low",
    "Weak Crypto Usage": "High",
    "Code Injection Risks": "High",
    "SSL Pinning": "medium",
    "Screenshot Protection": "Low",
    "Tapjacking Protection": "Low",
    "Emulator Detection": "Low",
    "Verbose Logging": "Low",
    "Backup Allowed": "Low"
}

# === TOOL VERIFICATION ===
def check_tools():
    """Verify that required command-line tools are installed."""
    for tool, path in [("Apktool", APKTOOL_PATH), ("strings", STRINGS_PATH)]:
        if not shutil.which(path):
            print(colored(f"❌ Error: {tool} not found at '{path}'.", "red"))
            print(colored(f"➡️ Please install {tool} and ensure it's in your system's PATH.", "yellow"))
            sys.exit(1)

# === COMMAND EXECUTION ===
def run_command(cmd_list):
    """Executes a command securely and handles errors."""
    try:
        return subprocess.run(
            cmd_list, capture_output=True, text=True, check=True, encoding='utf-8', errors='ignore'
        ).stdout
    except FileNotFoundError:
        raise RuntimeError(f"Command not found: {cmd_list[0]}")
    except subprocess.CalledProcessError as e:
        raise RuntimeError(f"Command failed with exit code {e.returncode}:\n{e.stderr.strip()}")

# === APK DECOMPILATION ===
def decompile_apk(apk_path, output_dir):
    """Decompiles the APK file using Apktool."""
    print(f"[*] Decompiling '{os.path.basename(apk_path)}'...")
    if os.path.exists(output_dir):
        shutil.rmtree(output_dir, ignore_errors=True)
    os.makedirs(output_dir, exist_ok=True)
    try:
        run_command([APKTOOL_PATH, "d", "-f", "-o", output_dir, apk_path])
        print(colored(f"✅ Decompilation successful: '{output_dir}'", "green"))
    except RuntimeError as e:
        print(colored(f"❌ Apktool decompilation failed: {e}", "red"))
        shutil.rmtree(output_dir, ignore_errors=True)
        sys.exit(1)

# === ANALYSIS CORE ===
def scan_files(patterns, search_path):
    """Generic file scanner with confidence logic."""
    if not os.path.isdir(search_path):
        return "None", "Search path not found"
    
    found_defs, found_calls = set(), set()
    file_list = [os.path.join(r, f) for r, _, fs in os.walk(search_path) for f in fs if f.endswith(('.smali', '.xml'))]

    for file_path in tqdm(file_list, desc="Scanning Smali/XML", unit="file", leave=False):
        try:
            with open(file_path, 'r') as f:
                content = f.read()
                for pat in patterns.get('defs', []):
                    if re.search(pat, content, re.IGNORECASE):
                        found_defs.add(pat)
                for pat in patterns.get('calls', []):
                    if re.search(pat, content, re.IGNORECASE):
                        found_calls.add(pat)
        except Exception:
            continue

    if found_defs and found_calls:
        return "High", f"Definitions ({len(found_defs)}) and Calls ({len(found_calls)}) found."
    elif found_defs:
        return "Low", f"Definitions ({len(found_defs)}) found, but no direct calls."
    elif found_calls:
        return "Low", f"Calls ({len(found_calls)}) found, but no custom definitions."
    else:
        return "None", "No evidence found."

def analyze_apk_features(output_dir):
    """Orchestrates the analysis of security features in Smali code."""
    checks = {
        "Screenshot Protection": {'defs': [r'FLAG_SECURE'], 'calls': [r'setFlags\(.*?FLAG_SECURE']},
        "Root Detection": {'defs': [r'isRooted', r'rootbeer', r'magisk'], 'calls': [r'/system/bin/su', r'/system/xbin/su']},
        "Emulator Detection": {'defs': [r'isEmulator'], 'calls': [r'generic', r'goldfish', r'qemu', r'ranchu']},
        "SSL Pinning": {'defs': [r'CertificatePinner', r'okhttp3\.CertificatePinner'], 'calls': [r'checkServerTrusted']},
        "Debug Mode Enabled": {'defs': [r'android:debuggable=\"true\"'], 'calls': [r'Debug\.isDebuggerConnected']},
        "Cleartext Traffic Allowed": {'defs': [r'android:usesCleartextTraffic=\"true\"'], 'calls': [r'http://[^\s"\'<]+']},
        "Hardcoded Secrets": {'defs': [], 'calls': [
            r"password\s*[:=]\s*['\"].+['\"]", r"secret\s*[:=]\s*['\"].+['\"]",
            r"api_?key\s*[:=]\s*['\"].+['\"]", r"token\s*[:=]\s*['\"].+['\"]",
            r'AIza[0-9A-Za-z\-_]{35}', # Google API Key
            r'amzn\.mws\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}' # Amazon MWS Auth Token
        ]},
        "Code Injection Risks": {'defs': [r'loadDex'], 'calls': [r'System\.loadLibrary', r'Runtime\.getRuntime\(\)\.exec', r'Class\.forName']},
        "Insecure WebView": {'defs': [], 'calls': [r'setJavaScriptEnabled\(true\)', r'addJavascriptInterface']},
        "Tapjacking Protection": {'defs': [], 'calls': [r'setFilterTouchesWhenObscured']},
        "Verbose Logging": {'defs': [], 'calls': [r'Log\.d', r'Log\.v', r'System\.out\.println']},
        "Weak Crypto Usage": {'defs': [], 'calls': [r'Cipher\.getInstance\("DES', r'Cipher\.getInstance\("MD5"', r'Cipher\.getInstance\("RC4"']}
    }
    
    results = []
    print("\n[*] Analyzing application features...")
    for name, patterns in checks.items():
        level, reason = scan_files(patterns, output_dir)
        severity = SEVERITY.get(name, "Informational")
        is_vulnerability = name in ["Debug Mode Enabled", "Cleartext Traffic Allowed", "Hardcoded Secrets", "Insecure WebView", "Verbose Logging", "Weak Crypto Usage"]
        
        if level != "None":
            status = colored(f"Detected ({level} confidence)", "yellow") if is_vulnerability else colored(f"Implemented ({level} confidence)", "green")
            results.append({"check": name, "severity": severity, "status": status, "reason": reason})
        else:
            status = colored("Not Detected", "green") if is_vulnerability else colored("Not Implemented", "red")
            results.append({"check": name, "severity": severity, "status": status, "reason": "No evidence found."})
            
    return results

def analyze_native_libs(output_dir):
    """Scans native libraries (.so) for insecure C/C++ functions."""
    print("[*] Analyzing native libraries...")
    insecure_functions = {"strcpy", "strncpy", "strcat", "sprintf", "vsprintf", "gets", "system", "exec", "popen"}
    findings = []
    so_files = [os.path.join(r, f) for r, _, fs in os.walk(output_dir) for f in fs if f.endswith('.so')]

    for so_file in tqdm(so_files, desc="Scanning .so files", unit="file", leave=False):
        try:
            strings_output = run_command([STRINGS_PATH, so_file])
            found = insecure_functions.intersection(set(strings_output.split()))
            if found:
                reason = f"Found in {os.path.basename(so_file)}: {', '.join(found)}"
                findings.append({"check": "Insecure Native Functions", "severity": "High", "status": colored("Detected", "red"), "reason": reason})
        except RuntimeError:
            continue
    return findings

def analyze_manifest(manifest_path):
    """Performs a comprehensive analysis of the AndroidManifest.xml file."""
    print("[*] Analyzing AndroidManifest.xml...")
    results = []
    permissions = {'secure': [], 'insecure': [], 'unknown': []}
    if not os.path.exists(manifest_path):
        return results, permissions

    try:
        ET.register_namespace('android', "http://schemas.android.com/apk/res/android")
        tree = ET.parse(manifest_path)
        root = tree.getroot()
        ns = {'android': 'http://schemas.android.com/apk/res/android'}
        app_node = root.find('application')

        # Check for backup allowed
        if app_node.get(f'{{{ns["android"]}}}allowBackup') == 'true':
            results.append({"check": "Backup Allowed", "severity": "Low", "status": colored("Enabled", "yellow"), "reason": "android:allowBackup is true, sensitive data may be backed up."})

        # Check for exported components
        exported_components = []
        for tag in ['activity', 'service', 'receiver', 'provider']:
            for comp in app_node.findall(tag):
                if comp.get(f'{{{ns["android"]}}}exported') == 'true':
                    name = comp.get(f'{{{ns["android"]}}}name', 'N/A')
                    exported_components.append(f"{tag}: {name}")
        if exported_components:
            results.append({"check": "Exported Components", "severity": "Medium", "status": colored("Detected", "yellow"), "reason": f"{len(exported_components)} components are exported."})
            
        # Analyze permissions
        for perm in root.findall(".//uses-permission"):
            name = perm.get(f'{{{ns["android"]}}}name', '').split('.')[-1]
            if name in SECURE_PERMS: permissions['secure'].append(name)
            elif name in INSECURE_PERMS: permissions['insecure'].append(name)
            else: permissions['unknown'].append(name)
        
    except ET.ParseError as e:
        print(colored(f"❌ Error parsing AndroidManifest.xml: {e}", "red"))
    return results, permissions

# === REPORTING ===
def print_results(all_results, permissions, apk_name):
    """Prints the final analysis results to the console."""
    print("\n" + "="*80)
    print(colored(f"📊 Security Analysis Report for: {apk_name}", "cyan", attrs=["bold"]))
    print("="*80)

    # Sort results by severity
    severity_order = {"High": 0, "Medium": 1, "Low": 2, "Informational": 3}
    sorted_results = sorted(all_results, key=lambda x: severity_order.get(x['severity'], 99))

    for res in sorted_results:
        print(f"[{res['severity']:<13}] {res['check']:<30}: {res['status']:<35} | {res['reason']}")

    print(colored("\n--- AndroidManifest.xml Permissions ---", "white", attrs=["bold"]))
    print(colored("Secure:", "green"), ", ".join(sorted(permissions['secure'])) or "None")
    print(colored("Insecure:", "red"), ", ".join(sorted(permissions['insecure'])) or "None")
    print(colored("Other:", "yellow"), ", ".join(sorted(permissions['unknown'])) or "None")
    print("="*80 + "\n")

def generate_json_report(all_results, permissions, apk_name, output_file):
    """Generates a JSON report of the findings."""
    report = {
        "apkName": apk_name,
        "findings": all_results,
        "permissions": permissions
    }
    # Clean up color codes for JSON
    for finding in report["findings"]:
        finding["status"] = re.sub(r'\x1b\[[0-9;]*m', '', finding["status"])

    try:
        with open(output_file, 'w') as f:
            json.dump(report, f, indent=4)
        print(colored(f"✅ JSON report saved to '{output_file}'", "green"))
    except IOError as e:
        print(colored(f"❌ Failed to write JSON report: {e}", "red"))

# === MAIN EXECUTION BLOCK ===
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Advanced APK Security Analyzer.")
    parser.add_argument("apk", help="Path to the APK file.")
    parser.add_argument("-o", "--output", default="apk_analyzer_out", help="Directory for decompiled files.")
    parser.add_argument("--json", help="Output findings to a JSON file.")
    args = parser.parse_args()

    check_tools()
    if not os.path.isfile(args.apk):
        print(colored(f"❌ Error: APK file not found at '{args.apk}'!", "red"))
        sys.exit(1)

    decompile_apk(args.apk, args.output)
    
    all_findings = []
    all_findings.extend(analyze_apk_features(args.output))
    all_findings.extend(analyze_native_libs(args.output))
    
    manifest_findings, perms = analyze_manifest(os.path.join(args.output, "AndroidManifest.xml"))
    all_findings.extend(manifest_findings)

    apk_filename = os.path.basename(args.apk)
    print_results(all_findings, perms, apk_filename)

    if args.json:
        generate_json_report(all_findings, perms, apk_filename, args.json)

    print(colored("✅ Analysis Complete!", "green", attrs=["bold"]))

