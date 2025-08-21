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
    """Prints a stylized banner."""
    banner = r"""
     ██████╗ ███████╗████████╗███████╗ ██████╗ ████████╗ ██████╗ ██████╗ 
    ██╔═══██╗██╔════╝╚══██╔══╝██╔════╝██╔═══██╗╚══██╔══╝██╔═══██╗██╔══██╗
    ██║   ██║█████╗     ██║   █████╗  ██║         ██║   ██║   ██║██████╔╝
    ██║   ██║██╔══╝     ██║   ██╔══╝  ██║         ██║   ██║   ██║██╔═══╝ 
    ╚██████╔╝███████╗   ██║   ███████╗╚██████╔╝   ██║   ╚██████╔╝██║ ██   
     ╚═════╝ ╚══════╝   ╚═╝   ╚══════╝ ╚═════╝    ╚═╝    ╚═════╝ ╚═╝   ██╗
    """
    print(colored(banner, "green", attrs=["bold"]))
    print(colored("          Developed by Jeeban JD", "yellow", attrs=["bold"]))
    print(colored("          APK Security Analyzer", "green", attrs=["bold"]))
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
    "Screenshot Protection": "Low",
    "Root Detection": "High",
    "Emulator Detection": "Low",
    "Developer Mode Detection": "Low",
    "Screen Mirroring Detection": "Low",
    "SSL Pinning Detection": "Medium",
    "Debug Mode": "High",
    "Cleartext Traffic": "High",
    "Hardcoded Password": "High",
    "Virtual Space Detection": "Medium",
    "Unsafe WiFi Detection": "Low",
    "Repacking Detection": "High",
    "Code Injection Protection": "High",
    "Keylogger Protection": "Medium",
    "ADB Status": "Low",
    "Untrusted Source Detection": "Medium",
    "Memory Corruption Protection": "High",
    "WebView Security": "High",
    "Tapjacking Protection": "Medium",
    "Firebase Security": "Medium",
    "Crypto Implementation": "Low",
    "Biometric Implementation": "Low",
    "Deep Link Handling": "Medium",
    "Content Provider Security": "Medium",
    "Log Security": "Low",
    "Backup Allowed": "Low",
    "Exported Components": "Medium",
    "Insecure Native Functions": "High"
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
    
    found_patterns = set()
    file_list = [os.path.join(r, f) for r, _, fs in os.walk(search_path) for f in fs if f.endswith(('.smali', '.xml'))]

    for file_path in tqdm(file_list, desc="Scanning Smali/XML", unit="file", leave=False):
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
                for pat in patterns:
                    if re.search(pat, content, re.IGNORECASE):
                        found_patterns.add(pat)
        except Exception:
            continue

    if found_patterns:
        return "Detected", f"Found patterns: {', '.join(found_patterns)}"
    else:
        return "Not Detected", "No evidence found."

def analyze_apk_features(output_dir):
    """Orchestrates the analysis of security features in Smali code."""
    checks = [
        ("Screenshot Protection", [r"FLAG_SECURE", r"setFlags\(.*WindowManager.LayoutParams.FLAG_SECURE"]),
        ("Root Detection", [r"su\s*\(", r"rootbeer", r"checkRoot", r"SuperUser", r"magisk", r"supersu", r"/system/bin/su", r"/system/xbin/su"]),
        ("Emulator Detection", [r"ro\.build\.host", r"Genymotion", r"vbox86p", r"EmulatorDetection", r"isEmulator", r"qemu", r"goldfish"]),
        ("Developer Mode Detection", [r"DEVELOPMENT_SETTINGS_ENABLED", r"Settings\.Global\.DEVELOPMENT_SETTINGS_ENABLED", r"isDeveloperMode"]),
        ("Screen Mirroring Detection", [r"DisplayManager", r"getDisplays", r"VIRTUAL_DISPLAY_FLAG_AUTO_MIRROR", r"isScreenCast"]),
        ("SSL Pinning Detection", [r"checkServerTrusted", r"X509TrustManager", r"setSSLSocketFactory", r"TrustManager", r"CertificatePinner", r"pinCertificates"]),
        ("Debug Mode", [r"android:debuggable=\"true\"", r"isDebuggable", r"BuildConfig\.DEBUG", r"Debug\.isDebuggerConnected"]),
        ("Cleartext Traffic", [r"android:usesCleartextTraffic=\"true\"", r"http://", r"cleartext", r"setHostnameVerifier\(.*ALLOW_ALL"]),
        ("Hardcoded Password", [r"password\s*=\s*['\"].+['\"]", r"passwd\s*=\s*['\"].+['\"]", r"secret\s*=\s*['\"].+['\"]", r"api[_-]?key\s*=\s*['\"].+['\"]"]),
        ("Virtual Space Detection", [r"virtualapp", r"com\.lbe\.doubleagent", r"com\.android\.virtual", r"parallel", r"dualspace"]),
        ("Unsafe WiFi Detection", [r"WifiManager", r"getScanResults", r"open wifi", r"WEP", r"no password", r"isSecure"]),
        ("Repacking Detection", [r"checkSignature", r"verifySignature", r"getPackageManager", r"getPackageInfo", r"validateAppSignature"]),
        ("Code Injection Protection", [r"loadLibrary", r"System\.load", r"Class\.forName", r"Reflection", r"getDeclaredMethod", r"invoke\("]),
        ("Keylogger Protection", [r"InputMethodManager", r"onKey", r"dispatchKeyEvent", r"onKeyDown"]),
        ("ADB Status", [r"adb_enabled", r"Settings\.Global\.ADB_ENABLED", r"isAdbEnabled"]),
        ("Untrusted Source Detection", [r"INSTALL_NON_MARKET_APPS", r"Unknown Sources", r"verifyInstaller", r"getInstallerPackageName"]),
        ("Memory Corruption Protection", [r"memset", r"memcpy", r"strcpy", r"strncpy", r"sprintf"]),
        ("WebView Security", [r"setJavaScriptEnabled", r"addJavascriptInterface", r"WebViewClient", r"onReceivedSslError"]),
        ("Tapjacking Protection", [r"setFilterTouchesWhenObscured", r"FLAG_WINDOW_IS_OBSCURED", r"onFilterTouchEventForSecurity"]),
        ("Firebase Security", [r"FirebaseAuth", r"FirebaseDatabase", r"getReference", r"setValue"]),
        ("Crypto Implementation", [r"Cipher", r"getInstance", r"AES", r"DES", r"RSA", r"BouncyCastle", r"SecureRandom"]),
        ("Biometric Implementation", [r"BiometricPrompt", r"FingerprintManager", r"authenticate", r"canAuthenticate"]),
        ("Deep Link Handling", [r"BROWSABLE", r"VIEW", r"intent-filter", r"android:scheme"]),
        ("Content Provider Security", [r"content://", r"ContentProvider", r"android:exported=\"true\"", r"UriMatcher"]),
        ("Log Security", [r"Log\.d", r"Log\.v", r"Log\.i", r"println", r"System\.out\.print"]),
    ]
    
    results = []
    print("\n[*] Analyzing application features...")
    for name, patterns in checks:
        status, reason = scan_files(patterns, output_dir)
        severity = SEVERITY.get(name, "Informational")
        
        # Determine the color based on status
        if status == "Detected":
            color = "yellow" if severity in ["Low", "Medium"] else "red"
            status_text = colored(status, color)
        else:
            color = "green"
            status_text = colored(status, color)
        
        results.append({
            "check": name,
            "severity": severity,
            "status": status_text,
            "reason": reason
        })
            
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
        if app_node is not None and app_node.get(f'{{{ns["android"]}}}allowBackup') == 'true':
            results.append({"check": "Backup Allowed", "severity": "Low", "status": colored("Enabled", "yellow"), "reason": "android:allowBackup is true, sensitive data may be backed up."})
        else:
            results.append({"check": "Backup Allowed", "severity": "Low", "status": colored("Disabled", "green"), "reason": "android:allowBackup is false or not set."})

        # Check for exported components
        exported_components = []
        for tag in ['activity', 'service', 'receiver', 'provider']:
            for comp in root.findall(f'.//{tag}'):
                if comp.get(f'{{{ns["android"]}}}exported') == 'true':
                    name = comp.get(f'{{{ns["android"]}}}name', 'N/A')
                    exported_components.append(f"{tag}: {name}")
        if exported_components:
            results.append({"check": "Exported Components", "severity": "Medium", "status": colored("Detected", "yellow"), "reason": f"{len(exported_components)} components are exported."})
        else:
            results.append({"check": "Exported Components", "severity": "Medium", "status": colored("Not Detected", "green"), "reason": "No components are exported."})
            
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
