#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
APK Security Analyzer - Advanced Edition v2.0.0
Performs in-depth static analysis of Android APK files.
"""

import os
import re
import sys
import json
import math
import shutil
import hashlib
import argparse
import subprocess
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from xml.etree import ElementTree as ET

try:
    from tqdm import tqdm
    from termcolor import colored
    from colorama import init
    init(autoreset=True)
except ImportError:
    subprocess.check_call([sys.executable, "-m", "pip", "install",
                           "termcolor", "colorama", "tqdm", "--quiet"])
    from tqdm import tqdm
    from termcolor import colored
    from colorama import init
    init(autoreset=True)

# ── CONFIG ────────────────────────────────────────────────────────────────────
APKTOOL_PATH = "apktool"
STRINGS_PATH = "strings"
VERSION      = "2.0.0"
MAX_WORKERS  = min(8, (os.cpu_count() or 2) * 2)

# ── PERMISSION SETS ───────────────────────────────────────────────────────────
SECURE_PERMS = {
    "INTERNET", "ACCESS_NETWORK_STATE", "ACCESS_WIFI_STATE", "VIBRATE",
    "WAKE_LOCK", "RECEIVE_BOOT_COMPLETED", "POST_NOTIFICATIONS", "FOREGROUND_SERVICE",
    "USE_FINGERPRINT", "REQUEST_IGNORE_BATTERY_OPTIMIZATIONS",
}
INSECURE_PERMS = {
    "READ_SMS", "RECEIVE_SMS", "SEND_SMS", "READ_PHONE_STATE", "WRITE_SETTINGS",
    "READ_EXTERNAL_STORAGE", "WRITE_EXTERNAL_STORAGE", "SYSTEM_ALERT_WINDOW",
    "REQUEST_INSTALL_PACKAGES", "MANAGE_EXTERNAL_STORAGE", "QUERY_ALL_PACKAGES",
    "BIND_ACCESSIBILITY_SERVICE", "USE_BIOMETRIC", "ACCESS_FINE_LOCATION",
    "ACCESS_COARSE_LOCATION", "READ_CONTACTS", "WRITE_CONTACTS", "GET_ACCOUNTS",
    "PROCESS_OUTGOING_CALLS", "READ_CALL_LOG", "WRITE_CALL_LOG",
    "RECORD_AUDIO", "CAMERA", "READ_MEDIA_IMAGES", "READ_MEDIA_VIDEO",
}

DANGEROUS_COMBOS = [
    ({"READ_SMS", "SEND_SMS"},                       "Toll Fraud / SMS Phishing risk"),
    ({"RECORD_AUDIO", "INTERNET"},                   "Potential audio exfiltration"),
    ({"ACCESS_FINE_LOCATION", "INTERNET"},           "Location tracking risk"),
    ({"READ_CONTACTS", "INTERNET"},                  "Contact harvesting risk"),
    ({"CAMERA", "INTERNET"},                         "Remote camera access risk"),
    ({"READ_SMS", "INTERNET"},                       "SMS interception / OTP theft risk"),
    ({"BIND_ACCESSIBILITY_SERVICE", "INTERNET"},     "Overlay / keylogging risk"),
]

# ── SEVERITY & CVSS MAPPING ───────────────────────────────────────────────────
CHECKS_META = {
    "Screenshot Protection":        ("Low",    3.1, []),
    "Root Detection":               ("High",   8.1, ["CVE-2014-7911"]),
    "Emulator Detection":           ("Low",    2.5, []),
    "Developer Mode Detection":     ("Low",    2.5, []),
    "Screen Mirroring Detection":   ("Low",    3.0, []),
    "SSL Pinning Detection":        ("Medium", 6.5, ["CWE-295"]),
    "Debug Mode":                   ("High",   7.5, ["CWE-215"]),
    "Cleartext Traffic":            ("High",   8.0, ["CWE-319"]),
    "Hardcoded Secret":             ("High",   9.0, ["CWE-798", "CWE-259"]),
    "Virtual Space Detection":      ("Medium", 5.0, []),
    "Unsafe WiFi Detection":        ("Low",    4.0, []),
    "Repacking Detection":          ("High",   7.5, ["CWE-494"]),
    "Code Injection Protection":    ("High",   8.5, ["CWE-470", "CWE-94"]),
    "Keylogger Protection":         ("Medium", 6.0, ["CWE-312"]),
    "ADB Status":                   ("Low",    3.0, []),
    "Untrusted Source Detection":   ("Medium", 5.5, ["CWE-494"]),
    "Memory Corruption Protection": ("High",   8.8, ["CWE-120", "CWE-121"]),
    "WebView Security":             ("High",   8.0, ["CWE-749", "CVE-2012-6636"]),
    "Tapjacking Protection":        ("Medium", 5.0, ["CWE-1021"]),
    "Firebase Security":            ("Medium", 6.5, ["CWE-732"]),
    "Weak Crypto":                  ("High",   7.4, ["CWE-327", "CWE-328"]),
    "Biometric Implementation":     ("Low",    3.5, []),
    "Deep Link Handling":           ("Medium", 5.8, ["CWE-939"]),
    "Content Provider Security":    ("Medium", 6.0, ["CWE-926"]),
    "Log Security":                 ("Low",    3.0, ["CWE-532"]),
    "Backup Allowed":               ("Low",    3.5, ["CWE-530"]),
    "Exported Components":          ("Medium", 6.5, ["CWE-926"]),
    "Intent Hijacking":             ("Medium", 6.5, ["CWE-927"]),
    "Implicit Intents":             ("Medium", 5.5, ["CWE-927"]),
    "Insecure Native Functions":    ("High",   8.8, ["CWE-120", "CWE-676"]),
    "Obfuscation / Packer":         ("Medium", 5.0, []),
    "Network Security Config":      ("Medium", 6.0, ["CWE-295"]),
    "Dangerous Permission Combo":   ("High",   7.5, ["CWE-272"]),
    "Entropy Secret Detection":     ("High",   9.0, ["CWE-798"]),
}

# ── BANNER ────────────────────────────────────────────────────────────────────
def print_banner():
    lines = [
        "  ____  _____ _____ _____ ____ _____ ___  ____  ",
        " |  _ \\| ____|_   _| ____/ ___|_   _/ _ \\|  _ \\ ",
        " | | | |  _|   | | |  _|| |     | || | | | |_) |",
        " | |_| | |___  | | | |__| |___  | || |_| |  _ < ",
        " |____/|_____| |_| |_____\\____| |_| \\___/|_| \\_\\",
    ]
    print(colored("\n".join(lines), "green", attrs=["bold"]))
    print(colored("          APK Security Analyzer  v" + VERSION, "cyan", attrs=["bold"]))
    print(colored("          Developed by Jeeban JD  |  Advanced Edition", "yellow"))
    print(colored("=" * 72, "magenta", attrs=["bold"]))

# ── TOOL VERIFICATION ─────────────────────────────────────────────────────────
def check_tools():
    for tool, path in [("Apktool", APKTOOL_PATH), ("strings", STRINGS_PATH)]:
        if not shutil.which(path):
            print(colored("  [X] " + tool + " not found at '" + path + "'.", "red"))
            print(colored("      Install " + tool + " and add it to PATH.", "yellow"))
            sys.exit(1)

# ── COMMAND EXECUTION ─────────────────────────────────────────────────────────
def run_command(cmd_list, timeout=120):
    try:
        return subprocess.run(
            cmd_list, capture_output=True, text=True,
            check=True, encoding="utf-8", errors="ignore", timeout=timeout
        ).stdout
    except FileNotFoundError:
        raise RuntimeError("Command not found: " + cmd_list[0])
    except subprocess.TimeoutExpired:
        raise RuntimeError("Command timed out: " + " ".join(cmd_list))
    except subprocess.CalledProcessError as e:
        raise RuntimeError("Command failed (exit " + str(e.returncode) + "):\n" + e.stderr.strip())

# ── APK INFO ──────────────────────────────────────────────────────────────────
def get_apk_info(apk_path):
    size_mb = os.path.getsize(apk_path) / (1024 * 1024)
    sha256 = hashlib.sha256()
    with open(apk_path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            sha256.update(chunk)
    return {"sha256": sha256.hexdigest(), "size_mb": round(size_mb, 2)}

# ── DECOMPILATION ─────────────────────────────────────────────────────────────
def decompile_apk(apk_path, output_dir):
    print("\n[*] Decompiling '" + os.path.basename(apk_path) + "'...")
    if os.path.exists(output_dir):
        shutil.rmtree(output_dir, ignore_errors=True)
    os.makedirs(output_dir, exist_ok=True)
    try:
        run_command([APKTOOL_PATH, "d", "-f", "-o", output_dir, apk_path])
        print(colored("[+] Decompiled -> '" + output_dir + "'", "green"))
    except RuntimeError as e:
        print(colored("[-] Apktool failed: " + str(e), "red"))
        shutil.rmtree(output_dir, ignore_errors=True)
        sys.exit(1)

# ── ENTROPY HELPER ────────────────────────────────────────────────────────────
def shannon_entropy(data):
    if not data:
        return 0.0
    freq = {}
    for c in data:
        freq[c] = freq.get(c, 0) + 1
    length = len(data)
    return -sum((v / length) * math.log2(v / length) for v in freq.values())

# ── SINGLE FILE SCANNER ───────────────────────────────────────────────────────
def _scan_single_file(file_path, patterns):
    hits = []
    try:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            for lineno, line in enumerate(f, 1):
                for pat in patterns:
                    if re.search(pat, line, re.IGNORECASE):
                        hits.append((pat, lineno))
    except Exception:
        pass
    return hits

# ── PARALLEL SCANNER ──────────────────────────────────────────────────────────
def scan_files(patterns, search_path, verbose=False):
    if not os.path.isdir(search_path):
        return "None", "Search path not found", []

    file_list = [
        os.path.join(r, fn)
        for r, _, fs in os.walk(search_path)
        for fn in fs if fn.endswith((".smali", ".xml", ".java"))
    ]

    found_patterns = {}
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as exe:
        futures = {exe.submit(_scan_single_file, fp, patterns): fp for fp in file_list}
        for future in as_completed(futures):
            fp = futures[future]
            hits = future.result()
            for pat, lineno in hits:
                found_patterns.setdefault(pat, []).append(fp + ":" + str(lineno))

    if found_patterns:
        reason = "Patterns matched: " + ", ".join(found_patterns.keys())
        locations = [loc for locs in found_patterns.values() for loc in locs[:3]]
        return "Detected", reason, locations
    return "Not Detected", "No evidence found.", []

# ── ENTROPY SECRET SCANNER ────────────────────────────────────────────────────
_SECRET_RE = re.compile(
    r"(?:api[_\-]?key|secret|token|password|passwd|auth|bearer|private[_\-]?key)"
    r"\s*[=:]\s*[\"']?([A-Za-z0-9+/=_\-]{16,})[\"']?",
    re.IGNORECASE,
)

def scan_entropy_secrets(search_path, threshold=4.5):
    findings = []
    file_list = [
        os.path.join(r, fn)
        for r, _, fs in os.walk(search_path)
        for fn in fs if fn.endswith((".smali", ".xml", ".java", ".properties", ".json"))
    ]
    for fp in file_list:
        try:
            with open(fp, "r", encoding="utf-8", errors="ignore") as f:
                for lineno, line in enumerate(f, 1):
                    for m in _SECRET_RE.finditer(line):
                        val = m.group(1)
                        if shannon_entropy(val) >= threshold:
                            rel = os.path.relpath(fp, search_path)
                            findings.append(rel + ":" + str(lineno) + " -- '" + val[:30] + "...'")
        except Exception:
            continue
    return findings

# ── OBFUSCATION DETECTION ─────────────────────────────────────────────────────
def detect_obfuscation(output_dir):
    packer_signatures = [
        r"jiagu", r"bangcle", r"ijiami", r"qihoo", r"360protect",
        r"tencent\.mm\.odex", r"libbavmpatch", r"libddog", r"libmtguard",
    ]
    short_id_re = re.compile(r"\.class\s+\S+\s+L([a-z])/([a-z])\b", re.IGNORECASE)
    packer_hits, short_id_count, total_classes = [], 0, 0

    smali_files = [
        os.path.join(r, fn)
        for r, _, fs in os.walk(output_dir)
        for fn in fs if fn.endswith(".smali")
    ]
    for fp in smali_files:
        try:
            with open(fp, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()
            total_classes += content.count(".class ")
            if short_id_re.search(content):
                short_id_count += 1
            for sig in packer_signatures:
                if re.search(sig, content, re.IGNORECASE):
                    packer_hits.append(sig)
        except Exception:
            continue

    ratio = (short_id_count / total_classes) if total_classes else 0
    hints = []
    if ratio > 0.3:
        hints.append("High short-identifier ratio (" + "{:.0%}".format(ratio) + ")")
    if packer_hits:
        hints.append("Packer signatures: " + ", ".join(set(packer_hits)))

    if hints:
        return "Detected", " | ".join(hints), []
    return "Not Detected", "No obfuscation/packer indicators found.", []

# ── NETWORK SECURITY CONFIG ───────────────────────────────────────────────────
def analyze_network_security_config(output_dir):
    nsc_path = os.path.join(output_dir, "res", "xml", "network_security_config.xml")
    if not os.path.exists(nsc_path):
        return "Not Found", "network_security_config.xml absent -- default platform policy applies.", []
    try:
        tree = ET.parse(nsc_path)
        root = tree.getroot()
        issues = []
        for domain_config in root.iter("domain-config"):
            ct = domain_config.find("cleartext-traffic-permitted")
            if ct is not None and ct.get("value", "false").lower() == "true":
                issues.append("cleartext-traffic-permitted=true for a domain")
        for ta in root.iter("trust-anchors"):
            for cert in ta.findall("certificates"):
                src = cert.get("src", "")
                if src in ("user", "@raw/"):
                    issues.append("User/custom CA trusted: " + src)
        if issues:
            return "Issues Found", "; ".join(issues), [nsc_path]
        return "Secure", "NSC present, no obvious misconfigurations.", []
    except ET.ParseError as e:
        return "Parse Error", str(e), []

# ── INTENT ANALYSIS ───────────────────────────────────────────────────────────
def _meta(name):
    severity, cvss, cves = CHECKS_META.get(name, ("Informational", 0.0, []))
    return {"cvss": cvss, "cve_refs": cves}

def analyze_intents(manifest_path):
    results = []
    if not os.path.exists(manifest_path):
        return results
    try:
        tree = ET.parse(manifest_path)
        root = tree.getroot()
        ns_a = "http://schemas.android.com/apk/res/android"
        implicit_actions, hijack_candidates = [], []

        for ifilter in root.iter("intent-filter"):
            actions = [
                a.get("{" + ns_a + "}name", "")
                for a in ifilter.findall("action")
            ]
            for action in actions:
                if action and "android.intent.action" in action:
                    implicit_actions.append(action)
            sensitive = {"android.intent.action.VIEW", "android.intent.action.SEND"}
            if any(a in sensitive for a in actions):
                hijack_candidates.append(actions[0] if actions else "unknown")

        if implicit_actions:
            entry = {
                "check":      "Implicit Intents",
                "severity":   "Medium",
                "status_raw": "Detected",
                "reason":     str(len(implicit_actions)) + " implicit intent actions found.",
                "locations":  implicit_actions[:5],
            }
            entry.update(_meta("Implicit Intents"))
            results.append(entry)

        if hijack_candidates:
            entry = {
                "check":      "Intent Hijacking",
                "severity":   "Medium",
                "status_raw": "Detected",
                "reason":     "Potential hijack targets: " + ", ".join(set(hijack_candidates[:3])),
                "locations":  [],
            }
            entry.update(_meta("Intent Hijacking"))
            results.append(entry)

    except ET.ParseError:
        pass
    return results

# ── FEATURE CHECKS ────────────────────────────────────────────────────────────
FEATURE_CHECKS = [
    ("Screenshot Protection",        [r"FLAG_SECURE", r"setFlags\(.*FLAG_SECURE"]),
    ("Root Detection",               [r"\bsu\b", r"rootbeer", r"checkRoot", r"SuperUser",
                                      r"magisk", r"supersu", r"/system/bin/su", r"/system/xbin/su",
                                      r"com\.topjohnwu\.magisk"]),
    ("Emulator Detection",           [r"ro\.build\.host", r"Genymotion", r"vbox86p",
                                      r"isEmulator", r"qemu", r"goldfish", r"sdk_gphone"]),
    ("Developer Mode Detection",     [r"DEVELOPMENT_SETTINGS_ENABLED", r"isDeveloperMode"]),
    ("Screen Mirroring Detection",   [r"MediaProjection", r"createVirtualDisplay", r"MEDIA_PROJECTION"]),
    ("SSL Pinning Detection",        [r"CertificatePinner", r"TrustManagerImpl", r"SSLContext",
                                      r"checkServerTrusted", r"X509TrustManager"]),
    ("Debug Mode",                   [r"android:debuggable=\"true\"", r"BuildConfig\.DEBUG",
                                      r"stetho", r"com\.facebook\.stetho"]),
    ("Cleartext Traffic",            [r"android:usesCleartextTraffic=\"true\"", r"http://",
                                      r"HttpURLConnection"]),
    ("Hardcoded Secret",             [r'(?:password|passwd|secret|apikey|api_key|token)\s*=\s*"[^"]{6,}"',
                                      r"(?:PRIVATE KEY|BEGIN RSA)"]),
    ("Virtual Space Detection",      [r"virtualapp", r"com\.lbe\.doubleagent", r"parallel", r"dualspace"]),
    ("Unsafe WiFi Detection",        [r"WEP", r"isSecure\(\)", r"getScanResults"]),
    ("Repacking Detection",          [r"checkSignature", r"validateAppSignature", r"getPackageInfo"]),
    ("Code Injection Protection",    [r"loadLibrary", r"System\.load", r"Class\.forName",
                                      r"getDeclaredMethod", r"\.invoke\("]),
    ("Keylogger Protection",         [r"InputMethodManager", r"dispatchKeyEvent", r"onKeyDown"]),
    ("ADB Status",                   [r"adb_enabled", r"Settings\.Global\.ADB_ENABLED"]),
    ("Untrusted Source Detection",   [r"INSTALL_NON_MARKET_APPS", r"verifyInstaller"]),
    ("Memory Corruption Protection", [r"\bmemset\b", r"\bstrcpy\b", r"\bsprintf\b", r"\bgets\b"]),
    ("WebView Security",             [r"setJavaScriptEnabled\(true\)", r"addJavascriptInterface",
                                      r"onReceivedSslError", r"setAllowFileAccess\(true\)"]),
    ("Tapjacking Protection",        [r"setFilterTouchesWhenObscured", r"FLAG_WINDOW_IS_OBSCURED"]),
    ("Firebase Security",            [r"FirebaseDatabase", r"getReference\(", r"setValue\("]),
    ("Weak Crypto",                  [r"\bDES\b", r"\bRC4\b", r"\bMD5\b", r"SHA-?1\b",
                                      r'getInstance\("DES', r'getInstance\("RC4']),
    ("Biometric Implementation",     [r"BiometricPrompt", r"FingerprintManager", r"canAuthenticate"]),
    ("Deep Link Handling",           [r"android:scheme", r"BROWSABLE", r"DeepLink"]),
    ("Content Provider Security",    [r'android:exported="true".*[Pp]rovider', r"ContentProvider",
                                      r"UriMatcher"]),
    ("Log Security",                 [r"Log\.[dvie]\(", r"System\.out\.print", r"printStackTrace"]),
]

def analyze_apk_features(output_dir, verbose=False):
    results = []
    print("\n[*] Scanning Smali / XML files (parallel)...")
    for name, patterns in tqdm(FEATURE_CHECKS, desc="Feature checks", unit="check"):
        status, reason, locations = scan_files(patterns, output_dir, verbose)
        severity, cvss, cves = CHECKS_META.get(name, ("Informational", 0.0, []))
        results.append({
            "check":      name,
            "severity":   severity,
            "status_raw": status,
            "reason":     reason,
            "locations":  locations[:5] if verbose else [],
            "cvss":       cvss,
            "cve_refs":   cves,
        })
    return results

# ── ADVANCED CHECKS ───────────────────────────────────────────────────────────
def run_advanced_checks(output_dir, verbose=False):
    results = []

    print("[*] Running entropy-based secret detection...")
    secrets = scan_entropy_secrets(output_dir)
    results.append({
        "check":      "Entropy Secret Detection",
        "severity":   "High",
        "status_raw": "Detected" if secrets else "Not Detected",
        "reason":     str(len(secrets)) + " high-entropy secret(s) found." if secrets
                      else "No high-entropy secrets found.",
        "locations":  secrets[:5] if (verbose and secrets) else [],
        "cvss":       9.0,
        "cve_refs":   ["CWE-798"],
    })

    print("[*] Checking for obfuscation / packers...")
    status, reason, locs = detect_obfuscation(output_dir)
    results.append({
        "check":      "Obfuscation / Packer",
        "severity":   "Medium",
        "status_raw": status,
        "reason":     reason,
        "locations":  locs,
        "cvss":       5.0,
        "cve_refs":   [],
    })

    print("[*] Analyzing Network Security Config...")
    status, reason, locs = analyze_network_security_config(output_dir)
    status_raw = "Issues Found" if status in ("Issues Found", "Parse Error") else "Not Detected"
    results.append({
        "check":      "Network Security Config",
        "severity":   "Medium",
        "status_raw": status_raw,
        "reason":     "[" + status + "] " + reason,
        "locations":  locs,
        "cvss":       6.0,
        "cve_refs":   ["CWE-295"],
    })
    return results

# ── NATIVE LIBRARY SCAN ───────────────────────────────────────────────────────
INSECURE_NATIVE = {
    "strcpy", "strncpy", "strcat", "strncat",
    "sprintf", "vsprintf", "gets", "system", "exec", "popen",
    "memcpy", "memmove", "scanf",
}

def analyze_native_libs(output_dir):
    print("[*] Scanning native libraries (.so)...")
    findings = []
    so_files = [
        os.path.join(r, fn)
        for r, _, fs in os.walk(output_dir)
        for fn in fs if fn.endswith(".so")
    ]
    for so_file in tqdm(so_files, desc=".so files", unit="file", leave=False):
        try:
            out = run_command([STRINGS_PATH, so_file])
            found = INSECURE_NATIVE.intersection(set(re.split(r"\W+", out)))
            if found:
                findings.append({
                    "check":      "Insecure Native Functions",
                    "severity":   "High",
                    "status_raw": "Detected",
                    "reason":     os.path.basename(so_file) + ": " + ", ".join(sorted(found)),
                    "locations":  [so_file],
                    "cvss":       8.8,
                    "cve_refs":   ["CWE-120", "CWE-676"],
                })
        except RuntimeError:
            continue
    return findings

# ── MANIFEST ANALYSIS ─────────────────────────────────────────────────────────
def analyze_manifest(manifest_path):
    print("[*] Analyzing AndroidManifest.xml...")
    results = []
    permissions = {"secure": [], "insecure": [], "unknown": []}
    if not os.path.exists(manifest_path):
        return results, permissions, []

    try:
        tree = ET.parse(manifest_path)
        root = tree.getroot()
        ns_uri = "http://schemas.android.com/apk/res/android"

        def A(tag):
            return "{" + ns_uri + "}" + tag

        app = root.find("application")

        # allowBackup
        backup = app.get(A("allowBackup"), "false") if app is not None else "false"
        results.append({
            "check":      "Backup Allowed",
            "severity":   "Low",
            "status_raw": "Enabled" if backup == "true" else "Disabled",
            "reason":     "android:allowBackup=true, sensitive data may be backed up."
                          if backup == "true" else "android:allowBackup disabled.",
            "locations":  [], "cvss": 3.5, "cve_refs": ["CWE-530"],
        })

        # usesCleartextTraffic
        cleartext = app.get(A("usesCleartextTraffic"), "false") if app is not None else "false"
        if cleartext == "true":
            results.append({
                "check":      "Cleartext Traffic",
                "severity":   "High",
                "status_raw": "Detected",
                "reason":     "android:usesCleartextTraffic=true allows HTTP traffic.",
                "locations":  [], "cvss": 8.0, "cve_refs": ["CWE-319"],
            })

        # debuggable
        debuggable = app.get(A("debuggable"), "false") if app is not None else "false"
        if debuggable == "true":
            results.append({
                "check":      "Debug Mode",
                "severity":   "High",
                "status_raw": "Detected",
                "reason":     "android:debuggable=true -- app can be attached with debugger.",
                "locations":  [], "cvss": 7.5, "cve_refs": ["CWE-215"],
            })

        # Exported components
        exported = []
        for tag in ["activity", "service", "receiver", "provider"]:
            for comp in root.findall(".//" + tag):
                if comp.get(A("exported")) == "true":
                    name = comp.get(A("name"), "N/A")
                    exported.append(tag + ":" + name)
        results.append({
            "check":      "Exported Components",
            "severity":   "Medium",
            "status_raw": "Detected" if exported else "Not Detected",
            "reason":     str(len(exported)) + " exported: " + ", ".join(exported[:3])
                          if exported else "No exported components.",
            "locations":  [], "cvss": 6.5, "cve_refs": ["CWE-926"],
        })

        # Permissions
        all_perm_names = []
        for perm in root.findall(".//uses-permission"):
            full_name = perm.get(A("name"), "")
            short = full_name.split(".")[-1]
            all_perm_names.append(short)
            if short in SECURE_PERMS:
                permissions["secure"].append(short)
            elif short in INSECURE_PERMS:
                permissions["insecure"].append(short)
            else:
                permissions["unknown"].append(short)

        # Dangerous combos
        perm_set = set(all_perm_names)
        combo_hits = [desc for combo, desc in DANGEROUS_COMBOS if combo.issubset(perm_set)]
        if combo_hits:
            results.append({
                "check":      "Dangerous Permission Combo",
                "severity":   "High",
                "status_raw": "Detected",
                "reason":     " | ".join(combo_hits),
                "locations":  [], "cvss": 7.5, "cve_refs": ["CWE-272"],
            })

        results.extend(analyze_intents(manifest_path))

    except ET.ParseError as e:
        print(colored("[-] Manifest parse error: " + str(e), "red"))

    return results, permissions, []

# ── RISK SCORE ────────────────────────────────────────────────────────────────
def compute_risk_score(all_results):
    weights = {"High": 3, "Medium": 2, "Low": 1, "Informational": 0}
    total, detected = 0, 0
    for r in all_results:
        w = weights.get(r.get("severity", "Informational"), 0)
        total += w
        if r.get("status_raw", "") in ("Detected", "Enabled", "Issues Found"):
            detected += w
    return round((detected / total) * 100) if total else 0

# ── CONSOLE REPORT ────────────────────────────────────────────────────────────
SEV_COLOR = {"High": "red", "Medium": "yellow", "Low": "cyan", "Informational": "white"}

def print_results(all_results, permissions, apk_name, apk_info, verbose=False):
    print("\n" + "=" * 90)
    print(colored("  Security Report -- " + apk_name, "cyan", attrs=["bold"]))
    print(colored("  SHA-256: " + apk_info["sha256"] + "   Size: " + str(apk_info["size_mb"]) + " MB", "white"))
    print("=" * 90)

    order = {"High": 0, "Medium": 1, "Low": 2, "Informational": 3}
    for r in sorted(all_results, key=lambda x: order.get(x.get("severity", "Informational"), 99)):
        sev    = r.get("severity", "Info")
        name   = r.get("check", "")
        raw    = r.get("status_raw", "")
        reason = r.get("reason", "")
        cvss   = r.get("cvss", 0.0)
        cves   = r.get("cve_refs", [])

        if raw in ("Detected", "Enabled", "Issues Found"):
            status_c = colored(raw, SEV_COLOR.get(sev, "white"), attrs=["bold"])
        else:
            status_c = colored(raw, "green")

        sev_c = colored("{:<8}".format(sev), SEV_COLOR.get(sev, "white"))
        cve_s = " [" + ", ".join(cves) + "]" if cves else ""
        print(" " + sev_c + " CVSS:{:<4} {:<35} {:<20} {}{}".format(cvss, name, raw, reason, cve_s))

        if verbose and r.get("locations"):
            for loc in r["locations"]:
                print(colored("            -> " + str(loc), "white"))

    risk = compute_risk_score(all_results)
    risk_color = "red" if risk >= 70 else "yellow" if risk >= 40 else "green"
    print("\n" + "=" * 90)
    print(colored("  Overall Risk Score: " + str(risk) + "/100", risk_color, attrs=["bold"]))
    print("=" * 90)
    print(colored("\n  Permissions", "white", attrs=["bold"]))
    print(colored("  Secure:   ", "green")  + (", ".join(sorted(permissions["secure"]))  or "None"))
    print(colored("  Insecure: ", "red")    + (", ".join(sorted(permissions["insecure"])) or "None"))
    print(colored("  Other:    ", "yellow") + (", ".join(sorted(permissions["unknown"]))  or "None"))
    print()

# ── JSON REPORT ───────────────────────────────────────────────────────────────
def generate_json_report(all_results, permissions, apk_name, apk_info, output_file):
    report = {
        "tool":        "APK Security Analyzer v" + VERSION,
        "timestamp":   datetime.utcnow().isoformat() + "Z",
        "apkName":     apk_name,
        "apkInfo":     apk_info,
        "riskScore":   compute_risk_score(all_results),
        "findings":    all_results,
        "permissions": permissions,
    }
    try:
        with open(output_file, "w") as f:
            json.dump(report, f, indent=4, default=str)
        print(colored("[+] JSON report -> '" + output_file + "'", "green"))
    except IOError as e:
        print(colored("[-] JSON write failed: " + str(e), "red"))

# ── HTML REPORT ───────────────────────────────────────────────────────────────
def generate_html_report(all_results, permissions, apk_name, apk_info, output_file):
    risk = compute_risk_score(all_results)
    sev_counts = {"High": 0, "Medium": 0, "Low": 0, "Informational": 0}
    for r in all_results:
        if r.get("status_raw") in ("Detected", "Enabled", "Issues Found"):
            k = r.get("severity", "Informational")
            sev_counts[k] = sev_counts.get(k, 0) + 1

    sev_hex = {"High": "#e74c3c", "Medium": "#e67e22", "Low": "#3498db", "Informational": "#95a5a6"}
    order   = {"High": 0, "Medium": 1, "Low": 2, "Informational": 3}
    sorted_results = sorted(all_results, key=lambda x: order.get(x.get("severity", "Informational"), 99))

    rows = ""
    for r in sorted_results:
        sev   = r.get("severity", "Info")
        raw   = r.get("status_raw", "")
        color = sev_hex.get(sev, "#95a5a6")
        bg    = "#fdecea" if raw in ("Detected", "Enabled", "Issues Found") else "#eafaf1"
        cves  = ", ".join(r.get("cve_refs", [])) or "--"
        td_color = "#c0392b" if raw in ("Detected", "Enabled", "Issues Found") else "#27ae60"
        rows += (
            '<tr style="background:' + bg + '">'
            '<td><span style="color:' + color + ';font-weight:bold">' + sev + "</span></td>"
            "<td>" + r.get("check", "") + "</td>"
            '<td style="color:' + td_color + ';font-weight:bold">' + raw + "</td>"
            "<td>" + r.get("reason", "") + "</td>"
            "<td>" + str(r.get("cvss", 0.0)) + "</td>"
            "<td>" + cves + "</td>"
            "</tr>\n"
        )

    perm_rows = ""
    for p in sorted(permissions.get("insecure", [])):
        perm_rows += '<tr><td style="color:#e74c3c">' + p + "</td><td>Insecure</td></tr>\n"
    for p in sorted(permissions.get("secure", [])):
        perm_rows += '<tr><td style="color:#27ae60">' + p + "</td><td>Secure</td></tr>\n"
    for p in sorted(permissions.get("unknown", [])):
        perm_rows += '<tr><td style="color:#e67e22">' + p + "</td><td>Other</td></tr>\n"

    risk_color = "#e74c3c" if risk >= 70 else "#e67e22" if risk >= 40 else "#27ae60"
    generated  = datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")

    html = """<!DOCTYPE html>
<html lang="en">
<head><meta charset="UTF-8">
<title>APK Security Report</title>
<style>
  body{font-family:'Segoe UI',sans-serif;background:#1a1a2e;color:#eee;margin:0;padding:20px}
  h1{color:#00d4ff} h2{color:#a29bfe;border-bottom:1px solid #444;padding-bottom:6px}
  .meta{background:#16213e;border-radius:8px;padding:14px;margin-bottom:20px;font-size:0.85em}
  .score{font-size:2.5em;font-weight:bold;color:""" + risk_color + """}
  .cards{display:flex;gap:16px;flex-wrap:wrap;margin-bottom:20px}
  .card{background:#16213e;border-radius:8px;padding:16px 24px;min-width:120px;text-align:center}
  .card .num{font-size:2em;font-weight:bold} .card .lbl{font-size:0.8em;color:#aaa}
  table{width:100%;border-collapse:collapse;margin-bottom:30px}
  th{background:#0f3460;color:#a29bfe;padding:10px;text-align:left}
  td{padding:8px 10px;border-bottom:1px solid #333;font-size:0.88em;color:#ddd}
  tr:hover td{background:#1e2a4a!important}
</style>
</head>
<body>
<h1>APK Security Report</h1>
<div class="meta">
  <strong>APK:</strong> """ + apk_name + """ &nbsp;|&nbsp;
  <strong>SHA-256:</strong> """ + apk_info["sha256"] + """ &nbsp;|&nbsp;
  <strong>Size:</strong> """ + str(apk_info["size_mb"]) + """ MB &nbsp;|&nbsp;
  <strong>Generated:</strong> """ + generated + """
</div>
<h2>Overall Risk Score</h2>
<div class="score">""" + str(risk) + """/100</div>
<h2>Finding Summary</h2>
<div class="cards">
  <div class="card"><div class="num" style="color:#e74c3c">""" + str(sev_counts["High"]) + """</div><div class="lbl">High</div></div>
  <div class="card"><div class="num" style="color:#e67e22">""" + str(sev_counts["Medium"]) + """</div><div class="lbl">Medium</div></div>
  <div class="card"><div class="num" style="color:#3498db">""" + str(sev_counts["Low"]) + """</div><div class="lbl">Low</div></div>
</div>
<h2>Detailed Findings</h2>
<table>
  <tr><th>Severity</th><th>Check</th><th>Status</th><th>Detail</th><th>CVSS</th><th>CVE/CWE</th></tr>
  """ + rows + """
</table>
<h2>Permissions</h2>
<table>
  <tr><th>Permission</th><th>Classification</th></tr>
  """ + perm_rows + """
</table>
</body></html>"""

    try:
        with open(output_file, "w", encoding="utf-8") as f:
            f.write(html)
        print(colored("[+] HTML report -> '" + output_file + "'", "green"))
    except IOError as e:
        print(colored("[-] HTML write failed: " + str(e), "red"))

# ── MAIN ──────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    print_banner()

    parser = argparse.ArgumentParser(
        description="APK Security Analyzer v" + VERSION + " -- Advanced Static Analysis",
        formatter_class=argparse.RawTextHelpFormatter,
    )
    parser.add_argument("apk",               help="Path to the APK file.")
    parser.add_argument("-o", "--output",    default="apk_analyzer_out",
                        help="Output directory for decompiled files.")
    parser.add_argument("--json",            metavar="FILE", help="Save findings to a JSON file.")
    parser.add_argument("--html",            metavar="FILE", help="Save findings to an HTML report.")
    parser.add_argument("-v", "--verbose",   action="store_true",
                        help="Show file paths for each finding.")
    parser.add_argument("--skip-decompile",  action="store_true",
                        help="Reuse existing decompiled directory.")
    args = parser.parse_args()

    check_tools()

    if not os.path.isfile(args.apk):
        print(colored("[-] APK not found: '" + args.apk + "'", "red"))
        sys.exit(1)

    apk_info = get_apk_info(args.apk)
    print(colored("[*] APK SHA-256: " + apk_info["sha256"] + "  (" + str(apk_info["size_mb"]) + " MB)", "white"))

    if not args.skip_decompile:
        decompile_apk(args.apk, args.output)
    else:
        if not os.path.isdir(args.output):
            print(colored("[-] Decompiled dir '" + args.output + "' not found.", "red"))
            sys.exit(1)
        print(colored("[*] Reusing existing decompiled dir: '" + args.output + "'", "yellow"))

    manifest_path = os.path.join(args.output, "AndroidManifest.xml")

    all_findings = []
    all_findings.extend(analyze_apk_features(args.output, verbose=args.verbose))
    all_findings.extend(run_advanced_checks(args.output, verbose=args.verbose))
    all_findings.extend(analyze_native_libs(args.output))
    manifest_findings, perms, _ = analyze_manifest(manifest_path)
    all_findings.extend(manifest_findings)

    apk_filename = os.path.basename(args.apk)
    print_results(all_findings, perms, apk_filename, apk_info, verbose=args.verbose)

    if args.json:
        generate_json_report(all_findings, perms, apk_filename, apk_info, args.json)
    if args.html:
        generate_html_report(all_findings, perms, apk_filename, apk_info, args.html)

    print(colored("[+] Analysis complete!", "green", attrs=["bold"]))
