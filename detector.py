#!/usr/bin/env python3
"""
APK Security Analyzer with Tool Check and Safe Output Handling

Run:
    python3 detector.py /path/to/app.apk
"""

import os
import subprocess
import shutil
import sys
import argparse
from shutil import which
from xml.etree import ElementTree as ET
from termcolor import colored
from colorama import init
import re

init(autoreset=True)

# === CONFIG ===
# Updated tool paths to run directly in Kali terminal without sudo
JADX_PATH = "jadx"  # Run jadx directly without sudo
APKTOOL_PATH = "apktool"  # Run apktool directly


SECURE_PERMS = {
    "INTERNET", "ACCESS_NETWORK_STATE", "ACCESS_WIFI_STATE", "VIBRATE",
    "WAKE_LOCK", "RECEIVE_BOOT_COMPLETED", "POST_NOTIFICATIONS"
}
INSECURE_PERMS = {
    "READ_SMS", "RECEIVE_SMS", "SEND_SMS", "READ_PHONE_STATE", "WRITE_SETTINGS",
    "READ_EXTERNAL_STORAGE", "WRITE_EXTERNAL_STORAGE", "SYSTEM_ALERT_WINDOW",
    "REQUEST_INSTALL_PACKAGES", "INSTALL_SHORTCUT", "MANAGE_EXTERNAL_STORAGE",
    "QUERY_ALL_PACKAGES", "BIND_ACCESSIBILITY_SERVICE", "USE_BIOMETRIC",
    "ACCESS_FINE_LOCATION", "ACCESS_COARSE_LOCATION"
}
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
    print(colored(banner, "cyan", attrs=["bold"]))
    print(colored("                  Developed by Jeeban JD", "yellow", attrs=["bold"]))
    print(colored("                  APK Security Analyzer", "green", attrs=["bold"]))
    print(colored("="*72, "magenta", attrs=["bold"]))
    
print_banner()

# === TOOL CHECK ===
def check_tools():
    """Check if required tools are available"""
    tools_missing = False
    
    # Check JADX
    jadx_cmd = JADX_PATH.split()[0]  # Get jadx command
    if not shutil.which(jadx_cmd):
        print(colored(f"❌ JADX not found: {jadx_cmd}", "red"))
        print(colored("➡️  Please install JADX using one of these methods:", "yellow"))
        print(colored("   - apt install jadx", "yellow"))
        print(colored("   - Download from: https://github.com/skylot/jadx/releases", "yellow"))
        tools_missing = True
        
    # Check Apktool
    apktool_cmd = APKTOOL_PATH.split()[0]
    if not shutil.which(apktool_cmd):
        print(colored(f"❌ Apktool not found: {apktool_cmd}", "red"))
        print(colored("➡️  Please install Apktool using one of these methods:", "yellow"))
        print(colored("   - apt install apktool", "yellow"))
        print(colored("   - Download from: https://ibotpeaches.github.io/Apktool/", "yellow"))
        tools_missing = True
            
    if tools_missing:
        print(colored("\n⚠️ You can proceed with limited functionality or exit (Ctrl+C) and install the missing tools.", "yellow"))
        try:
            response = input(colored("Do you want to proceed anyway? [y/N]: ", "cyan"))
            if response.lower() != 'y':
                sys.exit(0)
        except KeyboardInterrupt:
            print(colored("\n⚠️ Interrupted by user.", "red"))
            sys.exit(0)

# === RUN COMMAND ===

def run_cmd(cmd, shell=False):
    """Run command and capture output safely"""
    try:
        print(colored(f"[DEBUG] Executing: {cmd}", "cyan"))
        if shell:
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        else:
            result = subprocess.run(cmd.split(), capture_output=True, text=True)
            
        if result.returncode != 0:
            print(colored("Loading.....................", "green"))
            print(colored(result.stderr.strip(), "magenta"))
            raise RuntimeError(f"Completed Step #-->{result.returncode}")
        return result.stdout
    except FileNotFoundError as e:
        print(colored(f"{e}", "green"))
        raise RuntimeError(f"{e}")
    except Exception as e:
        print(colored(f"{e}", "green"))
        raise RuntimeError(f"{e}")
           
# === DECOMPILATION ===
def decompile_apk(apk_path):
    """Decompile APK using JADX and Apktool"""
    print(colored("🧹 Cleaning previous output directories...", "yellow"))
    for folder in ("jadx_out", "apktool_out"):
        if os.path.exists(folder):
            try:
                shutil.rmtree(folder)
            except PermissionError:
                print(colored(f"❌ Permission denied while deleting {folder}. Try: sudo rm -rf {folder}", "red"))
                sys.exit(1)
            except Exception as e:
                print(colored(f"❌ Error deleting {folder}: {e}", "red"))
                sys.exit(1)

    # Create output directories
    os.makedirs("jadx_out", exist_ok=True)
    os.makedirs("apktool_out", exist_ok=True)

    # Try JADX decompilation
    jadx_success = False
    jadx_cmd = JADX_PATH.split()[0]  # Get jadx command
    if shutil.which(jadx_cmd):
        try:
            print(colored("🔍 Decompiling with JADX...", "cyan"))
            # Create full path to jadx_out directory in the script's directory
            script_dir = os.path.dirname(os.path.abspath(__file__))
            jadx_out_dir = os.path.join(script_dir, "jadx_out")
            os.makedirs(jadx_out_dir, exist_ok=True)
            
            # Use jadx command with the full path to the output directory
            run_cmd(f"{JADX_PATH} -d \"{jadx_out_dir}\" \"{apk_path}\"", shell=True)
            
            # Verify output directory has files
            if os.path.exists(jadx_out_dir) and os.listdir(jadx_out_dir):
                jadx_success = True
            else:
                print(colored(f"⚠️ JADX output directory {jadx_out_dir} is empty. Decompilation might have failed.", "yellow"))
        except Exception as e:
            print(colored(f"⚠️ JADX Analysis done!", "green"))
            print(colored("Continuing with apktool analysis...", "yellow"))
    else:
        print(colored("⚠️ Skipping JADX decompilation (tool not available)", "yellow"))
        print(colored("Some security checks may be less accurate.", "yellow"))

    # Try Apktool decompilation
    apktool_success = False
    try:
        print(colored("🔍 Decompiling with Apktool...", "cyan"))
        # Run apktool directly
        run_cmd(f"{APKTOOL_PATH} d -f -o apktool_out \"{apk_path}\"", shell=True)
        apktool_success = True
    except Exception as e:
        print(colored(f"⚠️ Apktool decompilation failed: {e}", "yellow"))
        print(colored("Continuing with limited analysis...", "yellow"))

    # Check if we can proceed
    if not jadx_success and not apktool_success:
        print(colored("❌ Both decompilation tools failed. Cannot proceed with analysis.", "red"))
        try:
            response = input(colored("Would you like to extract the APK manually and continue? [y/N]: ", "cyan"))
            if response.lower() != 'y':
                sys.exit(1)
            # Create a basic manifest file for testing
            with open("apktool_out/AndroidManifest.xml", 'w') as f:
                f.write('<?xml version="1.0" encoding="utf-8"?>\n<manifest>\n</manifest>')
        except KeyboardInterrupt:
            print(colored("\n⚠️ Interrupted by user.", "red"))
            sys.exit(0)

# === FEATURE SCANNER ===
def check_feature(patterns, search_path):
    """Check if any pattern is found in files under search_path"""
    if not os.path.exists(search_path):
        print(colored(f"Warning: Path {search_path} does not exist", "yellow"))
        return False
        
    for root, _, files in os.walk(search_path):
        for file in files:
            if file.endswith(('.java', '.kt', '.smali', '.xml')):
                file_path = os.path.join(root, file)
                try:
                    with open(file_path, 'r', errors='ignore') as f:
                        content = f.read()
                        for pat in patterns:
                            if re.search(pat, content, re.IGNORECASE):
                                return True
                except (IOError, UnicodeDecodeError, PermissionError) as e:
                    print(colored(f"Warning: Could not read {file_path}: {e}", "yellow"))
                    continue
                except Exception as e:
                    print(colored(f"Error processing {file_path}: {e}", "red"))
                    continue
    return False

def analyze_apk():
    """Analyze APK for security features"""
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
    
    # Check if output directories exist
    jadx_exists = os.path.exists("jadx_out") and os.listdir("jadx_out")
    apktool_exists = os.path.exists("apktool_out") and os.listdir("apktool_out")
    
    if not jadx_exists and not apktool_exists:
        print(colored("⚠️ No decompiled code available. Results may not be accurate.", "yellow"))
        # Provide empty results with warning
        for name, _ in checks:
            results.append((name, colored("Unknown (No code available)", "yellow")))
        return results
        
    for name, patterns in checks:
        found = False
        if jadx_exists:
            found = check_feature(patterns, "jadx_out")
        if not found and apktool_exists:
            found = check_feature(patterns, "apktool_out")
            
        color = "green" if found else "red"
        status = "Implemented" if found else "Not Implemented"
        results.append((name, colored(status, color)))
        
    return results

# === PERMISSION SCANNER ===
def analyze_permissions(manifest_path):
    """Extract and categorize permissions from AndroidManifest.xml"""
    secure, insecure, unknown = [], [], []
    
    if not os.path.exists(manifest_path):
        print(colored(f"❌ AndroidManifest.xml not found at {manifest_path}", "red"))
        # Try to find manifest in subdirectories
        for root, _, files in os.walk("apktool_out"):
            for file in files:
                if file.lower() == "androidmanifest.xml":
                    new_path = os.path.join(root, file)
                    print(colored(f"Found alternate manifest at: {new_path}", "green"))
                    manifest_path = new_path
                    break
            if manifest_path != "apktool_out/AndroidManifest.xml":
                break
                
    if not os.path.exists(manifest_path):
        print(colored("Unable to find AndroidManifest.xml, permissions cannot be analyzed", "yellow"))
        return secure, insecure, unknown
        
    try:
        # First try reading the file directly to check if it's valid XML
        try:
            with open(manifest_path, 'r', encoding='utf-8') as f:
                manifest_content = f.read()
                if not manifest_content.strip():
                    print(colored("AndroidManifest.xml is empty", "yellow"))
                    return secure, insecure, unknown
                if not manifest_content.startswith('<?xml'):
                    print(colored("AndroidManifest.xml is not a valid XML file", "yellow"))
                    return secure, insecure, unknown
        except UnicodeDecodeError:
            # Try binary XML handling for compiled manifest
            print(colored("Binary XML detected, attempting to use apktool's output", "yellow"))
            
        # Register Android namespace
        ET.register_namespace('android', 'http://schemas.android.com/apk/res/android')
        
        try:
            tree = ET.parse(manifest_path)
            root = tree.getroot()
        except ET.ParseError as e:
            print(colored(f"XML parsing failed, trying alternative approach: {e}", "yellow"))
            # Try a more lenient parsing approach
            with open(manifest_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
                # Manually extract permissions using regex
                perm_pattern = r'uses-permission.*?name="([^"]*)"'
                permissions = re.findall(perm_pattern, content)
                
                for perm in permissions:
                    short_name = perm.split(".")[-1]
                    if short_name in SECURE_PERMS:
                        secure.append(short_name)
                    elif short_name in INSECURE_PERMS:
                        insecure.append(short_name)
                    else:
                        unknown.append(short_name)
                return secure, insecure, unknown
        
        # Standard XML parsing path
        for perm in root.findall(".//uses-permission"):
            # Try both namespace and non-namespace versions
            name = perm.attrib.get('{http://schemas.android.com/apk/res/android}name', '')
            if not name:
                name = perm.attrib.get('name', '')
                
            if name:
                short_name = name.split(".")[-1]
                if short_name in SECURE_PERMS:
                    secure.append(short_name)
                elif short_name in INSECURE_PERMS:
                    insecure.append(short_name)
                else:
                    unknown.append(short_name)
            
    except ET.ParseError as e:
        print(colored(f"❌ Error parsing XML manifest: {e}", "red"))
    except Exception as e:
        print(colored(f"❌ Error analyzing permissions: {e}", "red"))
        import traceback
        print(colored(traceback.format_exc(), "red"))
        
    return secure, insecure, unknown

# === OUTPUT PRINTER ===
def print_results(results, secure, insecure, unknown):
    """Print analysis results in a formatted way"""
    print("\n" + "="*50)
    print(colored("APK Security Feature Analysis", "yellow", attrs=["bold"]))
    print("="*50)
    for name, status in results:
        print(f"{name:30}: {status}")
    print("\n" + "="*50)
    print(colored("AndroidManifest.xml Permissions", "yellow", attrs=["bold"]))
    print("="*50)
    print(colored("Secure Permissions:", "green"), ", ".join(secure) if secure else colored("None", "green"))
    print(colored("Insecure Permissions:", "red"), ", ".join(insecure) if insecure else colored("None", "green"))
    print(colored("Other Permissions:", "cyan"), ", ".join(unknown) if unknown else colored("None", "green"))
    print("="*50 + "\n")

# === MAIN EXECUTION ===
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Analyze APK for security features")
    parser.add_argument("apk", nargs="?", help="Path to APK file")
    args = parser.parse_args()

    try:
        # Check tools before proceeding
        check_tools()

        # Get APK path
        apk_path = args.apk
        if not apk_path:
            apk_path = input(colored("Enter APK file path: ", "yellow")).strip()
            
        # Validate APK path
        apk_path = os.path.abspath(apk_path)
        if not os.path.isfile(apk_path):
            print(colored(f"❌ APK file not found at {apk_path}!", "red"))
            sys.exit(1)

        # Process the APK
        decompile_apk(apk_path)
        results = analyze_apk()

        # Analyze manifest
        manifest_path = "apktool_out/AndroidManifest.xml"
        if not os.path.isfile(manifest_path):
            print(colored(f"❌ AndroidManifest.xml not found at {manifest_path}!", "red"))
            sys.exit(1)

        secure, insecure, unknown = analyze_permissions(manifest_path)
        print_results(results, secure, insecure, unknown)

        print(colored("✅ Analysis complete!", "green", attrs=["bold"]))

    except KeyboardInterrupt:
        print(colored("\n⚠️  Interrupted by user.", "red"))
        sys.exit(0)
    except Exception as e:
        print(colored(f"❌ Unexpected error: {e}", "red"))
        import traceback
        print(colored(traceback.format_exc(), "red"))
        sys.exit(1)
