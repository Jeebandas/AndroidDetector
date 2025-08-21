<img width="937" height="427" alt="sleekshot" src="https://github.com/user-attachments/assets/15bcb1ed-bb35-4d00-ab80-3429fb575cbe" />

# 📱 APK Security Analyzer (Advanced)

This tool performs **static security analysis** of Android APK files.  
It decompiles the APK, analyzes Smali code, inspects the `AndroidManifest.xml`,  
and scans native libraries for insecure patterns.

## 🚀 Features
- Decompile APKs using **Apktool**
- Analyze **AndroidManifest.xml** for misconfigurations
- Detect **hardcoded secrets**, **weak cryptography**, and **insecure WebView usage**
- Identify **exported components** and **debuggable apps**
- Scan native libraries (`.so`) for **unsafe C functions**
- Generate results in **console** and **JSON report**

---

## 📦 Requirements

- **Python 3.8+**
- **External tools (must be installed & available in PATH):**
  - [Apktool](https://ibotpeaches.github.io/Apktool/) sudo apt install apktool
  - `strings` utility (commonly available on Linux/macOS, or via [binutils](https://www.gnu.org/software/binutils/))

### Install Python Dependencies
```bash
pip install -r requirements.txt
```

---

## 🛠️ Installation Guide

1. **Clone the repository (or download the script):**
   ```bash
   git clone https://github.com/Jeebandas/AndroidDetector.git
   cd AndroidDetector
   ./ detector.py myapp.apk
   ```

2. **Install Python dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

3. **Install Apktool:**
   - Download from [Apktool Official Site](https://ibotpeaches.github.io/Apktool/)
   - Place the `apktool` binary/jar in your PATH (e.g., `/usr/local/bin/` on Linux or add to Environment Variables on Windows).

4. **Ensure `strings` utility is available:**
   - On Linux: Usually comes with `binutils` → install via:
     ```bash
     sudo apt install binutils
     ```
   - On macOS: Included by default (or install via Xcode command line tools).
   - On Windows: Install via [GnuWin32 strings](http://gnuwin32.sourceforge.net/packages/strings.htm) or use Linux subsystem.

5. **Run the tool:**
   ```bash
   python3 detector.py myapp.apk --json report.json
   ./detector.py myapp.apk
   ```

---

## 🔧 Usage

```bash
python3 detector.py <apk_file> [options]
```

### Options
| Flag | Description |
|------|-------------|
| `-o <dir>` | Output directory for decompiled files (default: `apk_analyzer_out`) |
| `--json <file>` | Save results to a JSON file |

### Example
```bash
python3 detector.py myapp.apk --json report.json
```

---

## 📊 Sample Output
```
📊 Security Analysis Report for: myapp.apk
[High] Hardcoded Secrets       : Detected (High confidence) | Found API key
[Medium] Exported Components   : Detected | 2 components are exported
[Low] Backup Allowed           : Enabled | android:allowBackup is true
...
```

---

## ⚠️ Disclaimer
This tool is intended **for educational and security auditing purposes only**.  
Do not use it on applications without proper authorization.


