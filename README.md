 <img width="764" height="414" alt="screenshot" src="https://github.com/user-attachments/assets/656f3546-8a8b-4d3c-87c1-0d5de232d995" />


=========================================
         AndroidDetector - Setup Guide
           by Jeeban JD
=========================================

PREREQUISITES
-----------------------------------------
- Python 3.x installed on your system
- pip3 installed
- Apktool installed:
  sudo apt update
  sudo apt install apktool -y

- JADX installed: 
  sudo apt update
  sudo apt install jadx -y


- (Optional) Virtual environment for isolated dependencies


SETUP INSTRUCTIONS
-----------------------------------------
1. Extract the project ZIP file.
2. Open a terminal inside the extracted folder.
3. Install dependencies by running:
   pip3 install -r requirements.txt
4. Run the detector using:
   python3 detector.py


USAGE
-----------------------------------------
1. Place your APK file inside the project folder.
2. When prompted, type ONLY the APK filename 
   (Example: xyz.apk).
3. Press ENTER and wait for the analysis to complete.


VIRTUAL ENVIRONMENT (OPTIONAL BUT RECOMMENDED)
-----------------------------------------
If you want to run the tool inside a virtual environment:

Step 1: Install venv (if not already installed):
   sudo apt update
   sudo apt install python3-venv -y

Step 2: Create and activate the virtual environment:
   python3 -m venv myenv
   source myenv/bin/activate

Step 3: Install dependencies inside the environment:
   pip3 install -r requirements.txt

Step 4: Run the detector:
   python3 detector.py

To deactivate the virtual environment:
   deactivate


NOTES
-----------------------------------------
- Always activate the virtual environment before running the tool if using one.
- Make sure your APK file is placed in the project folder.
- Only enter the APK filename when prompted (without path).

=========================================
            End of Instructions
=========================================
