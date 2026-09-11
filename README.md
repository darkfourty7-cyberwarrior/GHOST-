- ⚠️ Basic security risk analysis
- 📄 JSON report generation
- 🌍 HTML report generation
- 📊 Full security scan
- 💻 Termux / Linux compatible
- 🎨 Terminal-based security console
- ⚡ Lightweight Python implementation

---

📱 Installation — Termux

1. Update Termux

pkg update -y

2. Install Git

pkg install git -y

3. Install Python

pkg install python -y

4. Clone GHOST

git clone https://github.com/darkfourty7-cyberwarrior/GHOST-.git

5. Enter the project

cd GHOST-

6. Check Python

python --version

7. Run GHOST

python ghost.py

---

🖥️ Usage

After launching the console, GHOST displays the main menu.

Typical options include:

1. Full Security Scan
2. Port Scan
3. Web Security Audit
4. TLS / SSL Audit
5. DNS Information
6. Local Network Information
7. Generate Report
8. Exit

Select an option and follow the prompts shown by the console.

---

📊 Security Reports

GHOST can generate reports for completed assessments.

JSON Report

ghost_security_report.json

HTML Report

ghost_security_report.html

The reports can be opened later for reviewing scan results.

---

🔍 What GHOST Checks

🌐 Network

GHOST can resolve a target and check selected common TCP ports.

🔐 Web Security

The web audit checks for commonly recommended HTTP security headers and can identify whether a website is being accessed over plain HTTP.

🛡️ TLS / SSL

The TLS audit provides information about the HTTPS/TLS connection and certificate.

📡 DNS

DNS information can be collected for the selected target.

⚠️ Risk Analysis

GHOST provides basic defensive risk observations based on the information collected during an assessment.

---

📦 Requirements

- Python 3
- Internet/network access when performing remote assessments
- Termux, Linux, or another Python-compatible environment

The project uses Python standard-library modules, so no large dependency installation is required.

---

🛠️ Project Structure

GHOST-/
├── README.md
├── Screenshot_20260911_110423_Termux.jpg
└── <Python source file>

The exact Python source filename depends on the file included in the repository.

---

⚡ Quick Start

If Git and Python are already installed:

git clone https://github.com/darkfourty7-cyberwarrior/GHOST-.git

cd GHOST-

python GHOST.py

---

🛡️ Responsible Use

GHOST is intended for:

- Authorized penetration testing
- Defensive security assessment
- Security learning
- Lab environments
- Testing systems you own
- Testing systems where you have explicit permission

Do not scan or assess systems, websites, networks, or devices without authorization.

---

⚠️ Disclaimer

GHOST Security Console is provided for educational and authorized defensive security purposes only.

The author is not responsible for misuse, unauthorized scanning, damage, data loss, service disruption, or any illegal activity performed using this software.

Always obtain appropriate authorization before conducting security assessments.

---

👤 Author

DARK 47

GHOST SECURITY CONSOLE

Made by DARK 47 🛡️

---

⭐ Support the Project

If you find GHOST useful:

- ⭐ Star the repository
- 🐛 Report bugs
- 💡 Suggest improvements
- 🔧 Contribute improvements
- 📢 Share the project responsibly

---

🔗 Repository

GHOST Security Console

"https://github.com/darkfourty7-cyberwarrior/GHOST-.git"

---

👻 GHOST SECURITY CONSOLE

"DEFENSIVE • AUTHORIZED • SECURITY ASSESSMENT"

Made by DARK 47
