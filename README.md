AP Web Automation Tool
A Python-based SAP WebGUI automation utility with a Tkinter GUI for secure login, TCode management, and automated workflows.
This tool is designed to streamline SAP interactions, perform system checks, and send email alerts — all while keeping credentials encrypted.

✨ Features
🔐 Secure Credential Storage

Stores SAP and email credentials encrypted using Fernet with PBKDF2 key derivation.

Separate encryption for SAP and email logins.

🖥️ TCode Management

Add, edit, delete, import, and export TCodes.

Search & filter through a scrollable Tkinter interface.

🤖 SAP Web Automation (Selenium)

Headless or visible browser mode.

Automatic SAP login and TCode navigation.

Screenshot capture of SAP screens.

📊 System Health Checks

Monitors /backup filesystem usage.

Sends email alerts if usage falls below 60%.

📧 Email Automation

Sends screenshots or alerts via Gmail SMTP.

Supports encrypted storage for email credentials.

🖱️ User-Friendly Interface

Scrollable, resizable Tkinter GUI.

Color-coded TCode list.

Inline status updates.

🛠️ Technologies Used
Python 3

Tkinter – GUI framework

Selenium – Browser automation

cryptography (Fernet) – Secure credential storage

smtplib – Email sending

Pandas – CSV import/export for TCodes

📌 Usage Scenarios
Automating repetitive SAP tasks

Quickly navigating and executing TCODES

Monitoring backup storage usage

Sending automated status reports/screenshots
