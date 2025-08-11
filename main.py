import tkinter as tk
from tkinter import messagebox, simpledialog, scrolledtext, ttk, filedialog
import threading
import os
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.fernet import Fernet, InvalidToken
import base64
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.base import MIMEBase
from email import encoders
import platform
import subprocess
import csv
import json
from email.header import Header
import chromedriver_autoinstaller

try:
    from selenium import webdriver
    from selenium.webdriver.common.by import By
    from selenium.webdriver.support.ui import WebDriverWait
    from selenium.webdriver.support import expected_conditions as EC
    from selenium.webdriver.common.keys import Keys
    from selenium.webdriver.chrome.options import Options
    SELENIUM_AVAILABLE = True
except ImportError:
    SELENIUM_AVAILABLE = False

CRED_FILE = 'sap_creds.enc'
EMAIL_CRED_FILE = 'email_creds.enc'
TCODE_FILE = 'tcodes.json'
SALT = b'sapgui_salt_2024'  # Should be random in production
EMAIL_SALT = b'email_salt_2024'

SCREENSHOT_DIR = 'screenshots'

# Example TCode list
TCODE_LIST = [
    {"code": "ST06", "name": "Operating System Monitor"},
    {"code": "SE11", "name": "Data Dictionary"},
    {"code": "ME21N", "name": "Create Purchase Order"},
    {"code": "FB03", "name": "Display Document"},
    {"code": "SU01", "name": "User Maintenance"},
    {"code": "SM37", "name": "Job Monitoring"},
    {"code": "MM03", "name": "Display Material"},
    {"code": "VA01", "name": "Create Sales Order"},
    {"code": "FBL1N", "name": "Vendor Line Item Display"},
    {"code": "SE80", "name": "Object Navigator"},
    # ... add more as needed
]

def derive_key(master_password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100_000,
        backend=default_backend()
    )
    return base64.urlsafe_b64encode(kdf.derive(master_password.encode()))

def save_credentials(url, username, password, parent):
    master_password = simpledialog.askstring('Master Password', 'Enter a master password to encrypt credentials:', show='*', parent=parent)
    if not master_password:
        return
    key = derive_key(master_password, SALT)
    f = Fernet(key)
    data = f"{url}\n{username}\n{password}"
    token = f.encrypt(data.encode())
    with open(CRED_FILE, 'wb') as file:
        file.write(token)
    messagebox.showinfo('Saved', 'Credentials saved securely!', parent=parent)

def load_credentials(url_entry, username_entry, password_entry, parent):
    if not os.path.exists(CRED_FILE):
        messagebox.showerror('Error', 'No saved credentials found.', parent=parent)
        return
    master_password = simpledialog.askstring('Master Password', 'Enter the master password to decrypt credentials:', show='*', parent=parent)
    if not master_password:
        return
    key = derive_key(master_password, SALT)
    f = Fernet(key)
    try:
        with open(CRED_FILE, 'rb') as file:
            token = file.read()
        data = f.decrypt(token).decode()
        url, username, password = data.split('\n', 2)
        url_entry.delete(0, tk.END)
        url_entry.insert(0, url)
        username_entry.delete(0, tk.END)
        username_entry.insert(0, username)
        password_entry.delete(0, tk.END)
        password_entry.insert(0, password)
        messagebox.showinfo('Loaded', 'Credentials loaded!', parent=parent)
    except (InvalidToken, ValueError):
        messagebox.showerror('Error', 'Invalid master password or corrupted file.', parent=parent)

def save_email_credentials(sender, app_password, recipient, parent):
    master_password = simpledialog.askstring('Master Password', 'Enter a master password to encrypt email credentials:', show='*', parent=parent)
    if not master_password:
        return
    key = derive_key(master_password, EMAIL_SALT)
    f = Fernet(key)
    data = f"{sender}\n{app_password}\n{recipient}"
    token = f.encrypt(data.encode())
    with open(EMAIL_CRED_FILE, 'wb') as file:
        file.write(token)
    messagebox.showinfo('Saved', 'Email credentials saved securely!', parent=parent)

def load_email_credentials(sender_entry, app_password_entry, recipient_entry, parent):
    if not os.path.exists(EMAIL_CRED_FILE):
        messagebox.showerror('Error', 'No saved email credentials found.', parent=parent)
        return
    master_password = simpledialog.askstring('Master Password', 'Enter the master password to decrypt email credentials:', show='*', parent=parent)
    if not master_password:
        return
    key = derive_key(master_password, EMAIL_SALT)
    f = Fernet(key)
    try:
        with open(EMAIL_CRED_FILE, 'rb') as file:
            token = file.read()
        data = f.decrypt(token).decode()
        sender, app_password, recipient = data.split('\n', 2)
        sender_entry.delete(0, tk.END)
        sender_entry.insert(0, sender)
        app_password_entry.delete(0, tk.END)
        app_password_entry.insert(0, app_password)
        recipient_entry.delete(0, tk.END)
        recipient_entry.insert(0, recipient)
        messagebox.showinfo('Loaded', 'Email credentials loaded!', parent=parent)
    except (InvalidToken, ValueError):
        messagebox.showerror('Error', 'Invalid master password or corrupted file.', parent=parent)

def send_email_with_screenshot(sender, app_password, recipient, subject, message, status_label):
    try:
        msg = MIMEMultipart()
        msg['From'] = sender
        msg['To'] = recipient
        msg['Subject'] = subject
        
        # Debug: Print the email headers to verify subject is set
        print(f"DEBUG: Email headers in automation - From: {msg['From']}, To: {msg['To']}, Subject: {msg['Subject']}")
        
        msg.attach(MIMEText(message, 'plain'))
        # Attach screenshot
        with open(SCREENSHOT_FILE, 'rb') as f:
            part = MIMEBase('application', 'octet-stream')
            part.set_payload(f.read())
            encoders.encode_base64(part)
            part.add_header('Content-Disposition', f'attachment; filename={SCREENSHOT_FILE}')
            msg.attach(part)
        server = smtplib.SMTP('smtp.gmail.com', 587)
        server.starttls()
        server.login(sender, app_password)
        server.send_message(msg)
        server.quit()
        status_label.config(text='Email sent successfully!', fg='green')
    except Exception as e:
        status_label.config(text=f'Failed to send email: {e}', fg='red')

def login_to_sap(url, username, password, tcode, status_label, wait_for_filesystem_table=False, headless=False, keep_browser_open=False):
    if not SELENIUM_AVAILABLE:
        status_label.config(text='Selenium not installed. Please run: pip install selenium', fg='red')
        return None
    driver = None
    try:
        chromedriver_autoinstaller.install()
        chrome_options = Options()
        chrome_options.add_argument('--ignore-certificate-errors')
        chrome_options.add_argument('--ignore-ssl-errors')
        # headless mode removed for debugging
        # if headless:
        #     chrome_options.add_argument('--headless')
        #     chrome_options.add_argument('--window-size=1920,1080')
        print('Launching ChromeDriver...')
        driver = webdriver.Chrome(options=chrome_options)
        print('Navigating to URL:', url)
        driver.get(url)
        status_label.config(text='Opened SAP login page...', fg='blue')
        WebDriverWait(driver, 20).until(
            EC.presence_of_element_located((By.NAME, 'sap-user'))
        )
        print('Found username field')
        driver.find_element(By.NAME, 'sap-user').send_keys(username)
        driver.find_element(By.NAME, 'sap-password').send_keys(password)
        driver.find_element(By.NAME, 'sap-password').send_keys(Keys.RETURN)
        status_label.config(text='Login attempted. Waiting for SAP Easy Access...', fg='blue')
        # Debug: Print page source after login
        print('--- PAGE SOURCE AFTER LOGIN ---')
        print(driver.page_source[:2000])  # Print first 2000 chars for brevity
        print('--- END PAGE SOURCE ---')
        try:
            menu_input = WebDriverWait(driver, 30).until(
                EC.presence_of_element_located((By.XPATH, "//input[@aria-label='Menu' or @title='Menu' or @type='text']"))
            )
            print('Found menu input')
        except Exception as e:
            print('Menu input not found in main page, trying iframes...')
            iframes = driver.find_elements(By.TAG_NAME, 'iframe')
            print(f'Found {len(iframes)} iframes')
            if iframes:
                driver.switch_to.frame(iframes[0])
                try:
                    menu_input = WebDriverWait(driver, 30).until(
                        EC.presence_of_element_located((By.XPATH, "//input[@aria-label='Menu' or @title='Menu' or @type='text']"))
                    )
                    print('Found menu input in iframe')
                except Exception as e2:
                    print('Menu input not found in iframe:', e2)
                    status_label.config(text='Menu input not found.', fg='red')
                    if not keep_browser_open:
                        driver.quit()
                    return None
            else:
                status_label.config(text='Menu input not found.', fg='red')
                if not keep_browser_open:
                    driver.quit()
                return None
        menu_input.clear()
        menu_input.send_keys(tcode)
        menu_input.send_keys(Keys.RETURN)
        status_label.config(text=f'TCode {tcode} entered and executed. Waiting for Filesystem node...', fg='blue')
        filesystem_node = WebDriverWait(driver, 30).until(
            EC.element_to_be_clickable((By.XPATH, "//span[contains(text(), 'Filesystem')]"))
        )
        print('Found Filesystem node')
        driver.execute_script("arguments[0].scrollIntoView();", filesystem_node)
        filesystem_node.click()
        status_label.config(text=f"Clicked 'Filesystem' node. Waiting for Filesystem table...", fg='blue')
        if wait_for_filesystem_table:
            try:
                WebDriverWait(driver, 30).until(
                    EC.presence_of_element_located((By.XPATH, "//th[contains(., 'File System Name')]")
                ))
                status_label.config(text=f"Filesystem table detected. Taking screenshot...", fg='blue')
                screenshot_file = os.path.join(SCREENSHOT_DIR, f'screenshot_{tcode}.png')
                driver.save_screenshot(screenshot_file)
                status_label.config(text=f"Screenshot saved as {screenshot_file}.", fg='green')
                check_backup_and_alert(driver)
            except Exception as e:
                print('Error waiting for Filesystem table:', e)
                status_label.config(text=f"Could not detect Filesystem table: {e}", fg='orange')
        if not keep_browser_open:
            driver.quit()
        return driver
    except Exception as e:
        print('Navigation error:', e)
        status_label.config(text=f'Login OK, but could not complete navigation: {e}', fg='orange')
        if driver and not keep_browser_open:
            driver.quit()
        return None

def automate_multiple_tcodes(url, username, password, tcodes, sender, app_password, recipient, subject, message, status_label, headless, keep_browser_open):
    status_label.config(text='Starting full automation for multiple TCodes...', fg='blue')
    screenshots = []
    if not SELENIUM_AVAILABLE:
        status_label.config(text='Selenium not installed. Please run: pip install selenium', fg='red')
        return
    if not os.path.exists(SCREENSHOT_DIR):
        os.makedirs(SCREENSHOT_DIR)
    driver = None
    try:
        chromedriver_autoinstaller.install()
        chrome_options = Options()
        chrome_options.add_argument('--ignore-certificate-errors')
        chrome_options.add_argument('--ignore-ssl-errors')
        # headless mode removed for debugging
        # if headless:
        #     chrome_options.add_argument('--headless')
        #     chrome_options.add_argument('--window-size=1920,1080')
        print('Launching ChromeDriver for automation...')
        driver = webdriver.Chrome(options=chrome_options)
        driver.get(url)
        status_label.config(text='Opened SAP login page...', fg='blue')
        WebDriverWait(driver, 20).until(
            EC.presence_of_element_located((By.NAME, 'sap-user'))
        )
        driver.find_element(By.NAME, 'sap-user').send_keys(username)
        driver.find_element(By.NAME, 'sap-password').send_keys(password)
        driver.find_element(By.NAME, 'sap-password').send_keys(Keys.RETURN)
        status_label.config(text='Login attempted. Waiting for SAP Easy Access...', fg='blue')
        menu_input = WebDriverWait(driver, 30).until(
            EC.presence_of_element_located((By.XPATH, "//input[@aria-label='Menu' or @title='Menu' or @type='text']"))
        )
        for tcode in tcodes:
            tcode = tcode.strip()
            if not tcode:
                continue
            status_label.config(text=f'Processing TCode: {tcode}', fg='blue')
            menu_input.clear()
            menu_input.send_keys(tcode)
            menu_input.send_keys(Keys.RETURN)
            try:
                filesystem_node = WebDriverWait(driver, 30).until(
                    EC.element_to_be_clickable((By.XPATH, "//span[contains(text(), 'Filesystem')]"))
                )
                driver.execute_script("arguments[0].scrollIntoView();", filesystem_node)
                filesystem_node.click()
                WebDriverWait(driver, 30).until(
                    EC.presence_of_element_located((By.XPATH, "//th[contains(., 'File System Name')]")
                ))
                screenshot_file = os.path.join(SCREENSHOT_DIR, f'screenshot_{tcode}.png')
                driver.save_screenshot(screenshot_file)
                screenshots.append(screenshot_file)
                status_label.config(text=f'Screenshot for {tcode} saved.', fg='green')
            except Exception as e:
                print(f'Error processing TCode {tcode}:', e)
                status_label.config(text=f'Could not process TCode {tcode}: {e}', fg='orange')
        if not keep_browser_open:
            driver.quit()
    except Exception as e:
        print('Automation failed:', e)
        status_label.config(text=f'Automation failed: {e}', fg='red')
        if driver and not keep_browser_open:
            try:
                driver.quit()
            except Exception:
                pass
        return
    # Send email with all screenshots
    if screenshots:
        try:
            # Debug: Print the subject to see what's being passed
            print(f"DEBUG: Subject in automate_multiple_tcodes: '{subject}'")
            print(f"DEBUG: Subject length: {len(subject)}")
            
            msg = MIMEMultipart()
            msg['From'] = sender
            msg['To'] = recipient
            msg['Subject'] = subject
            
            # Debug: Print the email headers to verify subject is set
            print(f"DEBUG: Email headers in automation - From: {msg['From']}, To: {msg['To']}, Subject: {msg['Subject']}")
            
            msg.attach(MIMEText(message, 'plain'))
            for screenshot_file in screenshots:
                with open(screenshot_file, 'rb') as f:
                    part = MIMEBase('application', 'octet-stream')
                    part.set_payload(f.read())
                    encoders.encode_base64(part)
                    part.add_header('Content-Disposition', f'attachment; filename={os.path.basename(screenshot_file)}')
                    msg.attach(part)
            server = smtplib.SMTP('smtp.gmail.com', 587)
            server.starttls()
            server.login(sender, app_password)
            server.send_message(msg)
            server.quit()
            status_label.config(text='Email sent successfully with all screenshots!', fg='green')
        except Exception as e:
            status_label.config(text=f'Failed to send email: {e}', fg='red')
    else:
        status_label.config(text='No screenshots to send.', fg='red')

def open_screenshot_folder():
    folder = os.path.abspath('screenshots')
    if not os.path.exists(folder):
        os.makedirs(folder)
    if platform.system() == "Windows":
        os.startfile(folder)
    elif platform.system() == "Darwin":
        subprocess.Popen(["open", folder])
    else:
        subprocess.Popen(["xdg-open", folder])

def send_alert_email(subject, message, recipient="ranjitshine2003@gmail.com"):
    import smtplib
    from email.mime.text import MIMEText
    from email.header import Header
    sender = "ranjitshine2003@gmail.com"
    password = "pssr agfj gsuv skan"
    msg = MIMEText(message)
    msg["Subject"] = subject
    msg["From"] = sender
    msg["To"] = recipient
    with smtplib.SMTP("smtp.gmail.com", 587) as server:
        server.starttls()
        server.login(sender, password)
        server.sendmail(sender, recipient, msg.as_string())

def check_backup_and_alert(driver):
    # Extract table
    table = driver.find_element(By.XPATH, "//table")
    headers = [th.text for th in table.find_elements(By.XPATH, ".//th")]
    if not headers:
        headers = [td.text for td in table.find_elements(By.XPATH, ".//tr[1]/td")]
    rows = []
    for tr in table.find_elements(By.XPATH, ".//tr")[1:]:
        cells = [td.text for td in tr.find_elements(By.XPATH, ".//td")]
        if cells:
            rows.append(cells)
    # Find the /backup row and check Free (%)
    try:
        idx_fs = headers.index("File System Name")
        idx_free_pct = headers.index("Free (%)")
    except ValueError:
        print("Could not find required columns in table headers.")
        return
    for row in rows:
        if row[idx_fs].strip() == "/backup":
            try:
                free_pct = int(row[idx_free_pct].replace(",", "").strip())
                print(f"/backup Free (%) value: {free_pct}%")
            except Exception:
                print("Could not parse Free (%) value for /backup.")
                return
            if free_pct < 60:
                alert_msg = f"⚠️ ALERT: /backup Free (%) is {free_pct}% (less than 60%) ⚠️"
                print(alert_msg)
                try:
                    from tkinter import messagebox
                    messagebox.showwarning("Backup Space Alert", alert_msg)
                except Exception:
                    pass
                send_alert_email("Backup Space Alert", alert_msg)
            else:
                print(f"/backup Free (%) is {free_pct}% (OK)")
            break
    else:
        print("/backup not found in table.")

def main():
    root = tk.Tk()
    root.title('SAP Web Login Automation')
    root.geometry('900x500')

    # --- Make the whole window scrollable ---
    main_canvas = tk.Canvas(root, borderwidth=0, highlightthickness=0)
    main_scrollbar = tk.Scrollbar(root, orient='vertical', command=main_canvas.yview)
    scrollable_frame = tk.Frame(main_canvas)
    scrollable_frame.bind(
        '<Configure>',
        lambda e: main_canvas.configure(scrollregion=main_canvas.bbox('all'))
    )
    main_canvas.create_window((0, 0), window=scrollable_frame, anchor='nw')
    main_canvas.configure(yscrollcommand=main_scrollbar.set)
    main_canvas.pack(side='left', fill='both', expand=True)
    main_scrollbar.pack(side='right', fill='y')

    # Now use scrollable_frame instead of root for all your main layout (main_frame, etc.)
    main_frame = tk.Frame(scrollable_frame)
    main_frame.pack(fill='both', expand=True)

    # SAP Login Section (Left)
    sap_frame = tk.LabelFrame(main_frame, text='SAP Login', padx=10, pady=10)
    sap_frame.pack(side='left', fill='both', expand=True, padx=(0, 10))

    tk.Label(sap_frame, text='SAP Web URL:').pack(anchor='w')
    url_entry = tk.Entry(sap_frame, width=40)
    url_entry.pack()
    url_entry.insert(0, 'https://15.184.240.158/sap/bc/gui/sap/its/webgui?sap-client=050&sap-language=EN#Shell-home')

    tk.Label(sap_frame, text='Username:').pack(anchor='w', pady=(10,0))
    username_entry = tk.Entry(sap_frame, width=30)
    username_entry.pack()

    tk.Label(sap_frame, text='Password:').pack(anchor='w', pady=(10,0))
    password_entry = tk.Entry(sap_frame, width=30, show='*')
    password_entry.pack()

    # --- TCode Management UI ---
    tcode_mgmt_frame = tk.LabelFrame(sap_frame, text='TCode Management', padx=5, pady=5)
    tcode_mgmt_frame.pack(fill='both', expand=True, pady=(10, 0))

    # Search/filter with improved styling
    search_frame = tk.Frame(tcode_mgmt_frame)
    search_frame.pack(fill='x', pady=(0, 5))
    
    tk.Label(search_frame, text='🔍 Search TCodes:', font=('Arial', 9, 'bold')).pack(side='left')
    
    search_var = tk.StringVar()
    search_entry = tk.Entry(search_frame, textvariable=search_var, width=25, font=('Arial', 9))
    search_entry.pack(side='left', padx=(5, 5))
    search_entry.insert(0, 'Type to search...')
    search_entry.config(fg='gray')
    
    def on_search_focus_in(event):
        if search_entry.get() == 'Type to search...':
            search_entry.delete(0, tk.END)
            search_entry.config(fg='black')
    
    def on_search_focus_out(event):
        if not search_entry.get():
            search_entry.insert(0, 'Type to search...')
            search_entry.config(fg='gray')
    
    def clear_search():
        search_var.set('')
        search_entry.delete(0, tk.END)
        search_entry.insert(0, 'Type to search...')
        search_entry.config(fg='gray')
        load_tcodes()
    
    clear_btn = tk.Button(search_frame, text='✕', width=3, command=clear_search, bg='lightgray')
    clear_btn.pack(side='left')
    
    search_entry.bind('<FocusIn>', on_search_focus_in)
    search_entry.bind('<FocusOut>', on_search_focus_out)

    # Treeview for TCodes
    tcode_tree = ttk.Treeview(tcode_mgmt_frame, columns=('code', 'name'), show='headings', selectmode='browse', height=8)
    tcode_tree.heading('code', text='TCode')
    tcode_tree.heading('name', text='Description')
    tcode_tree.column('code', width=80)
    tcode_tree.column('name', width=180)
    tcode_tree.pack(fill='both', expand=True)

    # Add/Edit fields
    entry_frame = tk.Frame(tcode_mgmt_frame)
    entry_frame.pack(fill='x', pady=(5, 0))
    tk.Label(entry_frame, text='TCode:').pack(side='left')
    tcode_code_entry = tk.Entry(entry_frame, width=10)
    tcode_code_entry.pack(side='left', padx=(5, 0))
    tk.Label(entry_frame, text='Name:').pack(side='left', padx=(10, 0))
    tcode_name_entry = tk.Entry(entry_frame, width=20)
    tcode_name_entry.pack(side='left', padx=(5, 0))

    # --- TCode Management Buttons ---
    btn_frame = tk.Frame(tcode_mgmt_frame)
    btn_frame.pack(fill='x', pady=(5, 0))
    add_btn = tk.Button(btn_frame, text='Add', width=8)
    edit_btn = tk.Button(btn_frame, text='Edit', width=8)
    delete_btn = tk.Button(btn_frame, text='Delete', width=8)
    import_btn = tk.Button(btn_frame, text='Import', width=8)
    export_btn = tk.Button(btn_frame, text='Export', width=8)
    save_btn = tk.Button(btn_frame, text='Save', width=8)
    cancel_btn = tk.Button(btn_frame, text='Cancel', width=8)

    def update_tcode_buttons(mode):
        # Remove all buttons from the frame
        for btn in (add_btn, edit_btn, delete_btn, import_btn, export_btn, save_btn, cancel_btn):
            btn.pack_forget()
        if mode == 'normal':
            add_btn.pack(side='left', padx=2)
            edit_btn.pack(side='left', padx=2)
            delete_btn.pack(side='left', padx=2)
            import_btn.pack(side='left', padx=2)
            export_btn.pack(side='left', padx=2)
        elif mode == 'edit':
            save_btn.pack(side='left', padx=2)
            cancel_btn.pack(side='left', padx=2)

    # Show only normal buttons by default
    update_tcode_buttons('normal')

    # --- Edit logic with Save/Cancel ---
    edit_index = [None]  # Mutable holder for index being edited

    def start_edit():
        print('Edit button clicked!')
        selected = tcode_tree.selection()
        if not selected:
            messagebox.showerror('Error', 'Select a TCode to edit.')
            return
        idx = tcode_tree.index(selected[0])
        values = tcode_tree.item(selected[0], 'values')
        tcode_code_entry.delete(0, tk.END)
        tcode_code_entry.insert(0, values[0])
        tcode_name_entry.delete(0, tk.END)
        tcode_name_entry.insert(0, values[1])
        edit_index[0] = idx
        update_tcode_buttons('edit')

    def save_edit():
        print('Save button clicked!')
        idx = edit_index[0]
        code = tcode_code_entry.get().strip()
        name = tcode_name_entry.get().strip()
        if idx is None or not code or not name:
            messagebox.showerror('Error', 'Both TCode and Name are required.')
            return
        # Check for duplicate (except itself)
        for i, t in enumerate(TCODE_LIST):
            if i != idx and t['code'].lower() == code.lower():
                messagebox.showerror('Error', 'Duplicate TCode.')
                return
        TCODE_LIST[idx]['code'] = code
        TCODE_LIST[idx]['name'] = name
        save_tcodes()
        load_tcodes()
        tcode_code_entry.delete(0, tk.END)
        tcode_name_entry.delete(0, tk.END)
        edit_index[0] = None
        update_tcode_buttons('normal')

    def cancel_edit():
        print('Cancel button clicked!')
        tcode_code_entry.delete(0, tk.END)
        tcode_name_entry.delete(0, tk.END)
        edit_index[0] = None
        update_tcode_buttons('normal')

    # --- Helper functions ---
    def load_tcodes():
        tcode_tree.delete(*tcode_tree.get_children())
        filter_text = search_var.get().lower()
        # Don't filter if it's the placeholder text
        if filter_text == 'type to search...':
            filter_text = ''
        for t in TCODE_LIST:
            if not filter_text or filter_text in t['code'].lower() or filter_text in t['name'].lower():
                tcode_tree.insert('', 'end', values=(t['code'], t['name']))

    def save_tcodes():
        with open(TCODE_FILE, 'w') as f:
            json.dump(TCODE_LIST, f, indent=2)

    def load_tcodes_from_file():
        global TCODE_LIST
        if os.path.exists(TCODE_FILE):
            try:
                with open(TCODE_FILE, 'r') as f:
                    TCODE_LIST = json.load(f)
            except Exception as e:
                messagebox.showerror('Error', f'Could not load TCodes from file: {e}')
                # Keep the default list if loading fails

    def add_tcode():
        code = tcode_code_entry.get().strip()
        name = tcode_name_entry.get().strip()
        if not code or not name:
            messagebox.showerror('Error', 'Both TCode and Name are required.')
            return
        if any(t['code'].lower() == code.lower() for t in TCODE_LIST):
            messagebox.showerror('Error', 'Duplicate TCode.')
            return
        TCODE_LIST.append({'code': code, 'name': name})
        save_tcodes()
        load_tcodes()
        tcode_code_entry.delete(0, tk.END)
        tcode_name_entry.delete(0, tk.END)

    def delete_tcode():
        selected = tcode_tree.selection()
        if not selected:
            messagebox.showerror('Error', 'Select a TCode to delete.')
            return
        idx = tcode_tree.index(selected[0])
        if messagebox.askyesno('Confirm', 'Delete selected TCode?'):
            del TCODE_LIST[idx]
            save_tcodes()
            load_tcodes()

    def import_tcodes():
        file_path = filedialog.askopenfilename(filetypes=[('CSV Files', '*.csv')])
        if not file_path:
            return
        with open(file_path, newline='', encoding='utf-8') as csvfile:
            reader = csv.reader(csvfile)
            for row in reader:
                if len(row) >= 2:
                    code, name = row[0].strip(), row[1].strip()
                    if code and name and not any(t['code'].lower() == code.lower() for t in TCODE_LIST):
                        TCODE_LIST.append({'code': code, 'name': name})
        save_tcodes()
        load_tcodes()

    def export_tcodes():
        file_path = filedialog.asksaveasfilename(defaultextension='.csv', filetypes=[('CSV Files', '*.csv')])
        if not file_path:
            return
        with open(file_path, 'w', newline='', encoding='utf-8') as csvfile:
            writer = csv.writer(csvfile)
            for t in TCODE_LIST:
                writer.writerow([t['code'], t['name']])
        messagebox.showinfo('Exported', 'TCodes exported successfully.')

    def on_tree_select(event):
        selected = tcode_tree.selection()
        if selected:
            values = tcode_tree.item(selected[0], 'values')
            tcode_code_entry.delete(0, tk.END)
            tcode_code_entry.insert(0, values[0])
            tcode_name_entry.delete(0, tk.END)
            tcode_name_entry.insert(0, values[1])

    def on_search_entry(event=None):
        load_tcodes()

    # Bindings
    add_btn.config(command=add_tcode)
    delete_btn.config(command=delete_tcode)
    import_btn.config(command=import_tcodes)
    export_btn.config(command=export_tcodes)
    search_entry.bind('<KeyRelease>', on_search_entry)
    tcode_tree.bind('<<TreeviewSelect>>', on_tree_select)

    # Initial load
    load_tcodes_from_file()
    load_tcodes()

    status_label = tk.Label(sap_frame, text='', fg='red')
    status_label.pack(pady=(10,0))

    btn_frame = tk.Frame(sap_frame)
    btn_frame.pack(pady=10)

    # Headless mode checkbox
    headless_var = tk.BooleanVar(value=False)
    headless_check = tk.Checkbutton(sap_frame, text='Run in Headless Mode', variable=headless_var)
    headless_check.pack(anchor='w', pady=(0, 0))

    # Keep browser open checkbox
    keep_browser_open_var = tk.BooleanVar(value=False)
    keep_browser_open_check = tk.Checkbutton(sap_frame, text='Keep Browser Open After Automation', variable=keep_browser_open_var)
    keep_browser_open_check.pack(anchor='w', pady=(0, 10))

    def on_login():
        url = url_entry.get()
        username = username_entry.get()
        password = password_entry.get()
        selected = tcode_tree.selection()
        if not selected:
            status_label.config(text='Please select a TCode.', fg='red')
            return
        tcode = tcode_tree.item(selected[0])['values'][0]
        if not all([url, username, password, tcode]):
            status_label.config(text='Please fill in all fields.', fg='red')
            return
        status_label.config(text='Starting login...', fg='blue')
        threading.Thread(target=login_to_sap, args=(url, username, password, tcode, status_label, False, headless_var.get(), keep_browser_open_var.get()), daemon=True).start()

    login_btn = tk.Button(btn_frame, text='Login', command=on_login)
    login_btn.pack(side='left', padx=5)

    save_btn = tk.Button(btn_frame, text='Save Credentials', command=lambda: save_credentials(url_entry.get(), username_entry.get(), password_entry.get(), root))
    save_btn.pack(side='left', padx=5)

    load_btn = tk.Button(btn_frame, text='Load Credentials', command=lambda: load_credentials(url_entry, username_entry, password_entry, root))
    load_btn.pack(side='left', padx=5)

    # Email Section (Right)
    email_frame = tk.LabelFrame(main_frame, text='Email Screenshot', padx=10, pady=10)
    email_frame.pack(side='left', fill='both', expand=True, padx=(10, 0))

    tk.Label(email_frame, text='Sender Gmail:').pack(anchor='w')
    sender_entry = tk.Entry(email_frame, width=30)
    sender_entry.pack()
    tk.Label(email_frame, text='App Password:').pack(anchor='w', pady=(10,0))
    app_password_entry = tk.Entry(email_frame, width=30, show='*')
    app_password_entry.pack()
    tk.Label(email_frame, text='Recipient Email:').pack(anchor='w', pady=(10,0))
    recipient_entry = tk.Entry(email_frame, width=30)
    recipient_entry.pack()
    tk.Label(email_frame, text='Subject:').pack(anchor='w', pady=(10,0))
    subject_entry = tk.Entry(email_frame, width=40)
    subject_entry.pack()
    subject_entry.insert(0, 'SAP Filesystem Screenshot')
    tk.Label(email_frame, text='Message:').pack(anchor='w', pady=(10,0))
    message_entry = scrolledtext.ScrolledText(email_frame, width=40, height=4)
    message_entry.pack()
    message_entry.insert(tk.END, 'Please find the attached SAP Filesystem screenshot.')

    email_btn_frame = tk.Frame(email_frame)
    email_btn_frame.pack(pady=10)

    def on_send_email():
        sender = sender_entry.get()
        app_password = app_password_entry.get()
        recipient = recipient_entry.get()
        subject = subject_entry.get()
        message = message_entry.get('1.0', tk.END)
        
        # Debug: Print the subject to see what's being retrieved
        print(f"DEBUG: Subject retrieved from UI: '{subject}'")
        print(f"DEBUG: Subject length: {len(subject)}")
        
        if not all([sender, app_password, recipient, subject, message]):
            status_label.config(text='Please fill in all email fields.', fg='red')
            return
        # Find all screenshots in screenshots dir
        screenshots = [os.path.join(SCREENSHOT_DIR, f) for f in os.listdir(SCREENSHOT_DIR) if f.startswith('screenshot_') and f.endswith('.png')]
        if not screenshots:
            status_label.config(text='No screenshot found. Please login and navigate first.', fg='red')
            return
        status_label.config(text='Sending email...', fg='blue')
        try:
            msg = MIMEMultipart()
            msg['From'] = sender
            msg['To'] = recipient
            msg['Subject'] = subject
            
            # Debug: Print the email headers to verify subject is set
            print(f"DEBUG: Email headers in automation - From: {msg['From']}, To: {msg['To']}, Subject: {msg['Subject']}")
            
            msg.attach(MIMEText(message, 'plain'))
            for screenshot_file in screenshots:
                with open(screenshot_file, 'rb') as f:
                    part = MIMEBase('application', 'octet-stream')
                    part.set_payload(f.read())
                    encoders.encode_base64(part)
                    part.add_header('Content-Disposition', f'attachment; filename={os.path.basename(screenshot_file)}')
                    msg.attach(part)
            server = smtplib.SMTP('smtp.gmail.com', 587)
            server.starttls()
            server.login(sender, app_password)
            server.send_message(msg)
            server.quit()
            status_label.config(text='Email sent successfully with all screenshots!', fg='green')
        except Exception as e:
            status_label.config(text=f'Failed to send email: {e}', fg='red')
        # Do not delete screenshots

    send_email_btn = tk.Button(email_btn_frame, text='Send Email', command=on_send_email)
    send_email_btn.pack(side='left', padx=5)

    save_email_btn = tk.Button(email_btn_frame, text='Save Email Creds', command=lambda: save_email_credentials(sender_entry.get(), app_password_entry.get(), recipient_entry.get(), root))
    save_email_btn.pack(side='left', padx=5)

    load_email_btn = tk.Button(email_btn_frame, text='Load Email Creds', command=lambda: load_email_credentials(sender_entry, app_password_entry, recipient_entry, root))
    load_email_btn.pack(side='left', padx=5)

    # Automate Button centered below both sections
    automate_btn_frame = tk.Frame(main_frame)
    automate_btn_frame.pack(pady=10)

    def on_automate():
        url = url_entry.get()
        username = username_entry.get()
        password = password_entry.get()
        selected = tcode_tree.selection()
        if not selected:
            status_label.config(text='Please select at least one TCode.', fg='red')
            return
        tcodes = [tcode_tree.item(i)['values'][0] for i in selected]
        sender = sender_entry.get()
        app_password = app_password_entry.get()
        recipient = recipient_entry.get()
        subject = subject_entry.get()
        message = message_entry.get('1.0', tk.END)
        if not all([url, username, password, tcodes, sender, app_password, recipient, subject, message]):
            status_label.config(text='Please fill in all SAP and email fields.', fg='red')
            return
        status_label.config(text='Starting full automation...', fg='blue')
        threading.Thread(target=automate_multiple_tcodes, args=(url, username, password, tcodes, sender, app_password, recipient, subject, message, status_label, headless_var.get(), keep_browser_open_var.get()), daemon=True).start()

    automate_btn = tk.Button(automate_btn_frame, text='Automate Everything', command=on_automate, bg='orange', fg='white', font=('Arial', 12, 'bold'))
    automate_btn.pack()

    # View Screenshots Folder button
    view_folder_btn = tk.Button(automate_btn_frame, text='View Screenshots Folder', command=open_screenshot_folder, bg='blue', fg='white', font=('Arial', 10, 'bold'))
    view_folder_btn.pack(pady=10)

    root.mainloop()

if __name__ == '__main__':
    main()