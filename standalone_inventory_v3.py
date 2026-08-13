import tkinter as tk
from tkinter import ttk, messagebox
import sqlite3
import bcrypt
import os
import logging
import csv
import time
import re

# ==========================================
# 0. CUSTOM STYLING COLOR PALETTE (DARK MODE)
# ==========================================
BG_COLOR = "#0D1117"
PANEL_BG = "#161B22"
TEXT_COLOR = "#C9D1D9"
ACCENT_BLUE = "#58A6FF"
ACCENT_GREEN = "#238636"
ACCENT_RED = "#DA3633"

def on_enter(e, widget, hover_color):
    if widget['state'] != tk.DISABLED:
        widget['background'] = hover_color

def on_leave(e, widget, default_color):
    if widget['state'] != tk.DISABLED:
        widget['background'] = default_color

def custom_button(parent, text, command, bg_color, hover_color, width=None):
    btn = tk.Button(parent, text=text, command=command, bg=bg_color, fg="white",
                    disabledforeground="#A0A0A0", activebackground=hover_color, activeforeground="white",
                    font=("Consolas", 10, "bold"), relief="flat", cursor="hand2", pady=5)
    if width:
        btn.config(width=width)
    btn.bind("<Enter>", lambda e: on_enter(e, btn, hover_color))
    btn.bind("<Leave>", lambda e: on_leave(e, btn, bg_color))
    return btn

# ==========================================
# 1. AUDIT LOGGING SETUP
# ==========================================
def setup_logger():
    log_dir = "app_logging"
    if not os.path.exists(log_dir):
        os.makedirs(log_dir)
    logging.basicConfig(
        filename=os.path.join(log_dir, "app.log"),
        level=logging.INFO,
        format="%(asctime)s - [%(levelname)s] - %(name)s - %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S"
    )
    return logging.getLogger("HardwareApp")

logger = setup_logger()
DB_NAME = "hardware_inventory_standalone.db"

def init_db():
    try:
        conn = sqlite3.connect(DB_NAME)
        cursor = conn.cursor()
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            failed_attempts INTEGER DEFAULT 0,
            lockout_until REAL DEFAULT 0
        )
        """)
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS hardware (
            item_id INTEGER PRIMARY KEY AUTOINCREMENT,
            item_name TEXT NOT NULL,
            category TEXT NOT NULL,
            quantity INTEGER NOT NULL,
            unit_price REAL NOT NULL,
            status TEXT NOT NULL
        )
        """)
        conn.commit()
        conn.close()
    except sqlite3.Error as e:
        logger.error(f"Database setup error: {e}")

# ==========================================
# 2.A. LOGIN WINDOW (Username & Password Only)
# ==========================================
class LoginWindow:
    def __init__(self, root, on_success_callback, on_register_callback):
        self.root = root
        self.on_success = on_success_callback
        self.on_register = on_register_callback
        
        self.root.title("Terminal: System Login")
        self.root.geometry("400x380")
        self.root.configure(bg=BG_COLOR)
        self.root.resizable(False, False)
        self.build_ui()

    def build_ui(self):
        tk.Label(self.root, text="[ SECURE LOGIN ]", font=("Consolas", 14, "bold"), bg=BG_COLOR, fg=ACCENT_BLUE).pack(pady=(40, 15))
        
        frame_inputs = tk.Frame(self.root, bg=BG_COLOR)
        frame_inputs.pack(pady=10)

        tk.Label(frame_inputs, text="Username:", font=("Consolas", 10), bg=BG_COLOR, fg=TEXT_COLOR).grid(row=0, column=0, sticky="w", padx=5, pady=10)
        self.entry_user = ttk.Entry(frame_inputs, width=25, font=("Consolas", 11), style="Normal.TEntry")
        self.entry_user.grid(row=0, column=1, padx=5, pady=10)

        tk.Label(frame_inputs, text="Password:", font=("Consolas", 10), bg=BG_COLOR, fg=TEXT_COLOR).grid(row=1, column=0, sticky="w", padx=5, pady=10)
        self.entry_pass = ttk.Entry(frame_inputs, show="*", width=25, font=("Consolas", 11), style="Normal.TEntry")
        self.entry_pass.grid(row=1, column=1, padx=5, pady=10)
        
        self.show_pass_var = tk.IntVar()
        chk_show = tk.Checkbutton(self.root, text="Show Password", variable=self.show_pass_var, command=self.toggle_password,
                                  bg=BG_COLOR, fg=TEXT_COLOR, activebackground=BG_COLOR, activeforeground=TEXT_COLOR, selectcolor=PANEL_BG)
        chk_show.pack(anchor="w", padx=45, pady=(0, 20))
        
        btn_frame = tk.Frame(self.root, bg=BG_COLOR)
        btn_frame.pack(pady=5)
        
        self.btn_login = custom_button(btn_frame, ">> LOGIN <<", self.login, ACCENT_GREEN, "#2EA043", width=14)
        self.btn_login.pack(side="left", padx=10)
        
        btn_register = custom_button(btn_frame, "REGISTER", self.on_register, ACCENT_BLUE, "#79C0FF", width=12)
        btn_register.pack(side="right", padx=10)

    def toggle_password(self):
        if self.show_pass_var.get():
            self.entry_pass.config(show="")
        else:
            self.entry_pass.config(show="*")

    def start_lockout_countdown(self, remaining):
        if remaining > 0:
            self.btn_login.config(state=tk.DISABLED, text=f"LOCKED ({remaining}s)", bg="#3A3A3A", cursor="X_cursor")
            self.root.after(1000, self.start_lockout_countdown, remaining - 1)
        else:
            self.btn_login.config(state=tk.NORMAL, text=">> LOGIN <<", bg=ACCENT_GREEN, cursor="hand2")

    def login(self):
        user = self.entry_user.get().strip()
        pw = self.entry_pass.get().strip()
        
        conn = sqlite3.connect(DB_NAME)
        cursor = conn.cursor()
        cursor.execute("SELECT id, password_hash, failed_attempts, lockout_until FROM users WHERE username=?", (user,))
        row = cursor.fetchone()
        
        if not row:
            conn.close()
            messagebox.showerror("Access Denied", "Invalid username or password.")
            return
            
        user_id, hashed_pw, failed_attempts, lockout_until = row
        current_time = time.time()
        
        if lockout_until and current_time < lockout_until:
            remaining = int(lockout_until - current_time)
            conn.close()
            self.start_lockout_countdown(remaining)
            messagebox.showerror("Account Locked", f"System defense active.\nPlease wait {remaining} seconds.")
            return

        if bcrypt.checkpw(pw.encode('utf-8'), hashed_pw.encode('utf-8')):
            cursor.execute("UPDATE users SET failed_attempts = 0, lockout_until = 0 WHERE id=?", (user_id,))
            conn.commit()
            conn.close()
            logger.info(f"User {user} logged in successfully.")
            self.on_success(user)
        else:
            failed_attempts += 1
            new_lockout = 0
            msg = "Invalid username or password."
            
            if failed_attempts >= 3:
                new_lockout = current_time + 30
                msg = "3 consecutive failed attempts.\nAccount temporarily locked."
                logger.warning(f"User {user} locked out for 30s.")
            
            cursor.execute("UPDATE users SET failed_attempts = ?, lockout_until = ? WHERE id=?", (failed_attempts, new_lockout, user_id))
            conn.commit()
            conn.close()
            
            if failed_attempts >= 3:
                self.start_lockout_countdown(30)
                
            messagebox.showerror("Access Denied", msg)


# ==========================================
# 2.B. REGISTRATION WINDOW (Separate Page)
# ==========================================
class RegisterWindow:
    def __init__(self, root, on_back_callback):
        self.root = root
        self.on_back = on_back_callback
        
        self.root.title("Terminal: System Registration")
        self.root.geometry("420x450")
        self.root.configure(bg=BG_COLOR)
        self.root.resizable(False, False)
        self.build_ui()

    def build_ui(self):
        tk.Label(self.root, text="[ NEW ACCOUNT REGISTRATION ]", font=("Consolas", 13, "bold"), bg=BG_COLOR, fg=ACCENT_BLUE).pack(pady=(30, 15))
        
        frame_inputs = tk.Frame(self.root, bg=BG_COLOR)
        frame_inputs.pack(pady=10)

        tk.Label(frame_inputs, text="Username:", font=("Consolas", 10), bg=BG_COLOR, fg=TEXT_COLOR).grid(row=0, column=0, sticky="w", padx=5, pady=10)
        self.entry_user = ttk.Entry(frame_inputs, width=25, font=("Consolas", 11), style="Normal.TEntry")
        self.entry_user.grid(row=0, column=1, padx=5, pady=10)
        
        tk.Label(frame_inputs, text="Email Address:", font=("Consolas", 10), bg=BG_COLOR, fg=TEXT_COLOR).grid(row=1, column=0, sticky="w", padx=5, pady=10)
        self.entry_email = ttk.Entry(frame_inputs, width=25, font=("Consolas", 11), style="Normal.TEntry")
        self.entry_email.grid(row=1, column=1, padx=5, pady=10)

        tk.Label(frame_inputs, text="Password:", font=("Consolas", 10), bg=BG_COLOR, fg=TEXT_COLOR).grid(row=2, column=0, sticky="w", padx=5, pady=10)
        self.entry_pass = ttk.Entry(frame_inputs, show="*", width=25, font=("Consolas", 11), style="Normal.TEntry")
        self.entry_pass.grid(row=2, column=1, padx=5, pady=10)
        
        self.show_pass_var = tk.IntVar()
        chk_show = tk.Checkbutton(self.root, text="Show Password", variable=self.show_pass_var, command=self.toggle_password,
                                  bg=BG_COLOR, fg=TEXT_COLOR, activebackground=BG_COLOR, activeforeground=TEXT_COLOR, selectcolor=PANEL_BG)
        chk_show.pack(anchor="w", padx=45, pady=(0, 15))
        
        btn_frame = tk.Frame(self.root, bg=BG_COLOR)
        btn_frame.pack(pady=10)
        
        btn_back = custom_button(btn_frame, "<< BACK", self.on_back, ACCENT_RED, "#F85149", width=12)
        btn_back.pack(side="left", padx=10)
        
        btn_register = custom_button(btn_frame, ">> REGISTER <<", self.register, ACCENT_BLUE, "#79C0FF", width=14)
        btn_register.pack(side="right", padx=10)

    def toggle_password(self):
        if self.show_pass_var.get():
            self.entry_pass.config(show="")
        else:
            self.entry_pass.config(show="*")

    def register(self):
        user = self.entry_user.get().strip()
        email = self.entry_email.get().strip()
        pw = self.entry_pass.get().strip()
        
        if not re.match("^[a-zA-Z0-9_]{3,20}$", user):
            messagebox.showwarning("Validation Error", "Username must be 3-20 chars (letters/numbers/underscores only).")
            return
        if not re.match(r"[^@]+@[^@]+\.[^@]+", email):
            messagebox.showwarning("Validation Error", "Invalid email format.")
            return
        if len(pw) < 8 or not re.search(r'[A-Z]', pw) or not re.search(r'\d', pw) or not re.search(r'[@#$%^&*]', pw):
            messagebox.showwarning("Validation Error", "Password must have at least 8 chars, 1 uppercase, 1 number, and 1 special char (@#$%^&*).")
            return
            
        hashed_pw = bcrypt.hashpw(pw.encode('utf-8'), bcrypt.gensalt())
        try:
            conn = sqlite3.connect(DB_NAME)
            cursor = conn.cursor()
            cursor.execute("INSERT INTO users (username, email, password_hash) VALUES (?, ?, ?)", (user, email, hashed_pw.decode('utf-8')))
            conn.commit()
            conn.close()
            logger.info(f"Account created: {user}")
            messagebox.showinfo("Success", "Registration successful! You may now login.")
            self.on_back() # Auto-return to login screen after successful signup
        except sqlite3.IntegrityError as e:
            if "email" in str(e).lower():
                messagebox.showerror("Error", "Email already registered.")
            else:
                messagebox.showerror("Error", "Username already taken.")

# ==========================================
# 3. MAIN INVENTORY WINDOW (DARK THEME)
# ==========================================
class InventoryWindow:
    def __init__(self, root, current_user, on_logout_callback):
        self.root = root
        self.current_user = current_user
        self.on_logout = on_logout_callback
        
        self.root.title(f"Terminal: Hardware Inventory Nexus - User: {current_user}")
        self.root.geometry("850x650")
        self.root.configure(bg=BG_COLOR)
        
        self.build_ui()
        self.load_data()

    def build_ui(self):
        header_frame = tk.Frame(self.root, bg=BG_COLOR)
        header_frame.pack(fill="x", padx=15, pady=10)
        
        self.lbl_valuation = tk.Label(header_frame, text="TOTAL ASSET VALUATION: ₱0.00", font=("Consolas", 12, "bold"), fg=ACCENT_GREEN, bg=BG_COLOR)
        self.lbl_valuation.pack(side="left")
        
        btn_logout = custom_button(header_frame, "LOGOUT", self.logout, ACCENT_RED, "#F85149")
        btn_logout.pack(side="right")
        btn_export = custom_button(header_frame, "EXPORT CSV", self.export_csv, ACCENT_BLUE, "#79C0FF")
        btn_export.pack(side="right", padx=10)

        input_frame = tk.LabelFrame(self.root, text=" [+] LOG NEW HARDWARE ", bg=BG_COLOR, fg=ACCENT_BLUE, font=("Consolas", 11, "bold"), bd=1)
        input_frame.pack(fill="x", padx=15, pady=5)
        
        tk.Label(input_frame, text="Item Name:", bg=BG_COLOR, fg=TEXT_COLOR, font=("Consolas", 10)).grid(row=0, column=0, sticky="e", padx=5, pady=10)
        
        self.item_name_var = tk.StringVar()
        self.item_name_var.trace_add("write", self.check_duplicate_realtime)
        
        self.e_name = ttk.Entry(input_frame, width=22, font=("Consolas", 10), textvariable=self.item_name_var, style="Normal.TEntry")
        self.e_name.grid(row=0, column=1, padx=5, pady=10)
        
        tk.Label(input_frame, text="Category:", bg=BG_COLOR, fg=TEXT_COLOR, font=("Consolas", 10)).grid(row=0, column=2, sticky="e", padx=5, pady=10)
        self.e_category = ttk.Entry(input_frame, width=22, font=("Consolas", 10), style="Normal.TEntry")
        self.e_category.grid(row=0, column=3, padx=5, pady=10)
        
        tk.Label(input_frame, text="Quantity:", bg=BG_COLOR, fg=TEXT_COLOR, font=("Consolas", 10)).grid(row=1, column=0, sticky="e", padx=5, pady=10)
        self.e_qty = ttk.Entry(input_frame, width=22, font=("Consolas", 10), style="Normal.TEntry")
        self.e_qty.grid(row=1, column=1, padx=5, pady=10)
        
        tk.Label(input_frame, text="Unit Price (₱):", bg=BG_COLOR, fg=TEXT_COLOR, font=("Consolas", 10)).grid(row=1, column=2, sticky="e", padx=5, pady=10)
        self.e_price = ttk.Entry(input_frame, width=22, font=("Consolas", 10), style="Normal.TEntry")
        self.e_price.grid(row=1, column=3, padx=5, pady=10)
        
        self.btn_save = custom_button(input_frame, ">> ADD ITEM <<", self.save_item, ACCENT_GREEN, "#2EA043")
        self.btn_save.grid(row=1, column=4, padx=15, pady=10)

        grid_frame = tk.Frame(self.root, bg=BG_COLOR)
        grid_frame.pack(fill="both", expand=True, padx=15, pady=10)
        
        scroll = ttk.Scrollbar(grid_frame)
        scroll.pack(side="right", fill="y")
        
        self.tree = ttk.Treeview(grid_frame, columns=("ID", "Name", "Category", "Qty", "Price", "Status"), show="headings", yscrollcommand=scroll.set, selectmode="none")
        for col in ("ID", "Name", "Category", "Qty", "Price", "Status"):
            self.tree.heading(col, text=col.upper())
            self.tree.column(col, anchor="center", width=120)
        self.tree.column("Name", width=180)
        self.tree.pack(fill="both", expand=True)
        
        self.tree.tag_configure("In Stock", background="#003B00", foreground="white")
        self.tree.tag_configure("Low Stock", background="#3B3B00", foreground="white")
        self.tree.tag_configure("Out of Stock", background="#4A0000", foreground="white")

    def check_duplicate_realtime(self, *args):
        current_name = self.item_name_var.get().strip()
        if not current_name:
            self.btn_save.config(text=">> ADD ITEM <<", state=tk.NORMAL, bg=ACCENT_GREEN)
            self.e_name.config(style="Normal.TEntry")
            return

        conn = sqlite3.connect(DB_NAME)
        cursor = conn.cursor()
        cursor.execute("SELECT item_name FROM hardware WHERE LOWER(item_name) = LOWER(?)", (current_name,))
        exists = cursor.fetchone()
        conn.close()
        
        if exists:
            self.btn_save.config(text="[!] DUPLICATE DETECTED", state=tk.DISABLED, bg=ACCENT_RED, disabledforeground="white")
            self.e_name.config(style="Error.TEntry")
        else:
            self.btn_save.config(text=">> ADD ITEM <<", state=tk.NORMAL, bg=ACCENT_GREEN)
            self.e_name.config(style="Normal.TEntry")

    def compute_status(self, qty):
        if qty > 5:
            return 'In Stock'
        elif 1 <= qty <= 5:
            return 'Low Stock'
        else:
            return 'Out of Stock'

    def update_valuation(self):
        conn = sqlite3.connect(DB_NAME)
        cursor = conn.cursor()
        cursor.execute("SELECT SUM(quantity * unit_price) FROM hardware")
        total = cursor.fetchone()[0]
        conn.close()
        
        total_val = total if total else 0.0
        self.lbl_valuation.config(text=f"TOTAL ASSET VALUATION: ₱{total_val:,.2f}")

    def load_data(self):
        for row in self.tree.get_children():
            self.tree.delete(row)
            
        conn = sqlite3.connect(DB_NAME)
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM hardware")
        rows = cursor.fetchall()
        conn.close()
        
        for row in rows:
            status = row[5]
            formatted_row = (row[0], row[1], row[2], row[3], f"₱{row[4]:.2f}", row[5])
            self.tree.insert("", tk.END, values=formatted_row, tags=(status,))
        self.update_valuation()

    def save_item(self):
        name = self.item_name_var.get().strip()
        cat = self.e_category.get().strip()
        qty_str = self.e_qty.get().strip()
        price_str = self.e_price.get().strip()
        
        if not name or not cat or not qty_str or not price_str:
            messagebox.showwarning("Input Error", "All fields are required.")
            return
        try:
            qty = int(qty_str)
            price = float(price_str)
        except ValueError:
            messagebox.showerror("Format Error", "Quantity must be an integer and Price must be a number.")
            return
            
        status = self.compute_status(qty)
        
        conn = sqlite3.connect(DB_NAME)
        cursor = conn.cursor()
        cursor.execute("INSERT INTO hardware (item_name, category, quantity, unit_price, status) VALUES (?, ?, ?, ?, ?)",
                       (name, cat, qty, price, status))
        conn.commit()
        conn.close()
        
        logger.info(f"User {self.current_user} added {name}.")
        self.e_name.delete(0, tk.END)
        self.e_category.delete(0, tk.END)
        self.e_qty.delete(0, tk.END)
        self.e_price.delete(0, tk.END)
        
        self.load_data()
        self.check_duplicate_realtime()

    def export_csv(self):
        conn = sqlite3.connect(DB_NAME)
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM hardware")
        rows = cursor.fetchall()
        conn.close()
        
        filename = "inventory_report_v3.csv"
        try:
            with open(filename, 'w', newline='', encoding='utf-8') as f:
                writer = csv.writer(f)
                writer.writerow(["ID", "Name", "Category", "Quantity", "Unit Price", "Status"])
                writer.writerows(rows)
            logger.info(f"User {self.current_user} exported inventory to CSV.")
            messagebox.showinfo("System Alert", f"Data exported successfully to {filename}")
        except Exception as e:
            logger.error(f"Failed to export CSV: {e}")
            messagebox.showerror("System Error", "Failed to generate CSV report.")

    def logout(self):
        logger.info(f"User {self.current_user} logged out.")
        self.on_logout()

# ==========================================
# 4. APPLICATION CONTROLLER (NAVIGATION MANAGER)
# ==========================================
class AppController:
    def __init__(self):
        init_db()
        self.root = tk.Tk()
        self.setup_styles()
        self.show_login()
        self.root.mainloop()
        
    def setup_styles(self):
        style = ttk.Style()
        style.theme_use("clam")
        style.configure("Normal.TEntry", fieldbackground=PANEL_BG, foreground=TEXT_COLOR, insertcolor=TEXT_COLOR, bordercolor=BG_COLOR)
        style.configure("Error.TEntry", fieldbackground=PANEL_BG, foreground=ACCENT_RED, insertcolor=ACCENT_RED, bordercolor=ACCENT_RED)
        style.configure("Treeview", background=PANEL_BG, foreground=TEXT_COLOR, rowheight=35, fieldbackground=PANEL_BG, bordercolor=BG_COLOR, font=("Consolas", 10))
        style.configure("Treeview.Heading", font=("Consolas", 11, "bold"), background="#21262D", foreground=ACCENT_BLUE)

    def clear_window(self):
        for widget in self.root.winfo_children():
            widget.destroy()

    def show_login(self):
        self.clear_window()
        # Papasa natin yung show_inventory (kapag success login) at show_register (kapag click yung Register button)
        LoginWindow(self.root, self.show_inventory, self.show_register)

    def show_register(self):
        self.clear_window()
        # Papasa natin yung show_login para sa "<< BACK" button
        RegisterWindow(self.root, self.show_login)

    def show_inventory(self, username):
        self.clear_window()
        InventoryWindow(self.root, username, self.show_login)

if __name__ == "__main__":
    AppController()