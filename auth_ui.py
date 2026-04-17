"""
Login and Signup UI for OSINT Footprint Gathering Tool
Firebase Authentication via REST API
"""

import tkinter as tk
from tkinter import ttk, messagebox
import json
import requests

from firebase_config import FIREBASE_CONFIG, FIREBASE_AUTH_SIGNUP_URL, FIREBASE_AUTH_SIGNIN_URL

# Theme (match main app)
BG_DARK = "#2b2b2b"
BG_INPUT = "#3c3c3c"
FG = "#ffffff"
ACCENT = "#0078d4"
ACCENT_HOVER = "#005a9e"
LINK = "#4ec9b0"
ERROR = "#f48771"


def firebase_signup(email: str, password: str):
    """Register new user via Firebase Auth REST API."""
    url = FIREBASE_AUTH_SIGNUP_URL.format(api_key=FIREBASE_CONFIG["apiKey"])
    payload = {
        "email": email,
        "password": password,
        "returnSecureToken": True,
    }
    headers = {"Content-Type": "application/json"}
    r = requests.post(url, json=payload, headers=headers, timeout=15)
    data = r.json()
    if r.status_code != 200:
        err = data.get("error", {})
        msg = err.get("message", r.text)
        raise Exception(msg)
    return data


def firebase_signin(email: str, password: str):
    """Sign in via Firebase Auth REST API."""
    url = FIREBASE_AUTH_SIGNIN_URL.format(api_key=FIREBASE_CONFIG["apiKey"])
    payload = {
        "email": email,
        "password": password,
        "returnSecureToken": True,
    }
    headers = {"Content-Type": "application/json"}
    r = requests.post(url, json=payload, headers=headers, timeout=15)
    data = r.json()
    if r.status_code != 200:
        err = data.get("error", {})
        msg = err.get("message", r.text)
        raise Exception(msg)
    return data


class AuthUI:
    """Login and Signup windows."""

    def __init__(self, on_success):
        self.on_success = on_success
        self.root = tk.Tk()
        self.root.title("OSINT Footprint Gathering Tool - Login")
        self.root.configure(bg=BG_DARK)
        self.root.resizable(False, False)

        # Center window (login height; signup uses taller)
        self.win_w, self.win_h_login = 420, 340
        self.win_h_signup = 440
        sw = self.root.winfo_screenwidth()
        sh = self.root.winfo_screenheight()
        x = (sw - self.win_w) // 2
        y = (sh - self.win_h_login) // 2
        self.root.geometry(f"{self.win_w}x{self.win_h_login}+{x}+{y}")

        self.content = ttk.Frame(self.root, padding=24)
        self.content.pack(fill=tk.BOTH, expand=True)
        self.show_login()

    def _clear(self):
        for w in self.content.winfo_children():
            w.destroy()

    def _resize(self, height: int):
        sw = self.root.winfo_screenwidth()
        sh = self.root.winfo_screenheight()
        x = (sw - self.win_w) // 2
        y = (sh - height) // 2
        self.root.geometry(f"{self.win_w}x{height}+{x}+{y}")

    def show_login(self):
        self.root.title("OSINT Footprint Gathering Tool - Login")
        self._resize(self.win_h_login)
        self._clear()
        f = self.content

        title = tk.Label(
            f,
            text="OSINT Footprint Gathering Tool",
            font=("Segoe UI", 14, "bold"),
            fg=FG,
            bg=BG_DARK,
        )
        title.pack(pady=(0, 8))

        sub = tk.Label(
            f,
            text="Sign in to continue",
            font=("Segoe UI", 10),
            fg="#aaaaaa",
            bg=BG_DARK,
        )
        sub.pack(pady=(0, 20))

        email_l = tk.Label(f, text="Email", font=("Segoe UI", 10), fg=FG, bg=BG_DARK)
        email_l.pack(anchor="w", pady=(8, 2))
        self.email_var = tk.StringVar()
        email_e = tk.Entry(
            f,
            textvariable=self.email_var,
            font=("Segoe UI", 11),
            bg=BG_INPUT,
            fg=FG,
            insertbackground=FG,
            relief=tk.FLAT,
            width=36,
        )
        email_e.pack(ipady=8, ipadx=10, pady=(0, 12), fill=tk.X)

        pass_l = tk.Label(f, text="Password", font=("Segoe UI", 10), fg=FG, bg=BG_DARK)
        pass_l.pack(anchor="w", pady=(4, 2))
        self.pass_var = tk.StringVar()
        pass_e = tk.Entry(
            f,
            textvariable=self.pass_var,
            show="•",
            font=("Segoe UI", 11),
            bg=BG_INPUT,
            fg=FG,
            insertbackground=FG,
            relief=tk.FLAT,
            width=36,
        )
        pass_e.pack(ipady=8, ipadx=10, pady=(0, 16), fill=tk.X)
        pass_e.bind("<Return>", lambda e: self.do_login())

        btn_f = tk.Frame(f, bg=BG_DARK)
        btn_f.pack(fill=tk.X, pady=(0, 16))

        login_btn = tk.Button(
            btn_f,
            text="Login",
            font=("Segoe UI", 10, "bold"),
            bg=ACCENT,
            fg=FG,
            activebackground=ACCENT_HOVER,
            activeforeground=FG,
            relief=tk.FLAT,
            cursor="hand2",
            padx=24,
            pady=10,
            command=self.do_login,
        )
        login_btn.pack(side=tk.LEFT)

        reg_btn = tk.Button(
            btn_f,
            text="New user? Register",
            font=("Segoe UI", 10),
            fg=LINK,
            bg=BG_DARK,
            activeforeground=LINK,
            activebackground=BG_DARK,
            relief=tk.FLAT,
            cursor="hand2",
            command=self.show_signup,
        )
        reg_btn.pack(side=tk.LEFT, padx=(20, 0))

    def show_signup(self):
        self.root.title("OSINT Footprint Gathering Tool - Register")
        self._resize(self.win_h_signup)
        self._clear()
        f = self.content

        title = tk.Label(
            f,
            text="Create Account",
            font=("Segoe UI", 14, "bold"),
            fg=FG,
            bg=BG_DARK,
        )
        title.pack(pady=(0, 8))

        sub = tk.Label(
            f,
            text="Register to use OSINT Footprint Gathering Tool",
            font=("Segoe UI", 10),
            fg="#aaaaaa",
            bg=BG_DARK,
        )
        sub.pack(pady=(0, 16))

        email_l = tk.Label(f, text="Email", font=("Segoe UI", 10), fg=FG, bg=BG_DARK)
        email_l.pack(anchor="w", pady=(4, 2))
        self.reg_email = tk.StringVar()
        email_e = tk.Entry(
            f,
            textvariable=self.reg_email,
            font=("Segoe UI", 11),
            bg=BG_INPUT,
            fg=FG,
            insertbackground=FG,
            relief=tk.FLAT,
            width=36,
        )
        email_e.pack(ipady=8, ipadx=10, pady=(0, 10), fill=tk.X)

        pass_l = tk.Label(f, text="Password", font=("Segoe UI", 10), fg=FG, bg=BG_DARK)
        pass_l.pack(anchor="w", pady=(4, 2))
        self.reg_pass = tk.StringVar()
        pass_e = tk.Entry(
            f,
            textvariable=self.reg_pass,
            show="•",
            font=("Segoe UI", 11),
            bg=BG_INPUT,
            fg=FG,
            insertbackground=FG,
            relief=tk.FLAT,
            width=36,
        )
        pass_e.pack(ipady=8, ipadx=10, pady=(0, 10), fill=tk.X)

        confirm_l = tk.Label(
            f, text="Confirm Password", font=("Segoe UI", 10), fg=FG, bg=BG_DARK
        )
        confirm_l.pack(anchor="w", pady=(4, 2))
        self.reg_confirm = tk.StringVar()
        confirm_e = tk.Entry(
            f,
            textvariable=self.reg_confirm,
            show="•",
            font=("Segoe UI", 11),
            bg=BG_INPUT,
            fg=FG,
            insertbackground=FG,
            relief=tk.FLAT,
            width=36,
        )
        confirm_e.pack(ipady=8, ipadx=10, pady=(0, 16), fill=tk.X)
        confirm_e.bind("<Return>", lambda e: self.do_register())

        btn_f = tk.Frame(f, bg=BG_DARK)
        btn_f.pack(fill=tk.X, pady=(0, 12))

        reg_btn = tk.Button(
            btn_f,
            text="Register",
            font=("Segoe UI", 10, "bold"),
            bg=ACCENT,
            fg=FG,
            activebackground=ACCENT_HOVER,
            activeforeground=FG,
            relief=tk.FLAT,
            cursor="hand2",
            padx=24,
            pady=10,
            command=self.do_register,
        )
        reg_btn.pack(side=tk.LEFT)

        back_btn = tk.Button(
            btn_f,
            text="Already have account? Login",
            font=("Segoe UI", 10),
            fg=LINK,
            bg=BG_DARK,
            activeforeground=LINK,
            activebackground=BG_DARK,
            relief=tk.FLAT,
            cursor="hand2",
            command=self.show_login,
        )
        back_btn.pack(side=tk.LEFT, padx=(20, 0))

    def do_login(self):
        email = self.email_var.get().strip()
        password = self.pass_var.get()
        if not email or not password:
            messagebox.showwarning("Login", "Enter email and password.")
            return
        try:
            firebase_signin(email, password)
            self.root.destroy()
            self.on_success()
        except Exception as e:
            messagebox.showerror("Login Failed", str(e))

    def do_register(self):
        email = self.reg_email.get().strip()
        password = self.reg_pass.get()
        confirm = self.reg_confirm.get()
        if not email or not password:
            messagebox.showwarning("Register", "Enter email and password.")
            return
        if password != confirm:
            messagebox.showwarning("Register", "Passwords do not match.")
            return
        if len(password) < 6:
            messagebox.showwarning(
                "Register", "Password must be at least 6 characters."
            )
            return
        try:
            firebase_signup(email, password)
            messagebox.showinfo("Registered", "Account created. Please sign in.")
            self.reg_email.set("")
            self.reg_pass.set("")
            self.reg_confirm.set("")
            self.show_login()
        except Exception as e:
            messagebox.showerror("Registration Failed", str(e))

    def run(self):
        self.root.mainloop()


def run_auth_then_app():
    """Show login first; on success, run main OSINT app."""

    def on_success():
        from gui_app import main as run_main

        run_main()

    auth = AuthUI(on_success=on_success)
    auth.run()
