import tkinter as tk
from tkinter import ttk, messagebox
import string
import re
import math
from collections import Counter
import secrets

# Optional: For tooltips (Python 3.9+ only)
try:
    from idlelib.tooltip import Hovertip
    HAS_TOOLTIP = True
except ImportError:
    HAS_TOOLTIP = False

# Constants
STRENGTH_THRESHOLDS = [
    (80, 'green', 'Very Strong'),
    (60, 'blue', 'Strong'),
    (40, 'orange', 'Moderate'),
    (20, 'yellow', 'Weak'),
    (0, 'red', 'Very Weak')
]

class PasswordAnalyzerApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Password Strength Analyzer")
        self.root.geometry("800x600")

        self.style = ttk.Style()
        self.style.theme_use('clam')
        self.style.configure('TFrame', background='#f0f0f0')
        self.style.configure('TLabel', background='#f0f0f0', font=('Arial', 10))
        self.style.configure('TButton', font=('Arial', 10))
        self.style.configure('Header.TLabel', font=('Arial', 14, 'bold'))
        self.style.configure('Result.TLabel', font=('Arial', 10, 'bold'))

        self.analyzer = PasswordAnalyzer()
        self.create_widgets()

    def create_widgets(self):
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.pack(fill=tk.BOTH, expand=True)

        header = ttk.Label(main_frame, text="Password Strength Analyzer", style='Header.TLabel')
        header.pack(pady=10)

        entry_frame = ttk.Frame(main_frame)
        entry_frame.pack(fill=tk.X, pady=10)

        ttk.Label(entry_frame, text="Enter Password:").pack(side=tk.LEFT)

        self.password_var = tk.StringVar()
        self.password_entry = ttk.Entry(entry_frame, textvariable=self.password_var, show="*", width=40)
        self.password_entry.pack(side=tk.LEFT, padx=10)
        self.password_entry.bind('<KeyRelease>', self.on_password_change)

        self.show_password_var = tk.IntVar()
        ttk.Checkbutton(entry_frame, text="Show", variable=self.show_password_var,
                        command=self.toggle_password_visibility).pack(side=tk.LEFT)

        if HAS_TOOLTIP:
            Hovertip(self.password_entry, "Type or paste your password here.")

        btn_frame = ttk.Frame(main_frame)
        btn_frame.pack(pady=10)

        ttk.Button(btn_frame, text="Analyze Password", command=self.analyze_password).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="Generate Strong Password", command=self.generate_password).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="Copy", command=self.copy_to_clipboard).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="Save Report", command=self.save_report).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="Toggle Theme", command=self.toggle_theme).pack(side=tk.LEFT, padx=5)

        self.strength_label = ttk.Label(main_frame, text="Strength: ", style='Header.TLabel')
        self.strength_label.pack(pady=10)

        self.strength_meter = ttk.Progressbar(main_frame, length=500, mode='determinate')
        self.strength_meter.pack(pady=5)

        self.strength_text = ttk.Label(main_frame, text="", style='Result.TLabel')
        self.strength_text.pack(pady=5)

        self.result_box = tk.Text(main_frame, height=20, wrap=tk.WORD, padx=10, pady=10)
        self.result_box.pack(fill=tk.BOTH, expand=True)
        self.result_box.config(state=tk.DISABLED)

    def toggle_password_visibility(self):
        self.password_entry.config(show="" if self.show_password_var.get() else "*")

    def toggle_theme(self):
        current = self.style.theme_use()
        self.style.theme_use('default' if current == 'clam' else 'clam')

    def copy_to_clipboard(self):
        password = self.password_var.get()
        if password:
            self.root.clipboard_clear()
            self.root.clipboard_append(password)
            messagebox.showinfo("Copied", "Password copied to clipboard!")

    def generate_password(self):
        chars = string.ascii_letters + string.digits + string.punctuation
        password = ''.join(secrets.choice(chars) for _ in range(16))
        self.password_var.set(password)
        self.show_password_var.set(1)
        self.toggle_password_visibility()
        self.analyze_password()

    def save_report(self):
        result = self.analyzer.analyze_password(self.password_var.get())
        try:
            with open("password_report.txt", "w") as f:
                f.write("Password Strength Report\n")
                f.write("-" * 30 + "\n")
                for k, v in result.items():
                    f.write(f"{k}: {v}\n")
            messagebox.showinfo("Saved", "Report saved to password_report.txt")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to save report: {e}")

    def on_password_change(self, _=None):
        self.root.after(400, self.analyze_password)

    def analyze_password(self):
        password = self.password_var.get()
        if not password:
            self.strength_meter['value'] = 0
            self.strength_label.config(text="Strength: ")
            self.strength_text.config(text="")
            return

        result = self.analyzer.analyze_password(password)
        score = result['strength_score']
        self.strength_meter['value'] = score

        # Strength label & color
        for threshold, color, label in STRENGTH_THRESHOLDS:
            if score >= threshold:
                self.style.configure('Horizontal.TProgressbar', troughcolor='#f0f0f0', background=color)
                self.strength_label.config(text=f"Strength: {label}")
                self.strength_text.config(text=f"{score}/100")
                break

        # Result details
        self.result_box.config(state=tk.NORMAL)
        self.result_box.delete("1.0", tk.END)
        for k, v in result.items():
            self.result_box.insert(tk.END, f"{k}: {v}\n\n")
        self.result_box.config(state=tk.DISABLED)


class PasswordAnalyzer:
    def __init__(self):
        self.common_passwords = {'password', '123456', 'qwerty', 'abc123'}
        self.common_words = {'admin', 'love', 'test'}
        self.common_patterns = [
            r'\d{4}', r'(19|20)\d{2}', r'(abc|123|qwe|asd)', r'(.)\1{2,}', r'(password|admin|login)'
        ]
        self.attack_speeds = {
            'online_throttled': 10,
            'online_fast': 1000,
            'offline_slow': 1e6,
            'offline_fast': 1e9,
            'offline_gpu': 1e12
        }

    def get_charset_info(self, password):
        charset_size = 0
        types = []
        if any(c.islower() for c in password):
            charset_size += 26
            types.append("lowercase")
        if any(c.isupper() for c in password):
            charset_size += 26
            types.append("uppercase")
        if any(c.isdigit() for c in password):
            charset_size += 10
            types.append("digits")
        if any(c in string.punctuation for c in password):
            charset_size += 32
            types.append("special")
        return charset_size, types

    def check_dictionary(self, password):
        lower = password.lower()
        weaknesses = []
        if lower in self.common_passwords:
            return ["Common password"], len(self.common_passwords)
        for word in self.common_words:
            if word in lower:
                weaknesses.append(f"Contains '{word}'")
        return weaknesses, len(self.common_words)

    def check_patterns(self, password):
        patterns = []
        for pat in self.common_patterns:
            if re.search(pat, password.lower()):
                patterns.append(f"Pattern matched: {pat}")
        return patterns

    def calculate_entropy(self, password):
        charset_size, _ = self.get_charset_info(password)
        basic_entropy = len(password) * math.log2(charset_size) if charset_size else 0
        penalty = sum(Counter(password.lower()).values()) - len(password)
        adjusted = max(0, basic_entropy - penalty)
        return round(basic_entropy, 1), round(adjusted, 1)

    def get_strength_score(self, password):
        score = min(len(password) * 4, 40)
        charset_size, types = self.get_charset_info(password)
        score += len(types) * 10
        _, adjusted_entropy = self.calculate_entropy(password)
        score += min(adjusted_entropy / 2, 30)
        score -= len(self.check_dictionary(password)[0]) * 15
        score -= len(self.check_patterns(password)) * 10
        return max(0, min(100, int(score)))

    def analyze_password(self, password):
        charset_size, types = self.get_charset_info(password)
        weaknesses, _ = self.check_dictionary(password)
        patterns = self.check_patterns(password)
        basic, adjusted = self.calculate_entropy(password)
        score = self.get_strength_score(password)
        recommendations = self.get_recommendations(password, weaknesses, patterns, types)

        return {
            "password_length": len(password),
            "charset_size": charset_size,
            "charset_types": ', '.join(types),
            "basic_entropy": f"{basic} bits",
            "adjusted_entropy": f"{adjusted} bits",
            "dictionary_weaknesses": weaknesses,
            "patterns_found": patterns,
            "strength_score": score,
            "recommendations": recommendations
        }

    def get_recommendations(self, password, weaknesses, patterns, types):
        recs = []
        if len(password) < 12:
            recs.append("Use at least 12 characters.")
        if len(types) < 3:
            recs.append("Use a mix of uppercase, lowercase, digits, and symbols.")
        if weaknesses:
            recs.append("Avoid common or guessable words.")
        if patterns:
            recs.append("Avoid predictable sequences or repeats.")
        if not recs:
            recs.append("Password looks good! Consider using a password manager.")
            return recs

import sys

if __name__ == "__main__":
    if len(sys.argv) > 1:
        # CLI Mode
        password = sys.argv[1]
        analyzer = PasswordAnalyzer()
        result = analyzer.analyze_password(password)
        print("\nPassword Strength Report")
        print("-" * 30)
        for k, v in result.items():
            if isinstance(v, list):
                print(f"{k}:")
                for item in v:
                    print(f"  - {item}")
            else:
                print(f"{k}: {v}")
    else:
        # GUI Mode
        root = tk.Tk()
        app = PasswordAnalyzerApp(root)
        root.mainloop()

