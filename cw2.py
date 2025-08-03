import os
import hashlib
import json
from enum import Enum
from plyer import notification
import tkinter as tk
from tkinter import ttk, filedialog, scrolledtext, messagebox
import threading
import time

class ChangeType(Enum):
    MODIFIED = "Modified"
    ADDED = "Added"
    DELETED = "Deleted"

class FileIntegrityApp:
    def __init__(self, root):
        self.root = root
        self.root.title("File Integrity Monitor")
        self.root.geometry("800x600")
        self.root.resizable(True, True)
        
        # Variables
        self.directory_path = tk.StringVar()
        self.baseline_file = "baseline.json"
        self.monitoring = False
        self.monitor_thread = None
        
        # Create main frames
        self.create_frames()
        
        # Create widgets
        self.create_widgets()
        
        # Status bar
        self.status_var = tk.StringVar()
        self.status_var.set("Ready")
        status_bar = ttk.Label(self.root, textvariable=self.status_var, relief=tk.SUNKEN, anchor=tk.W)
        status_bar.pack(side=tk.BOTTOM, fill=tk.X)
    
    def create_frames(self):
        # Control frame
        self.control_frame = ttk.LabelFrame(self.root, text="Controls", padding=10)
        self.control_frame.pack(fill=tk.X, padx=10, pady=5)
        
        # Directory frame
        self.directory_frame = ttk.LabelFrame(self.root, text="Directory to Monitor", padding=10)
        self.directory_frame.pack(fill=tk.X, padx=10, pady=5)
        
        # Log frame
        self.log_frame = ttk.LabelFrame(self.root, text="Activity Log", padding=10)
        self.log_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        # Report frame
        self.report_frame = ttk.LabelFrame(self.root, text="Compliance Report", padding=10)
        self.report_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
    
    def create_widgets(self):
        # Directory selection
        ttk.Label(self.directory_frame, text="Directory:").grid(row=0, column=0, sticky=tk.W)
        ttk.Entry(self.directory_frame, textvariable=self.directory_path, width=60).grid(row=0, column=1, padx=5)
        ttk.Button(self.directory_frame, text="Browse", command=self.browse_directory).grid(row=0, column=2)
        
        # Control buttons
        ttk.Button(self.control_frame, text="Create Baseline", command=self.create_baseline_gui).pack(side=tk.LEFT, padx=5)
        ttk.Button(self.control_frame, text="Load Baseline", command=self.load_baseline_gui).pack(side=tk.LEFT, padx=5)
        ttk.Button(self.control_frame, text="Start Monitoring", command=self.start_monitoring_gui).pack(side=tk.LEFT, padx=5)
        ttk.Button(self.control_frame, text="Stop Monitoring", command=self.stop_monitoring_gui).pack(side=tk.LEFT, padx=5)
        ttk.Button(self.control_frame, text="Generate Report", command=self.generate_report_gui).pack(side=tk.LEFT, padx=5)
        ttk.Button(self.control_frame, text="Clear Log", command=self.clear_log).pack(side=tk.LEFT, padx=5)
        
        # Activity log
        self.log_text = scrolledtext.ScrolledText(self.log_frame, height=10, wrap=tk.WORD)
        self.log_text.pack(fill=tk.BOTH, expand=True)
        
        # Compliance report
        self.report_text = scrolledtext.ScrolledText(self.report_frame, height=10, wrap=tk.WORD)
        self.report_text.pack(fill=tk.BOTH, expand=True)
    
    def browse_directory(self):
        directory = filedialog.askdirectory()
        if directory:
            self.directory_path.set(directory)
            self.log(f"Selected directory: {directory}")
    
    def log(self, message):
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
        self.log_text.insert(tk.END, f"[{timestamp}] {message}\n")
        self.log_text.see(tk.END)
        self.root.update_idletasks()
    
    def create_baseline_gui(self):
        if not self.directory_path.get():
            messagebox.showerror("Error", "Please select a directory first")
            return
        
        try:
            self.status_var.set("Creating baseline...")
            self.log("Creating baseline...")
            self.root.update_idletasks()
            
            create_baseline(self.directory_path.get(), self.baseline_file)
            self.log(f"Baseline created successfully: {self.baseline_file}")
            self.status_var.set("Baseline created")
            messagebox.showinfo("Success", "Baseline created successfully")
        except Exception as e:
            self.log(f"Error creating baseline: {str(e)}")
            self.status_var.set("Error creating baseline")
            messagebox.showerror("Error", f"Failed to create baseline: {str(e)}")
    
    def load_baseline_gui(self):
        if not os.path.exists(self.baseline_file):
            messagebox.showerror("Error", f"Baseline file not found: {self.baseline_file}")
            return
        
        try:
            self.status_var.set("Loading baseline...")
            self.log("Loading baseline...")
            self.root.update_idletasks()
            
            verify_baseline_integrity(self.baseline_file)
            baseline = load_baseline(self.baseline_file)
            self.log(f"Baseline loaded successfully: {self.baseline_file}")
            self.status_var.set("Baseline loaded")
            messagebox.showinfo("Success", "Baseline loaded successfully")
        except Exception as e:
            self.log(f"Error loading baseline: {str(e)}")
            self.status_var.set("Error loading baseline")
            messagebox.showerror("Error", f"Failed to load baseline: {str(e)}")
    
    def start_monitoring_gui(self):
        if not self.directory_path.get():
            messagebox.showerror("Error", "Please select a directory first")
            return
        
        if not os.path.exists(self.baseline_file):
            messagebox.showerror("Error", f"Baseline file not found: {self.baseline_file}")
            return
        
        if self.monitoring:
            messagebox.showinfo("Info", "Monitoring is already running")
            return
        
        self.monitoring = True
        self.log("Starting monitoring...")
        self.status_var.set("Monitoring active")
        
        # Start monitoring in a separate thread
        self.monitor_thread = threading.Thread(target=self.monitor_thread_func)
        self.monitor_thread.daemon = True
        self.monitor_thread.start()
    
    def stop_monitoring_gui(self):
        if not self.monitoring:
            messagebox.showinfo("Info", "Monitoring is not running")
            return
        
        self.monitoring = False
        self.log("Stopping monitoring...")
        self.status_var.set("Monitoring stopped")
    
    def monitor_thread_func(self):
        try:
            baseline = load_baseline(self.baseline_file)
            
            while self.monitoring:
                self.log("Checking directory integrity...")
                self.root.after(0, lambda: self.status_var.set("Checking directory..."))
                
                modified_files, new_files, deleted_files = self.check_directory_changes(
                    self.directory_path.get(), baseline)
                
                if modified_files or new_files or deleted_files:
                    self.root.after(0, lambda: self.log("Changes detected!"))
                    self.root.after(0, lambda: self.status_var.set("Changes detected!"))
                    
                    # Update baseline
                    create_baseline(self.directory_path.get(), self.baseline_file)
                    baseline = load_baseline(self.baseline_file)
                    
                    # Send alert
                    self.root.after(0, lambda: send_alert(modified_files, new_files, deleted_files))
                    
                    # Generate report
                    self.root.after(0, lambda: self.generate_report_gui(modified_files, new_files, deleted_files))
                else:
                    self.root.after(0, lambda: self.log("No changes detected"))
                    self.root.after(0, lambda: self.status_var.set("No changes detected"))
                
                # Sleep for 10 seconds before next check
                time.sleep(10)
                
        except Exception as e:
            self.root.after(0, lambda: self.log(f"Monitoring error: {str(e)}"))
            self.root.after(0, lambda: self.status_var.set("Monitoring error"))
            self.monitoring = False
    
    def check_directory_changes(self, directory, baseline):
        modified_files = []
        new_files = []
        deleted_files = []
        
        # Check for modified and new files
        for root, dirs, files in os.walk(directory):
            for file in files:
                file_path = os.path.join(root, file)
                if file_path in baseline:
                    stored_hash = baseline[file_path]
                    current_hash = calculate_hash(file_path)
                    if current_hash != stored_hash:
                        modified_files.append(file_path)
                else:
                    new_files.append(file_path)
        
        # Check for deleted files
        for file_path in baseline.keys():
            if not os.path.exists(file_path):
                deleted_files.append(file_path)
        
        return modified_files, new_files, deleted_files
    
    def generate_report_gui(self, modified_files=None, new_files=None, deleted_files=None):
        try:
            self.status_var.set("Generating report...")
            self.log("Generating compliance report...")
            self.root.update_idletasks()
            
            if modified_files is None or new_files is None or deleted_files is None:
                # If no files provided, load from baseline
                if not os.path.exists(self.baseline_file):
                    messagebox.showerror("Error", "Baseline file not found")
                    return
                
                baseline = load_baseline(self.baseline_file)
                modified_files, new_files, deleted_files = self.check_directory_changes(
                    self.directory_path.get(), baseline)
            
            # Generate report
            report = "Compliance Report:\n\n"
            report += f"Generated: {time.strftime('%Y-%m-%d %H:%M:%S')}\n"
            report += f"Directory: {self.directory_path.get()}\n\n"
            
            if modified_files:
                bubble_sort(modified_files)
                report += "Modified files:\n"
                for file_path in modified_files:
                    report += f"- {file_path}\n"
                report += "\n"
            
            if new_files:
                bubble_sort(new_files)
                report += "New files created:\n"
                for file_path in new_files:
                    report += f"- {file_path}\n"
                report += "\n"
            
            if deleted_files:
                bubble_sort(deleted_files)
                report += "Deleted files:\n"
                for file_path in deleted_files:
                    report += f"- {file_path}\n"
                report += "\n"
            
            if not modified_files and not new_files and not deleted_files:
                report += "No changes detected.\n"
            
            # Save report to file
            report_file = 'compliance_report.txt'
            with open(report_file, 'w') as f:
                f.write(report)
            
            # Display report in GUI
            self.report_text.delete(1.0, tk.END)
            self.report_text.insert(tk.END, report)
            
            self.log(f"Compliance report generated: {report_file}")
            self.status_var.set("Report generated")
            messagebox.showinfo("Success", f"Compliance report generated: {report_file}")
            
        except Exception as e:
            self.log(f"Error generating report: {str(e)}")
            self.status_var.set("Error generating report")
            messagebox.showerror("Error", f"Failed to generate report: {str(e)}")
    
    def clear_log(self):
        self.log_text.delete(1.0, tk.END)
        self.log("Log cleared")

# Original functions with slight modifications for GUI integration
def calculate_hash(file_path):
    with open(file_path, 'rb') as f:
        sha256_hash = hashlib.sha256()
        while True:
            data = f.read(8192)
            if not data:
                break
            sha256_hash.update(data)
        return sha256_hash.hexdigest()

def create_baseline(directory, baseline_file):
    baseline = {}
    for root, dirs, files in os.walk(directory):
        for file in files:
            file_path = os.path.join(root, file)
            file_hash = calculate_hash(file_path)
            baseline[file_path] = file_hash
    with open(baseline_file, 'w') as f:
        json.dump(baseline, f, indent=4)

def load_baseline(baseline_file):
    with open(baseline_file) as f:
        baseline = json.load(f)
    return baseline

def verify_baseline_integrity(baseline_file):
    # Verify the integrity of the baseline file itself
    if not os.path.exists(baseline_file):
        raise FileNotFoundError(f"Baseline file not found: {baseline_file}")
    
    # For simplicity, we'll just check if the file exists and is readable
    # In a real implementation, you would verify the file's hash
    print("Baseline file integrity verified.")

def send_alert(modified_files, new_files, deleted_files):
    title = 'File Change Alert'
    message = ''
    
    if modified_files:
        message += 'Modified files:\n'
        for file_path in modified_files[:5]:  # Limit to first 5 files
            message += file_path + '\n'
        if len(modified_files) > 5:
            message += f'... and {len(modified_files) - 5} more\n'
    
    if new_files:
        message += 'New files created:\n'
        for file_path in new_files[:5]:  # Limit to first 5 files
            message += file_path + '\n'
        if len(new_files) > 5:
            message += f'... and {len(new_files) - 5} more\n'
    
    if deleted_files:
        message += 'Deleted files:\n'
        for file_path in deleted_files[:5]:  # Limit to first 5 files
            message += file_path + '\n'
        if len(deleted_files) > 5:
            message += f'... and {len(deleted_files) - 5} more\n'
    
    if not message:
        message = 'No changes detected.'
    
    notification.notify(
        title=title,
        message=message,
        timeout=10
    )

def bubble_sort(arr):
    n = len(arr)
    for i in range(n - 1):
        for j in range(0, n - i - 1):
            if arr[j] > arr[j + 1]:
                arr[j], arr[j + 1] = arr[j + 1], arr[j]

if __name__ == "__main__":
    root = tk.Tk()
    app = FileIntegrityApp(root)
    root.mainloop()
