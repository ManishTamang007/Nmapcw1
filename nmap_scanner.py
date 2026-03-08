import tkinter as tk
from tkinter import scrolledtext, messagebox
import nmap
import threading
import socket
import re


class NmapScanner:

    def __init__(self, root):
        self.root = root
        self.root.title("Nmap GUI Scanner")
        self.root.geometry("750x600")
        self.root.resizable(True, True)
        self.root.configure(bg="#1e1e2e")

        self.scanner = nmap.PortScanner()
        self.scan_running = False

        self.create_widgets()

    def create_widgets(self):

        title = tk.Label(
            self.root,
            text="Nmap GUI Network Scanner",
            font=("Courier", 18, "bold"),
            fg="#89dceb",
            bg="#1e1e2e"
        )
        title.pack(pady=(15, 5))

        subtitle = tk.Label(
            self.root,
            text="For Educational / Authorized Use Only",
            font=("Courier", 9),
            fg="#f38ba8",
            bg="#1e1e2e"
        )
        subtitle.pack(pady=(0, 10))

        frame = tk.Frame(self.root, bg="#313244", pady=12, padx=20)
        frame.pack(fill="x", padx=20)

        tk.Label(
            frame, text="Target IP / Domain:",
            font=("Courier", 10, "bold"),
            fg="#cdd6f4", bg="#313244"
        ).grid(row=0, column=0, padx=10, pady=5, sticky="w")

        self.target_entry = tk.Entry(
            frame, width=30,
            font=("Courier", 10),
            bg="#45475a", fg="#cdd6f4",
            insertbackground="#cdd6f4",
            relief="flat", bd=5
        )
        self.target_entry.grid(row=0, column=1, padx=10, pady=5)

        tk.Label(
            frame, text="Scan Type:",
            font=("Courier", 10, "bold"),
            fg="#cdd6f4", bg="#313244"
        ).grid(row=1, column=0, padx=10, pady=5, sticky="w")

        self.scan_type = tk.StringVar(value="Quick Scan")

        options = [
            "Quick Scan",
            "Port Scan (1-1024)",
            "Full Port Scan (1-65535)",
            "OS Detection",
            "Service Version",
            "Aggressive Scan"
        ]

        menu = tk.OptionMenu(frame, self.scan_type, *options)
        menu.config(
            font=("Courier", 10),
            bg="#45475a", fg="#cdd6f4",
            activebackground="#585b70",
            relief="flat", bd=0, width=22
        )
        menu["menu"].config(
            font=("Courier", 10),
            bg="#45475a", fg="#cdd6f4",
            activebackground="#89b4fa"
        )
        menu.grid(row=1, column=1, padx=10, pady=5, sticky="w")

        tk.Label(
            frame, text="Custom Arguments:",
            font=("Courier", 10, "bold"),
            fg="#cdd6f4", bg="#313244"
        ).grid(row=2, column=0, padx=10, pady=5, sticky="w")

        self.custom_args = tk.Entry(
            frame, width=30,
            font=("Courier", 10),
            bg="#45475a", fg="#a6e3a1",
            insertbackground="#a6e3a1",
            relief="flat", bd=5
        )
        self.custom_args.insert(0, "Optional (e.g. -sS -T4)")
        self.custom_args.bind("<FocusIn>", self._clear_placeholder)
        self.custom_args.bind("<FocusOut>", self._restore_placeholder)
        self.custom_args.grid(row=2, column=1, padx=10, pady=5)

        btn_frame = tk.Frame(self.root, bg="#1e1e2e")
        btn_frame.pack(pady=8)

        self.scan_btn = tk.Button(
            btn_frame, text="▶  Start Scan",
            command=self.start_scan,
            font=("Courier", 11, "bold"),
            bg="#89b4fa", fg="#1e1e2e",
            activebackground="#74c7ec",
            relief="flat", padx=16, pady=6, cursor="hand2"
        )
        self.scan_btn.grid(row=0, column=0, padx=8)

        clear_btn = tk.Button(
            btn_frame, text="✕  Clear",
            command=self.clear_results,
            font=("Courier", 11),
            bg="#45475a", fg="#cdd6f4",
            activebackground="#585b70",
            relief="flat", padx=16, pady=6, cursor="hand2"
        )
        clear_btn.grid(row=0, column=1, padx=8)

        self.status_var = tk.StringVar(value="Ready")
        self.status_label = tk.Label(
            self.root,
            textvariable=self.status_var,
            font=("Courier", 9),
            fg="#a6e3a1", bg="#1e1e2e"
        )
        self.status_label.pack()

        self.result_box = scrolledtext.ScrolledText(
            self.root,
            width=88, height=18,
            font=("Courier", 9),
            bg="#11111b", fg="#cdd6f4",
            insertbackground="#cdd6f4",
            relief="flat", bd=10,
            state="normal"
        )
        self.result_box.pack(padx=20, pady=(4, 15), fill="both", expand=True)

        self.result_box.tag_config("header",  foreground="#89dceb", font=("Courier", 9, "bold"))
        self.result_box.tag_config("host",    foreground="#a6e3a1", font=("Courier", 9, "bold"))
        self.result_box.tag_config("port",    foreground="#fab387")
        self.result_box.tag_config("error",   foreground="#f38ba8")
        self.result_box.tag_config("warning", foreground="#f9e2af")
        self.result_box.tag_config("normal",  foreground="#cdd6f4")

    def _clear_placeholder(self, event):
        if self.custom_args.get() == "Optional (e.g. -sS -T4)":
            self.custom_args.delete(0, tk.END)

    def _restore_placeholder(self, event):
        if not self.custom_args.get().strip():
            self.custom_args.insert(0, "Optional (e.g. -sS -T4)")

    def validate_target(self, target):
        """Return True if target looks like a valid IP or hostname."""
        ip_pattern = re.compile(
            r"^(\d{1,3}\.){3}\d{1,3}(/\d{1,2})?$"
        )
        if ip_pattern.match(target):
            return True
        hostname_pattern = re.compile(
            r"^(?:[a-zA-Z0-9\-]+\.)+[a-zA-Z]{2,}$|^localhost$"
        )
        if hostname_pattern.match(target):
            return True
        return False

    def safe_insert(self, text, tag="normal"):
        self.root.after(0, self._do_insert, text, tag)

    def _do_insert(self, text, tag):
        self.result_box.insert(tk.END, text, tag)
        self.result_box.see(tk.END)

    def set_status(self, text, color="#a6e3a1"):
        self.root.after(0, self._do_status, text, color)

    def _do_status(self, text, color):
        self.status_var.set(text)
        self.status_label.config(fg=color)

    def start_scan(self):
        if self.scan_running:
            messagebox.showwarning("Busy", "A scan is already running. Please wait.")
            return

        target = self.target_entry.get().strip()

        if not target:
            messagebox.showerror("Input Error", "Please enter a target IP or domain.")
            return

        if not self.validate_target(target):
            messagebox.showerror(
                "Invalid Target",
                f"'{target}' does not look like a valid IP address or hostname."
            )
            return

        self.scan_running = True
        self.scan_btn.config(state="disabled", bg="#585b70")
        thread = threading.Thread(target=self.run_scan, daemon=True)
        thread.start()

    def clear_results(self):
        self.result_box.delete(1.0, tk.END)
        self.set_status("Ready")

    def run_scan(self):
        target     = self.target_entry.get().strip()
        scan_type  = self.scan_type.get()
        custom     = self.custom_args.get().strip()
        use_custom = custom and custom != "Optional (e.g. -sS -T4)"

        self.root.after(0, self.result_box.delete, 1.0, tk.END)
        self.safe_insert(f"{'='*60}\n", "header")
        self.safe_insert(f"  Target   : {target}\n", "header")
        self.safe_insert(f"  Scan Type: {scan_type}\n", "header")
        self.safe_insert(f"{'='*60}\n\n", "header")
        self.set_status("Scanning…", "#f9e2af")

        try:
            resolved = socket.gethostbyname(target)
            if resolved != target:
                self.safe_insert(f"Resolved: {target} → {resolved}\n\n", "normal")
        except socket.gaierror:
            self.safe_insert(f"Warning: Could not resolve hostname '{target}'\n\n", "warning")

        try:
            if use_custom:
                arguments = custom
                self.safe_insert(f"Using custom arguments: {arguments}\n\n", "warning")
            elif scan_type == "Quick Scan":
                arguments = "-F -T4"
            elif scan_type == "Port Scan (1-1024)":
                arguments = "-p 1-1024 -T4"
            elif scan_type == "Full Port Scan (1-65535)":
                arguments = "-p- -T4"
                self.safe_insert(
                    "Note: Full port scan may take several minutes.\n\n", "warning"
                )
            elif scan_type == "OS Detection":
                arguments = "-O"
                self.safe_insert(
                    "Note: OS Detection requires administrator/root privileges.\n\n",
                    "warning"
                )
            elif scan_type == "Service Version":
                arguments = "-sV -T4"
            elif scan_type == "Aggressive Scan":
                arguments = "-A -T4"
                self.safe_insert(
                    "Note: Aggressive scan (-A) requires root on some systems.\n\n",
                    "warning"
                )

            self.scanner.scan(target, arguments=arguments)
            hosts = self.scanner.all_hosts()
            if not hosts:
                self.safe_insert(
                    "No hosts found. The target may be offline or blocking probes.\n",
                    "error"
                )
            else:
                for host in hosts:
                    self.safe_insert(f"Host  : {host}\n", "host")
                    hostname_list = self.scanner[host].hostname()
                    if hostname_list:
                        self.safe_insert(f"Name  : {hostname_list}\n", "host")
                    self.safe_insert(
                        f"State : {self.scanner[host].state()}\n\n", "host"
                    )
                    if "osmatch" in self.scanner[host]:
                        os_matches = self.scanner[host]["osmatch"]
                        if os_matches:
                            self.safe_insert("OS Detection Results:\n", "header")
                            for os in os_matches[:3]:           # top 3 matches
                                self.safe_insert(
                                    f"  {os['name']}  (accuracy: {os['accuracy']}%)\n",
                                    "normal"
                                )
                            self.safe_insert("\n", "normal")
                    for proto in self.scanner[host].all_protocols():
                        self.safe_insert(
                            f"Protocol : {proto.upper()}\n", "header"
                        )
                        self.safe_insert(
                            f"{'PORT':<10}{'STATE':<12}{'SERVICE':<18}{'VERSION'}\n",
                            "header"
                        )
                        self.safe_insert("-" * 55 + "\n", "header")

                        ports = sorted(self.scanner[host][proto].keys())
                        for port in ports:
                            port_info = self.scanner[host][proto][port]
                            state   = port_info.get("state",   "")
                            service = port_info.get("name",    "")
                            version = port_info.get("version", "")
                            product = port_info.get("product", "")

                            full_version = f"{product} {version}".strip()
                            line = f"{port:<10}{state:<12}{service:<18}{full_version}\n"
                            self.safe_insert(line, "port")

                    self.safe_insert("\n", "normal")

            self.safe_insert(f"{'='*60}\n", "header")
            self.safe_insert("Scan complete.\n", "header")
            self.set_status("Scan complete ✓", "#a6e3a1")

        except nmap.PortScannerError as e:
            self.safe_insert(
                f"Nmap Error: {str(e)}\n"
                "Make sure nmap is installed on your system.\n",
                "error"
            )
            self.set_status("Error", "#f38ba8")

        except Exception as e:
            self.safe_insert(f"Unexpected Error: {str(e)}\n", "error")
            self.set_status("Error", "#f38ba8")

        finally:
            self.scan_running = False
            self.root.after(0, self.scan_btn.config, {"state": "normal", "bg": "#89b4fa"})


if __name__ == "__main__":
    root = tk.Tk()
    app  = NmapScanner(root)
    root.mainloop()