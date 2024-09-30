import tkinter as tk
from tkinter import scrolledtext

class ScannerGUI:
    def __init__(self, master, start_scan_callback):
        self.master = master
        self.master.title("VirusTotal URL Scanner")
        self.master.geometry("600x400")

        # Create a text box to display scan results
        self.result_box = scrolledtext.ScrolledText(self.master, wrap=tk.WORD, width=70, height=20)
        self.result_box.pack(pady=10)

        # Create a button to start the scan
        self.scan_button = tk.Button(self.master, text="Start Scan", command=start_scan_callback)
        self.scan_button.pack(pady=10)

    def display_results(self, results):
        self.result_box.insert(tk.END, results + "\n")
        self.result_box.yview(tk.END)  # Auto-scroll to the end
