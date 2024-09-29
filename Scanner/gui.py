import tkinter as tk
import os
import subprocess

def save_credentials():
    # Get user inputs from entry fields
    virustotal_api = virustotal_entry.get()
    gmail_account = gmail_entry.get()
    app_password = app_password_entry.get()

    # Use setx to set permanent environment variables
    subprocess.run(['setx', 'VIRUSTOTAL_API_KEY', virustotal_api])
    subprocess.run(['setx', 'EMAIL_USERNAME', gmail_account])
    subprocess.run(['setx', 'APP_PASSWORD', app_password])

    # Saved successful message
    status_label.config(text="Credentials saved successfully! Please restart any open command windows.", fg="green")

# Create main window
window = tk.Tk()
window.title("Email Scanner - Credential Setup")
window.geometry("400x250")

# Create labels and input fields
virustotal_label = tk.Label(window, text="VirusTotal API Key:")
virustotal_label.pack(pady=5)
virustotal_entry = tk.Entry(window, width=50)
virustotal_entry.pack()

gmail_label = tk.Label(window, text="Gmail Account:")
gmail_label.pack(pady=5)
gmail_entry = tk.Entry(window, width=50)
gmail_entry.pack()

app_password_label = tk.Label(window, text="App Password:")
app_password_label.pack(pady=5)
app_password_entry = tk.Entry(window, width=50, show="*")
app_password_entry.pack()

# Save button
save_button = tk.Button(window, text="Save", command=save_credentials)
save_button.pack(pady=20)

# Status to show confirmation
status_label = tk.Label(window, text="")
status_label.pack()

# Run the GUI loop
window.mainloop()
