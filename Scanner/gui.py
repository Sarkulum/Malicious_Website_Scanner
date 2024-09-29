import tkinter as tk
import os

def save_credentials():
    # Get user inputs from entry fields
    virustotal_api = virustotal_entry.get()
    gmail_account = gmail_entry.get()
    app_password = app_password_entry.get()

    # Save input as os variables
    os.environ["VIRUSTOTAL_API_KEY"] = virustotal_api
    os.environ["EMAIL_USERNAME"] = gmail_account
    os.environ["APP_PASSWORD"] = app_password

    # Saved successfull message
    status_label.config(text="Credentials saved successfully!", fg="green")

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
