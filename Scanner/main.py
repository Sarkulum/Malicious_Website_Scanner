import email
from config import load_config
from email_utils import connect_to_gmail, fetch_emails, extract_urls_from_email
from virustotal_utils import scan_url_with_virustotal, encode_url, get_virustotal_scan_results

# Import ScannerGUI from scanner_gui.py
from scanner_gui import ScannerGUI
import tkinter as tk

def start_scan(gui):
    virus_total_api_key, email_username, app_password = load_config()

    # Connect to Gmail
    imap = connect_to_gmail(email_username, app_password)

    # Fetch the latest 10 emails
    email_ids = fetch_emails(imap, num_emails=10)

    # String to accumulate all scan results
    all_results = ""

    # Iterate through emails and extract URLs
    for email_id in email_ids:
        status, data = imap.fetch(email_id, "(RFC822)")
        raw_email = data[0][1]
        message = email.message_from_bytes(raw_email)

        urls = extract_urls_from_email(message)
        if urls:
            for url in urls:
                all_results += f"Found URL: {url}\n"

                # Scan URL with VirusTotal
                scan_id = scan_url_with_virustotal(virus_total_api_key, url)

                # Get the encoded URL for scan result retrieval
                encoded = encode_url(url)

                # Get the scan results
                if scan_id:
                    all_results += f"Scanning URL with ID: {scan_id}\n"
                    results = get_virustotal_scan_results(virus_total_api_key, encoded)

                    # Extract analysis statistics
                    if results:
                        all_results += f"Scan results for {url}:\n"
                        all_results += f" - Harmless: {results['harmless']}\n"
                        all_results += f" - Malicious: {results['malicious']}\n"
                        all_results += f" - Suspicious: {results['suspicious']}\n"
                        all_results += f" - Undetected: {results['undetected']}\n"
                    else:
                        all_results += "No scan results available.\n"
                else:
                    all_results += f"Failed to scan URL: {url}\n"
        else:
            all_results += "No URLs found in this email.\n"

    # Display all results in the GUI
    gui.display_results(all_results)

    # Close the connection
    imap.logout()

def main():
    # Set up the GUI
    root = tk.Tk()
    gui = ScannerGUI(root, lambda: start_scan(gui))
    root.mainloop()

if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        print(f"An error occurred: {e}")
