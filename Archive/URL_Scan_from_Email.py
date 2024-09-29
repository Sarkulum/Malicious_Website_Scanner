import imaplib
import email
import re
import base64
import requests
import vt
import os

# Fetch credentials from environment variables
virus_total_api_key = os.getenv("VIRUSTOTAL_API_KEY")
email_username = os.getenv("EMAIL_USERNAME")
email_password = os.getenv("EMAIL_PASSWORD")

# Check if the credentials are loaded correctly
if not virus_total_api_key:
    raise EnvironmentError("VIRUSTOTAL_API_KEY not found in environment variables!")
if not email_username or not email_password:
    raise EnvironmentError("Email credentials not found in environment variables!")

print("Credentials loaded successfully")

# VirusTotal API Key
API_KEY = "virus_total_api_key"

# Connect to your Email Provider
def connect_to_gmail(username, password):
    imap = imaplib.IMAP4_SSL("imap.gmail.com")
    imap.login(username, password)
    return imap

# Fetch emails from inbox
def fetch_emails(imap, folder="inbox", num_emails=10):
    imap.select(folder)
    status, messages = imap.search(None, "ALL")
    email_ids = messages[0].split()[-num_emails:]
    return email_ids

# Extract URLs from email body using regex
def extract_urls_from_email(message):
    urls = []
    for part in message.walk():
        if part.get_content_type() == "text/plain":  # Plain text part of the email
            body = part.get_payload(decode=True).decode()  # Decode the email content
            # Regex to match URLs
            urls = re.findall(r'(https?://\S+)', body)
    return urls

# Scan URL using VirusTotal
def scan_url_with_virustotal(url):
    # Base64 encode the URL (bause the API wants it like that)
    encoded_url = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
    
    # VirusTotal URL scanning
    vt_url = "https://www.virustotal.com/api/v3/urls"
    headers = {
        "accept": "application/json",
        "x-apikey": API_KEY,
        "content-type": "application/x-www-form-urlencoded"
    }
    
    # Send the URL to VirusTotal
    response = requests.post(vt_url, headers=headers, data=f"url={url}")
    
    if response.status_code == 200:
        result = response.json()
        scan_id = result["data"]["id"]
        return scan_id, encoded_url
    else:
        print(f"Error scanning URL: {response.status_code}")
        return None, None

# Retrieve scan results from VirusTotal
def get_virustotal_scan_results(client, encoded_url):
    report = client.get_object(f"/urls/{encoded_url}")
    return report.last_analysis_stats

# Main program to extract and scan URLs from emails
def main():
    # Your Gmail credentials
    username = "email_username"
    password = "email_password"
    
    # Connect to Gmail
    imap = connect_to_gmail(username, password)
    
    # Fetch the latest 10 emails
    email_ids = fetch_emails(imap, num_emails=10)
    
    # VirusTotal client
    client = vt.Client(API_KEY)
    
    # Iterate through emails and extract URLs
    for email_id in email_ids:
        status, data = imap.fetch(email_id, "(RFC822)")
        raw_email = data[0][1]
        message = email.message_from_bytes(raw_email)
        
        urls = extract_urls_from_email(message)
        if urls:
            for url in urls:
                print(f"Found URL: {url}")
                
                # Scan URL with VirusTotal
                scan_id, encoded_url = scan_url_with_virustotal(url)
                
                # Get the scan results
                if scan_id:
                    print(f"Scanning URL with ID: {scan_id}")
                    results = get_virustotal_scan_results(client, encoded_url)
                    print(f"Scan results for {url}: {results}")
        else:
            print("No URLs found in this email.")
    
    # Close the connection
    imap.logout()

if __name__ == "__main__":
    main()
