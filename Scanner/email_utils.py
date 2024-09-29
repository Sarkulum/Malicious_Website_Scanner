import imaplib
import email
import re

# Connect to Gmail
def connect_to_gmail(username, password):
    imap = imaplib.IMAP4_SSL("imap.gmail.com")
    imap.login(username, password)
    return imap

# Fetch emails from inbox
def fetch_emails(imap, folder="inbox", num_emails=10):
    imap.select(folder)
    status, messages = imap.search(None, "All")
    email_ids = messages[0].split()[-num_emails:]
    return email_ids

# Extract URL's from email using regex
def extract_urls_from_email(message):
    urls = []
    for part in message.walk():
        if part.get_content_type() == "text/plain" or part.get_content_type() == "text/html": # Get plain text or html of the Email
            body = part.get_payload(decode=True).decode() # Decode email content
            # Regex to extract URL's
            urls = re.findall(r'(https?://\S+)', body)
        return urls