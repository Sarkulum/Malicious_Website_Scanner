import requests
import base64
import vt

# The VirusTotal API Key you want to use.
API_KEY = ""

# URL to scan.
url_to_scan = "https://www.youtube.com/"

# VirusTotal needs you to encode the URL in Base64. I don't fucking know why.
encoded_url = base64.urlsafe_b64encode(url_to_scan.encode()).decode().strip("=")

# This is the URl API endpoint.
url = f"https://www.virustotal.com/api/v3/urls"

# The headers that get send to the VirusTotal API. So the application, the API Key and the Encodet URL.
headers = {
    "accept": "application/json",
    "x-apikey": API_KEY,
    "content-type": "application/x-www-form-urlencoded"
}

# POST request with the encoded URL.
response = requests.post(url, headers=headers, data=f"url={url_to_scan}")

# Print the scan response.
print("Scan response:", response.text)

# You could use the API Client to get the scan results.
client = vt.Client(API_KEY)

# The Base64-encoded URL to get the report (scan ID dosen't work)
report = client.get_object(f"/urls/{encoded_url}")

# Print analysis results
print(f"Analysis results for {url_to_scan}:")
print(report.last_analysis_stats)  # A summary of the analysis (malicious, safe, etc.)
