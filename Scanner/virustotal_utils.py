import requests
import base64

# Base64 encode te URL's (because of VirusTotal bs)
def encode_url(url):
    return base64.urlsafe_b64encode(url.encode()).decode().strip("=")

# Submit URL's to VirusTotal to scan
def scan_url_with_virustotal(api_key, url):
    vt_url = "https://www.virustotal.com/api/v3/urls"
    headers = {
        "accept": "application/jason",
        "x-apikey": api_key,
        "content-type": "application/x-www-form-urlencoded"
    }

    response = requests.post(vt_url, headers=headers, data=f"url={url}")

    if response.status_code == 200:
        result = response.json()
        scan_id = result["data"]["id"]
        return scan_id
    else:
        print(f"Error scanning URL: {response.status_code}, Response: {response.text}")
        return None
    
# Retrieve scan results from VirusTotal (don't use scan id, that dose not work)
def get_virustotal_scan_results(api_key, encoded_url):
    vt_url = f"https://www.virustotal.com/api/v3/urls/{encoded_url}"
    headers = {
        "accept": "application/json",
        "x-apikey": api_key
    }

    response = requests.get(vt_url, headers=headers)

    if response.status_code == 200:
        result = response.json()
        return result["data"]["attributes"]["last_analysis_stats"]
    else:
        print(f"Error retrieving scan results: {response.status_code}, Response: {response.text}")
        return None