import vt
import os

API_KEY = os.getenv("VIRUSTOTAL_API_KEY")

# Try to instantiate the VirusTotal client
client = vt.Client(API_KEY)

print("VirusTotal Client instantiated successfully.")
