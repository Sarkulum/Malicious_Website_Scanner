import os

def load_config():
    virus_total_api_key = os.getenv("VIRUSTOTAL_API_KEY")
    email_username = os.getenv("EMAIL_USERNAME")
    app_password = os.getenv("APP_PASSWORD")

    #Check if credentials loaded correctly
    if not virus_total_api_key:
        raise EnvironmentError("VIRUSTOTAL_API_KEY not found in environment variables!")
    if not email_username or not app_password:
        raise EnvironmentError("Email credentials not found in environment variables!")
    
    return virus_total_api_key, email_username, app_password