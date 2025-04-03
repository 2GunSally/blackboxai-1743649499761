import argparse
import requests
from requests.auth import HTTPBasicAuth

# Kroger API credentials
CLIENT_ID = "cartgenie-42a6b98e3c54f5b92092edf53fe6ea7c8103340637182546648"
CLIENT_SECRET = "nciRwpkzfWQT_ifv9Tg6tI258lxbZ2mdi6xbEzSq"
TOKEN_URL = "https://api.kroger.com/v1/connect/oauth2/token"

def validate_client_credentials(proxy=None):
    """Validate if the client credentials are valid"""
    auth = HTTPBasicAuth(CLIENT_ID, CLIENT_SECRET)
    headers = {
        "Content-Type": "application/x-www-form-urlencoded",
        "User-Agent": "KrogerClientValidator/1.0"
    }
    data = {
        "grant_type": "client_credentials",
        "scope": "profile.compact"
    }

    try:
        response = requests.post(
            TOKEN_URL,
            auth=auth,
            headers=headers,
            data=data,
            proxies=proxy,
            timeout=15
        )
        
        if response.status_code == 200:
            return True, "Valid client credentials"
        else:
            return False, f"API Error: {response.status_code} - {response.text}"
    except Exception as e:
        return False, f"Validation error: {str(e)}"

def main():
    parser = argparse.ArgumentParser(description="Kroger Client Credentials Validator")
    parser.add_argument("-p", "--proxy", action="store_true", help="Use proxy for requests")
    
    args = parser.parse_args()
    
    is_valid, message = validate_client_credentials()
    print(f"Client credentials validation result: {message}")

if __name__ == "__main__":
    main()