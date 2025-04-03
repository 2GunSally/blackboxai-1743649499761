#!/usr/bin/env python3
"""
Production Kroger OAuth2 Implementation
Using registered app credentials from cartgenie
"""

from requests.auth import HTTPBasicAuth
import requests
import webbrowser
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse, parse_qs, urlencode
from threading import Thread
import json

# Registered App Configuration
CLIENT_ID = "cartgenie-243261243034244c417a71504b73515051764a384a2e50532e7a39454f634b4c773257557971576a69374e784b6f4c64626b6b4754346846333761712748587326129489921"
CLIENT_SECRET = "r3JCQqSYNyld9A5njdTkhNDxMf86MTel50Oy4PP9"
REDIRECT_URIS = [
    "https://localhost:3000/auth/callback",
    "http://localhost:8000/auth/callback"
]
SCOPES = "product.compact profile.compact"

class OAuthHandler(BaseHTTPRequestHandler):
    auth_code = None
    
    def do_GET(self):
        query = urlparse(self.path).query
        params = parse_qs(query)
        
        if 'code' in params:
            self.auth_code = params['code'][0]
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"Authorization successful. You may close this window.")
            return
            
        self.send_response(400)
        self.end_headers()
        self.wfile.write(b"Authorization failed")

def start_server(port=8000):
    """Start callback server on available port"""
    for i in range(2):
        try:
            server = HTTPServer(('localhost', port+i), OAuthHandler)
            print(f"Callback server running on port {port+i}")
            server.handle_request()
            return port+i
        except OSError:
            continue
    raise Exception("No available ports for callback server")

def get_auth_url(redirect_uri):
    """Generate OAuth2 authorization URL"""
    params = {
        'client_id': CLIENT_ID,
        'response_type': 'code',
        'redirect_uri': redirect_uri,
        'scope': SCOPES,
        'state': 'security_token_' + str(int(time.time()))
    }
    return f"https://api.kroger.com/v1/connect/oauth2/authorize?{urlencode(params)}"

def get_access_token(code, redirect_uri):
    """Exchange authorization code for access token"""
    auth = HTTPBasicAuth(CLIENT_ID, CLIENT_SECRET)
    data = {
        'grant_type': 'authorization_code',
        'code': code,
        'redirect_uri': redirect_uri
    }
    
    response = requests.post(
        "https://api.kroger.com/v1/connect/oauth2/token",
        auth=auth,
        data=data,
        headers={'Content-Type': 'application/x-www-form-urlencoded'}
    )
    
    if response.status_code == 200:
        return response.json()
    raise Exception(f"Token exchange failed: {response.text}")

def main():
    try:
        # Start callback server
        port = 8000  # Try port 8000 first
        server_thread = Thread(target=start_server, args=(port,), daemon=True)
        server_thread.start()
        time.sleep(1)  # Allow server to start
        
        # Use the registered HTTP redirect URI
        redirect_uri = REDIRECT_URIS[1]  # Using http://localhost:8000/auth/callback
        
        # Launch authorization URL
        auth_url = get_auth_url(redirect_uri)
        print(f"Please authorize at: {auth_url}")
        webbrowser.open(auth_url)
        
        # Wait for authorization code
        while not OAuthHandler.auth_code:
            time.sleep(1)
        
        # Exchange code for token
        token_data = get_access_token(OAuthHandler.auth_code, redirect_uri)
        print("\nSuccessfully obtained access token:")
        print(json.dumps(token_data, indent=2))
        
    except Exception as e:
        print(f"Error: {str(e)}")
    finally:
        server_thread.join(timeout=1)

if __name__ == "__main__":
    main()