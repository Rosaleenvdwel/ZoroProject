

import os
import json
import logging
import requests
import shutil
from cryptography.fernet import Fernet
from typing import Optional, Dict, Any, Union
from pathlib import Path
from urllib.parse import urljoin

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class IPFSClient:
    
    
    def __init__(self, host: str = '127.0.0.1', port: int = 5001, encryption_key: Optional[bytes] = None):
        
        self.api_url = f'http://{host}:{port}/api/v0/'
        self.host = host
        self.port = port
        self.encryption_key = encryption_key
        self.cipher_suite = Fernet(encryption_key) if encryption_key else None
        
        # Ensure we can connect to the IPFS daemon
        try:
            response = self._make_request('id')
            logger.info(f"Connected to IPFS daemon at {self.api_url}")
            logger.info(f"IPFS Node ID: {response.get('ID', 'Unknown')}")
            self.node_id = response.get('ID', 'Unknown')
        except Exception as e:
            logger.error(f"Failed to connect to IPFS daemon: {e}")
            raise Exception(f"Failed to connect to IPFS daemon at {self.api_url}. Is the daemon running?")
    
    def _make_request(self, endpoint: str, method: str = 'post', 
                files = None, params = None, data = None) -> Dict[str, Any]:
        
        url = urljoin(self.api_url, endpoint)
        
        try:
            if method.lower() == 'get':
                response = requests.get(url, params=params)
            else:
                response = requests.post(url, files=files, params=params, data=data)
                
            response.raise_for_status()
            
            # Handle both JSON and non-JSON responses
            if response.headers.get('Content-Type', '').startswith('application/json'):
                return response.json()
            else:
                return {'raw_content': response.content}
                
        except requests.RequestException as e:
            logger.error(f"IPFS API request error for {endpoint}: {e}")
            raise Exception(f"IPFS API request failed: {e}")
    
    def add_file(self, file_path: str) -> str:
        
        if not os.path.exists(file_path):
            logger.error(f"File not found: {file_path}")
            raise FileNotFoundError(f"File not found: {file_path}")
            
        try:
            # Add the file to IPFS using the /add endpoint
            logger.info(f"Adding file to IPFS: {file_path}")
            with open(file_path, 'rb') as file_content:
                files = {'file': file_content}
                result = self._make_request('add', files=files, params={'pin': 'true'})
                
            ipfs_hash = result.get('Hash')
            if not ipfs_hash:
                raise Exception(f"IPFS add operation did not return a hash. Response: {result}")
                
            logger.info(f"File added to IPFS with hash: {ipfs_hash}")
            return ipfs_hash
        except Exception as e:
            logger.error(f"Error adding file to IPFS: {e}")
            raise Exception(f"Error adding file to IPFS: {e}")
    
    def get_file(self, ipfs_hash: str, output_path: str) -> bool:
        
        try:
            # Create the directory for the output file 
            os.makedirs(os.path.dirname(output_path), exist_ok=True)
            
            # Get the file from IPFS using the /cat endpoint
            logger.info(f"Retrieving file from IPFS: {ipfs_hash} to {output_path}")
            
            # Use streaming to handle potentially large files
            url = urljoin(self.api_url, 'cat')
            params = {'arg': ipfs_hash}
            
            with requests.post(url, params=params, stream=True) as r:
                r.raise_for_status()
                with open(output_path, 'wb') as f:
                    for chunk in r.iter_content(chunk_size=8192): 
                        f.write(chunk)
            
            logger.info(f"File retrieved successfully from IPFS to {output_path}")
            return True
        except Exception as e:
            logger.error(f"Error retrieving file from IPFS: {e}")
            raise Exception(f"Error retrieving file from IPFS: {e}")
    
    def encrypt_and_add_file(self, file_path: str) -> str:
        
        if not self.encryption_key:
            raise ValueError("No encryption key provided. Cannot encrypt file.")
            
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"File not found: {file_path}")
        
        temp_encrypted_path = f"{file_path}.encrypted"
        try:
            # Read the file content
            with open(file_path, 'rb') as f:
                file_data = f.read()
                
            # Encrypt the content
            try:
                encrypted_data = self.cipher_suite.encrypt(file_data)
            except Exception as e:
                logger.error(f"Error encrypting file: {e}")
                raise Exception(f"Error encrypting file: {e}")
                
            # Write the encrypted content to a temporary file
            with open(temp_encrypted_path, 'wb') as f:
                f.write(encrypted_data)
                
            # Add the encrypted file to IPFS
            ipfs_hash = self.add_file(temp_encrypted_path)
            
            logger.info(f"File encrypted and added to IPFS with hash: {ipfs_hash}")
            return ipfs_hash
            
        except Exception as e:
            logger.error(f"Error encrypting and adding file to IPFS: {e}")
            raise Exception(f"Error encrypting and adding file to IPFS: {e}")
        finally:
            # Clean up the temporary file
            if os.path.exists(temp_encrypted_path):
                os.remove(temp_encrypted_path)
                logger.debug(f"Removed temporary encrypted file: {temp_encrypted_path}")
    
    def get_and_decrypt_file(self, ipfs_hash: str, output_path: str) -> bool:
        
        if not self.encryption_key:
            raise ValueError("No encryption key provided. Cannot decrypt file.")
            
        try:
            # Create a temporary file for the encrypted content
            temp_encrypted_path = f"{output_path}.encrypted"
            
            # Get the encrypted file from IPFS
            self.get_file(ipfs_hash, temp_encrypted_path)
            
            # Read the encrypted content
            with open(temp_encrypted_path, 'rb') as f:
                encrypted_data = f.read()
                
            # Decrypt the content
            try:
                decrypted_data = self.cipher_suite.decrypt(encrypted_data)
            except Exception as e:
                logger.error(f"Error decrypting file: {e}")
                raise Exception(f"Error decrypting file: {e}")
                
            # Write the decrypted content to the output path
            with open(output_path, 'wb') as f:
                f.write(decrypted_data)
                
            # Clean up the temporary file
            os.remove(temp_encrypted_path)
            
            return True
        except Exception as e:
            logger.error(f"Error retrieving and decrypting file from IPFS: {e}")
            if os.path.exists(temp_encrypted_path):
                os.remove(temp_encrypted_path)
            raise Exception(f"Error retrieving and decrypting file from IPFS: {e}")
    
    def close(self):
        
        logger.info("IPFS client connection closed (no-op with requests)")

