
import hashlib
import json
import time
import os
import logging
import threading
import datetime
from typing import List, Dict, Any, Optional, Union

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class Block:
    
    def __init__(self, index: int, timestamp: float, transactions: List[Dict[str, Any]], 
                 previous_hash: str, nonce: int = 0):
        
        self.index = index
        self.timestamp = timestamp
        self.transactions = transactions
        self.previous_hash = previous_hash
        self.nonce = nonce
        self.hash = self.calculate_hash()
    
    def calculate_hash(self) -> str:
        
        block_string = json.dumps({
            "index": self.index,
            "timestamp": self.timestamp,
            "transactions": self.transactions,
            "previous_hash": self.previous_hash,
            "nonce": self.nonce
        }, sort_keys=True).encode()
        
        return hashlib.sha256(block_string).hexdigest()
    
    def mine_block(self, difficulty: int) -> None:
        
        target = "0" * difficulty
        
        while self.hash[:difficulty] != target:
            self.nonce += 1
            self.hash = self.calculate_hash()
        
        logger.info(f"Block mined: {self.hash}")
    
    def to_dict(self) -> Dict[str, Any]:
        
        return {
            "index": self.index,
            "timestamp": self.timestamp,
            "transactions": self.transactions,
            "previous_hash": self.previous_hash,
            "nonce": self.nonce,
            "hash": self.hash
        }
    
    @classmethod
    def from_dict(cls, block_dict: Dict[str, Any]) -> 'Block':
        
        block = cls(
            block_dict["index"],
            block_dict["timestamp"],
            block_dict["transactions"],
            block_dict["previous_hash"],
            block_dict["nonce"]
        )
        block.hash = block_dict["hash"]
        return block


class Blockchain:
    
    def __init__(self, blockchain_file: str = "blockchain/blockchain_data.json", difficulty: int = 4):
        
        self.chain: List[Block] = []
        self.pending_transactions: List[Dict[str, Any]] = []
        self.blockchain_file = blockchain_file
        self.difficulty = difficulty
        self.lock = threading.Lock()
        
        # Ensure the blockchain directory exists
        os.makedirs(os.path.dirname(self.blockchain_file), exist_ok=True)
        
        # Load the blockchain from file
        if os.path.exists(self.blockchain_file):
            self.load_chain()
        else:
            self.create_genesis_block()
            self.save_chain()
    
    def create_genesis_block(self) -> None:
        
        genesis_block = Block(0, time.time(), [], "0")
        self.chain.append(genesis_block)
        logger.info("Genesis block created")
    
    def get_latest_block(self) -> Block:
        
        return self.chain[-1]
    
    def add_transaction(self, action: str, username: str, filename: str, timestamp: Optional[str] = None) -> str:
        
        if not timestamp:
            timestamp = datetime.datetime.now().isoformat()
            
        # Validate inputs
        if not action or not username or not filename:
            raise ValueError("Action, username, and filename are required")
            
        # Create the transaction
        transaction = {
            "action": action,
            "username": username,
            "filename": filename,
            "timestamp": timestamp,
            "tx_time": time.time()
        }
        
        # Generate a transaction ID (hash of the transaction)
        tx_string = json.dumps(transaction, sort_keys=True).encode()
        transaction["txid"] = hashlib.sha256(tx_string).hexdigest()
        
        # Add to pending transactions
        with self.lock:
            self.pending_transactions.append(transaction)
            
        logger.info(f"Added transaction: {action} by {username} for {filename}")
        return transaction["txid"]
    
    def mine_pending_transactions(self) -> Optional[str]:
        
        with self.lock:
            if not self.pending_transactions:
                logger.info("No pending transactions to mine")
                return None
                
            # Create a new block with all pending transactions
            new_block = Block(
                len(self.chain),
                time.time(),
                self.pending_transactions,
                self.get_latest_block().hash
            )
            
            # Mine the block
            new_block.mine_block(self.difficulty)
            
            # Add the block to the chain
            self.chain.append(new_block)
            
            # Clear the pending transactions
            self.pending_transactions = []
            
            # Save the updated chain
            self.save_chain()
            
            logger.info(f"Mined new block #{new_block.index} with {len(new_block.transactions)} transactions")
            return new_block.hash
    
    def is_chain_valid(self) -> bool:
        
        for i in range(1, len(self.chain)):
            current_block = self.chain[i]
            previous_block = self.chain[i-1]
            
            # Validate block hash
            if current_block.hash != current_block.calculate_hash():
                logger.error(f"Block #{current_block.index} has an invalid hash")
                return False
                
            # Validate previous hash reference
            if current_block.previous_hash != previous_block.hash:
                logger.error(f"Block #{current_block.index} has an invalid previous hash reference")
                return False
                
            # Validate proof of work
            if current_block.hash[:self.difficulty] != "0" * self.difficulty:
                logger.error(f"Block #{current_block.index} has an invalid proof of work")
                return False
                
        return True
    
    def save_chain(self) -> None:
        
        with open(self.blockchain_file, 'w') as f:
            json_chain = [block.to_dict() for block in self.chain]
            json.dump({
                "chain": json_chain,
                "pending_transactions": self.pending_transactions,
                "difficulty": self.difficulty
            }, f, indent=4)
        logger.info(f"Blockchain saved to {self.blockchain_file}")
    
    def load_chain(self) -> None:
        
        try:
            with open(self.blockchain_file, 'r') as f:
                data = json.load(f)
                self.chain = [Block.from_dict(block_dict) for block_dict in data["chain"]]
                self.pending_transactions = data["pending_transactions"]
                self.difficulty = data.get("difficulty", 4)
            logger.info(f"Blockchain loaded from {self.blockchain_file} with {len(self.chain)} blocks")
        except Exception as e:
            logger.error(f"Failed to load blockchain: {e}")
            self.create_genesis_block()
    
    def query_transactions(self, username: Optional[str] = None, 
                           filename: Optional[str] = None, 
                           action: Optional[str] = None) -> List[Dict[str, Any]]:
        
        results = []
        
        # Check all blocks in the chain
        for block in self.chain:
            for tx in block.transactions:
                # Apply filters
                if username and tx.get("username") != username:
                    continue
                if filename and tx.get("filename") != filename:
                    continue
                if action and tx.get("action") != action:
                    continue
                
                # Add block information to the transaction
                tx_with_block = tx.copy()
                tx_with_block.update({
                    "block_index": block.index,
                    "block_hash": block.hash,
                    "block_timestamp": block.timestamp
                })
                results.append(tx_with_block)
        
        # Also check pending transactions
        for tx in self.pending_transactions:
            # Apply filters
            if username and tx.get("username") != username:
                continue
            if filename and tx.get("filename") != filename:
                continue
            if action and tx.get("action") != action:
                continue
            
            # Mark as pending
            tx_pending = tx.copy()
            tx_pending["pending"] = True
            results.append(tx_pending)
            
        return results
    
    def get_chain_data(self) -> Dict[str, Any]:
        
        return {
            "blocks": len(self.chain),
            "pending_transactions": len(self.pending_transactions),
            "difficulty": self.difficulty,
            "last_block_hash": self.get_latest_block().hash,
            "is_valid": self.is_chain_valid(),
            "total_transactions": sum(len(block.transactions) for block in self.chain)
        }


class HyperledgerClient:
    
    def __init__(self):
        """Initialize the blockchain client."""
        self.blockchain = Blockchain()
        # Start a background thread to mine pending transactions periodically
        self.start_mining_thread()
    
    def start_mining_thread(self) -> None:
        
        def mining_thread():
            while True:
                # If there are pending transactions, mine them
                if self.blockchain.pending_transactions:
                    self.blockchain.mine_pending_transactions()
                # Sleep for a few seconds
                time.sleep(10)
        
        # Start the thread as a daemon
        thread = threading.Thread(target=mining_thread, daemon=True)
        thread.start()
        logger.info("Started background mining thread")
    
    def record_transaction(self, action: str, username: str, filename: str) -> str:
        
        try:
            # Add the transaction to the blockchain
            tx_id = self.blockchain.add_transaction(action, username, filename)
            logger.info(f"Recorded transaction to blockchain: {action} by {username} for {filename} with tx_id {tx_id}")
            return tx_id
        except Exception as e:
            logger.error(f"Error recording transaction to blockchain: {e}")
            # Return a mock transaction ID for resilience
            return f"error_{time.time()}"
    
    def query_transactions_by_username(self, username: str) -> List[Dict[str, Any]]:
        
        return self.blockchain.query_transactions(username=username)
    
    def query_transactions_by_filename(self, filename: str) -> List[Dict[str, Any]]:
        
        return self.blockchain.query_transactions(filename=filename)
    
    def query_transactions(self, username: str, filename: str) -> List[Dict[str, Any]]:
        
        return self.blockchain.query_transactions(username=username, filename=filename)
    
    def query_all_transactions(self) -> List[Dict[str, Any]]:
        
        return self.blockchain.query_transactions()
    
    def get_blockchain_stats(self) -> Dict[str, Any]:
        
        return self.blockchain.get_chain_data()
    
    def close(self) -> None:
        
        self

