import datetime
import hashlib
import json
import requests
import time
from urllib.parse import urlparse
import logging
from crypto_utils import verify_signature
from merkletree import MerkleTree

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

class Blockchain:
    def __init__(self, port):
        self.chain = []
        self.pending_transactions = []
        self.difficulty = 20  # Initial difficulty
        self.target_time = 2  # Target block time in seconds
        self.nodes = set()
        self.nonces = {}
        self.uncle_blocks = [] 
        self.max_uncles = 2
        self.transaction_pool = set()
        self.load_nodes_from_file()  # Load nodes when initializing the blockchain
        self.port = port
        self.node_address = self.get_node_address()
        self.create_block(previous_hash='0', nonce=0, block_time=0, difficulty=self.difficulty)

    def load_nodes_from_file(self):
        try:
            with open('nodes.json', 'r') as f:
                nodes_data = json.load(f)
            for node in nodes_data.get('nodes', []):
                self.add_node(node)
            logging.info(f"Loaded {len(self.nodes)} nodes from nodes.json")
            logging.info(f"Current nodes: {self.nodes}")
        except FileNotFoundError:
            logging.error("nodes.json file not found. No nodes loaded.")
        except json.JSONDecodeError:
            logging.error("Error parsing nodes.json. Please ensure it's a valid JSON file.")
        except Exception as e:
            logging.error(f"An unexpected error occurred while loading nodes: {str(e)}")
        
    def add_node(self, address):
        try:
            parsed_url = urlparse(address)
            if parsed_url.netloc:
                self.nodes.add(parsed_url.netloc)
                logging.info(f"Added node: {parsed_url.netloc}")
            elif parsed_url.path:
                # Accepts an URL without scheme like '192.168.0.5:5000'.
                self.nodes.add(parsed_url.path)
                logging.info(f"Added node: {parsed_url.path}")
            else:
                raise ValueError('Invalid URL')
        except Exception as e:
            logging.error(f"Failed to add node {address}: {str(e)}")

    def mine_block(self):
        previous_block = self.get_previous_block()
        nonce, block_time, difficulty = self.proof_of_work(previous_block['nonce'])
        previous_hash = self.hash(previous_block)
        
        block = self.create_block(previous_hash, nonce, block_time, difficulty)
        print('Block %d mined' % block['index'])
        
        # Update nonces after mining the block
        for transaction in block['transactions']:
            sender = transaction['sender']
            self.nonces[sender] = transaction['nonce']
        
        self.broadcast_block(block)  # Broadcast the newly mined block to other nodes

        return block
    
    def broadcast_block(self, block):
        current_node = self.get_node_address()
        print("Current node ", current_node)

        for node in self.nodes:
            print(f"Broadcasting block to {node}")
            if node == current_node:
                continue
            try:
                response = requests.post(f'http://{node}/receive_block', json=block)
                if response.status_code == 200:
                    print(f"Block successfully broadcast to {node}")
                else:
                    print(f"Failed to broadcast block to {node}: {response.text}")
            except requests.RequestException as e:
                print(f"Failed to broadcast block to {node}: {str(e)}")

    def create_block(self, previous_hash, nonce, block_time, difficulty):
        merkletree = MerkleTree(self.pending_transactions)
        block = {
            'index': len(self.chain) + 1,
            'timestamp': str(datetime.datetime.now()),
            'previous_hash': previous_hash,
            'transactions': self.pending_transactions,
            'merkleroot': merkletree.get_root(),
            'difficulty': difficulty,
            'nonce': nonce,
            'block_time': block_time,
            'uncles': self.get_valid_uncles()
        }

        self.pending_transactions = [] # clear pending transactions
        self.chain.append(block) # append block to chain
        self.uncle_blocks = [uncle for uncle in self.uncle_blocks if uncle not in block['uncles']]
        return block
    
    def get_previous_block(self):
        return self.chain[-1] if self.chain else None

    def get_valid_uncles(self):
        valid_uncles = []
        for uncle in self.uncle_blocks:
            if len(valid_uncles) >= self.max_uncles:
                break
            if self.is_valid_uncle(uncle):
                valid_uncles.append(uncle)
        return valid_uncles

    def is_valid_uncle(self, uncle):
        if len(self.chain) < 7:
            return False
        uncle_index = uncle['index']
        current_index = len(self.chain)
        return current_index - 7 <= uncle_index < current_index

    def proof_of_work(self, previous_nonce):
        start_time = time.time()
        nonce = 0
        check_proof = False

        while not check_proof:
            hash_operation = self.calculate_hash(previous_nonce, nonce)
            if int(hash_operation, 16) < 2**(256 - self.difficulty):
                check_proof = True
            else:
                nonce += 1

        end_time = time.time()
        block_time = end_time - start_time
        print('Block time: ', block_time)

        current_difficulty = self.difficulty # save current
        self.adjust_difficulty(block_time)

        return nonce, block_time, current_difficulty

    def calculate_hash(self, previous_nonce, nonce):
        hash_str = f"{previous_nonce}{nonce}".encode()
        return self.sha256d(hash_str)

    def sha256d(self, data):
        """Perform double SHA-256 hash."""
        return hashlib.sha256(hashlib.sha256(data).digest()).hexdigest()

    def adjust_difficulty(self, block_time):
        if block_time < self.target_time * 0.8:
            self.difficulty += 1
        elif block_time > self.target_time * 1.2 and self.difficulty > 1:
            self.difficulty -= 1
        
        # Ensure difficulty doesn't drop too low
        self.difficulty = max(self.difficulty, 1)
        
        print(f"Adjusted difficulty to {self.difficulty}")

    def hash(self, block):
        encoded_block = json.dumps(block, sort_keys=True).encode()
        return self.sha256d(encoded_block)
    
    def get_node_address(self):
        return f"127.0.0.1:{self.port}"

    def add_transaction(self, sender, receiver, amount, signature, public_key, nonce=0):
        transaction = {
            'sender': sender,
            'receiver': receiver,
            'amount': amount,
            'nonce': nonce
        }

        transaction_data = json.dumps(transaction, sort_keys=True).encode()

        if verify_signature(public_key, transaction_data, signature):
            if self.is_valid_nonce(sender, nonce):
                transaction['signature'] = signature
                transaction['public_key'] = public_key

                self.pending_transactions.append(transaction)
                transaction_str = json.dumps(transaction, sort_keys=True)
                self.transaction_pool.add(transaction_str)
                self.nonces[sender] = nonce # update the nonce for the sender
                previous_block = self.get_previous_block()

                self.broadcast_transaction(transaction)  # Broadcast the transaction to other nodes

                return previous_block['index'] + 1 # return index of block
            else:
                print('Invalid nonce')
                return False
        else:
            print('Signature verification failed')
            return False 

    def is_valid_nonce(self, sender, nonce):
        if sender not in self.nonces:
            return True # first transaction
        return nonce > self.nonces[sender]

    def broadcast_transaction(self, transaction):
        for node in self.nodes:
            try:
                requests.post(f'http://{node}/receive_transaction', json=transaction)
            except requests.RequestException as e:
                print(f"Failed to broadcast transaction to {node}: {str(e)}")

    def add_node(self, address):
        parsed_url = urlparse(address)
        self.nodes.add(parsed_url.netloc)

    def is_chain_valid(self, chain):
        previous_block = chain[0]
        block_index = 1
        address_nonces = {}

        while block_index < len(chain):
            block = chain[block_index]
            calculated_previous_hash = self.hash(previous_block)
            print(f'Verifying block {block_index}')

            if block['previous_hash'] != calculated_previous_hash:
                print('Previous hash does not match')
                return False

            previous_nonce = previous_block['nonce']
            nonce = block['nonce']
            hash_operation = self.calculate_hash(previous_nonce, nonce)

            if int(hash_operation, 16) >= 2**(256 - block['difficulty']):
                print(f'Proof of work failed for block {block_index}')
                return False

            merkle_tree = MerkleTree(block['transactions'])
            if block['merkleroot'] != merkle_tree.get_root():
                print(f'Merkle root is invalid for block {block_index}')
                return False

            for transaction in block['transactions']:
                transaction_data = json.dumps({
                    'sender': transaction['sender'],
                    'receiver': transaction['receiver'],
                    'amount': transaction['amount'],
                    'nonce': transaction['nonce']
                }, sort_keys=True).encode()

                if not self.verify_signature(transaction['public_key'], transaction_data, transaction['signature']):
                    print('Invalid transaction signature')
                    return False

                if transaction['sender'] not in address_nonces:
                    address_nonces[transaction['sender']] = transaction['nonce']
                elif transaction['nonce'] <= address_nonces[transaction['sender']]:
                    print('Invalid nonce')
                    return False
                else:
                    address_nonces[transaction['sender']] = transaction['nonce']

            previous_block = block
            block_index += 1

        return True

    def apply_consensus(self):
        network = self.nodes
        longest_chain = None
        max_length = len(self.chain)
        consensus_applied = False

        for node in network:
            try:
                response = requests.get(f'http://{node}/get_chain')
                if response.status_code == 200:
                    length = response.json()['length']
                    chain = response.json()['chain']

                    if length > max_length and self.is_chain_valid(chain):
                        max_length = length
                        longest_chain = chain
            except requests.RequestException as e:
                print(f"Failed to get chain from {node}: {str(e)}")

        if longest_chain:
            self.chain = longest_chain
            self.sync_transaction_pool()  # Sync transaction pool after updating chain
            consensus_applied = True
        else:
            for node in network:
                try:
                    response = requests.get(f'http://{node}/get_chain')
                    if response.status_code == 200:
                        other_chain = response.json()['chain']
                        for block in other_chain:
                            if block not in self.chain and self.is_valid_uncle(block):
                                self.uncle_blocks.append(block)
                except requests.RequestException as e:
                    print(f"Failed to get chain from {node}: {str(e)}")

        return consensus_applied

    def sync_transaction_pool(self):
        confirmed_transactions = set()
        for block in self.chain:
            for tx in block['transactions']:
                confirmed_transactions.add(json.dumps(tx, sort_keys=True))
        
        self.transaction_pool -= confirmed_transactions