# pip install flask

import datetime # for timestamp of block
import hashlib # for hashing the block
import json # for encoding the block
from flask import Flask, jsonify # for web application
import requests
from uuid import uuid4
from urllib.parse import urlparse
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256

# Blockchain class
class Blockchain:
    def __init__(self): # constructor
        self.chain = []
        self.pending_transactions = []
        self.difficulty = 4  # Initial difficulty
        self.target_time = 0.5  # Target block time in seconds
        self.create_block(proof=1, previous_hash='0', nonce=0) # genesis block
        self.nodes = set()
        self.nonces = {}

    def create_block(self, proof, previous_hash, nonce):
        block = {
            'index': len(self.chain) + 1,
            'timestamp': str(datetime.datetime.now()),
            'proof': proof,
            'previous_hash': previous_hash,
            'transactions': self.pending_transactions,
            'difficulty': self.difficulty,
            'nonce': nonce
        }

        self.pending_transactions = [] # clear pending transactions
        self.chain.append(block) # append block to chain
        return block

    def get_previous_block(self):
        return self.chain[-1]

    def proof_of_work(self, previous_proof): # hard to find, easy to verify
        start_time = datetime.datetime.now()
        new_proof = 1
        nonce = 0
        check_proof = False

        while not check_proof:
            hash_operation = self.calculate_hash(previous_proof, new_proof, nonce)
            if int(hash_operation, 16) < 2**(256 - self.difficulty):
                check_proof = True
            else:
                nonce += 1

        end_time = datetime.datetime.now()
        block_time = end_time - start_time
        print('Block time: ', block_time)

        self.adjust_difficulty(block_time)

        return new_proof, nonce

    def calculate_hash(self, previous_proof, new_proof, nonce):
        hash_str = f"{previous_proof}{new_proof}{nonce}".encode()
        return hashlib.sha256(hash_str).hexdigest()

    def adjust_difficulty(self, block_time):
        if block_time < self.target_time * 0.5:
            self.difficulty += 1
        elif block_time > self.target_time * 1.5 and self.difficulty > 1:
            self.difficulty -= 1

    def hash(self, block):
        encoded_block = json.dumps(block, sort_keys=True).encode() # encode block
        return hashlib.sha256(encoded_block).hexdigest()

    def add_transaction(self, sender, receiver, amount, signature, public_key, nonce=0):
        transaction = {
            'sender': sender,
            'receiver': receiver,
            'amount': amount,
            'signature': signature.hex(),
            'nonce': nonce
        }

        # Use sorted keys for deterministic serialization
        transaction_data = json.dumps(transaction, sort_keys=True).encode()

        if self.verify_signature(public_key, transaction_data, signature):
             # Check if the nonce is valid (greater than the last used nonce)
            if self.is_valid_nonce(sender, nonce):
                self.pending_transactions.append(transaction)
                self.nonces[sender] = nonce # update the nonce for the sender
                previous_block = self.get_previous_block()
                return previous_block['index'] + 1 # return index of block
        else:
            return False 

    def is_valid_nonce(self, sender, nonce):
        if sender not in self.nonces:
            return True # first transaction
        return nonce > self.nonces[sender]

    def verify_signature(self, public_key, transaction_data, signature):
        try:
            public_key = RSA.import_key(public_key)
            hash_object = SHA256.new(transaction_data)
            pkcs1_15.new(public_key).verify(hash_object, signature)
            return True
        except (ValueError, TypeError):
            return False      

    def add_node(self, address):
        parsed_url = urlparse(address)
        self.nodes.add(parsed_url.netloc)

    def is_chain_valid(self, chain):
        previous_block = chain[0]
        block_index = 1

        while block_index < len(chain):
            block = chain[block_index]

            if block['previous_hash'] != self.hash(previous_block):
                return False

            previous_proof = previous_block['proof']
            proof = block['proof']
            nonce = block['nonce']
            hash_operation = self.calculate_hash(previous_proof, proof, nonce)

            if int(hash_operation, 16) >= 2**(256 - block['difficulty']):
                return False

            # verify each transaction's signature
            for transaction in block['transactions']:
                sender = transaction['sender']
                transaction_data = json.dumps({
                    'sender': sender,
                    'receiver': transaction['receiver'],
                    'amount': transaction['amount']
                }, sort_keys=True).encode()
                signature = bytes.fromhex(transaction['signature'])
                if not self.verify_signature(sender, transaction_data, signature):
                    return False

                # Check if the nonce is valid within the chain
                if sender not in address_nonces:
                    address_nonces[sender] = transaction['nonce']
                elif transaction['nonce'] <= address_nonces[sender]:
                    return False
                else:
                    address_nonces[sender] = transaction['nonce']

            previous_block = block
            block_index += 1

        return True

    def replace_chain(self):
        network = self.nodes
        longest_chain = None
        max_length = len(self.chain)

        for node in network:
            response = requests.get(f'http://{node}/get_chain')

            if response.status_code == 200:
                length = response.json()['length']
                chain = response.json()['chain']

                if length > max_length and self.is_chain_valid(chain):
                    max_length = length
                    longest_chain = chain

        if longest_chain:
            self.chain = longest_chain
            return True

        return False


# helper functions for key generation and signing
def generate_keys():
    key = RSA.generate(2048)
    private_key = key.export_key().decode()
    public_key = key.publickey().export_key().decode()
    return private_key, public_key

def sign_transaction(private_key, transaction_data):
    key = RSA.import_key(private_key)
    hash_object = SHA256.new(transaction_data)
    signature = pkcs1_15.new(key).sign(hash_object)
    return signature

# create web application
app = Flask(__name__)

# create address for the node on Port 5000
node_address = str(uuid4()).replace('-', '')  # unique address

# create blockchain
blockchain = Blockchain()

@app.route('/mine_block', methods=['GET'])
def mine_block():
    previous_block = blockchain.get_previous_block()
    previous_proof = previous_block['proof']
    proof, nonce = blockchain.proof_of_work(previous_proof)
    previous_hash = blockchain.hash(previous_block)
    blockchain.add_transaction(sender=node_address, receiver='You', amount=1) # reward for mining
    block = blockchain.create_block(proof, previous_hash, nonce)

    response = {
        'message': 'Congratulations, you just mined a block!',
        'index': block['index'],
        'timestamp': block['timestamp'],
        'proof': block['proof'],
        'previous_hash': block['previous_hash'],
        'transactions': block['transactions'],
        'difficulty': block['difficulty'],
        'nonce': block['nonce']
    }

    return jsonify(response), 200

@app.route('/get_chain', methods=['GET'])
def get_chain():
    response = {
        'chain': blockchain.chain,
        'length': len(blockchain.chain)
    }

    return jsonify(response), 200

@app.route('/is_valid', methods=['GET'])
def is_valid():
    is_valid = blockchain.is_chain_valid(blockchain.chain)
    response = {
        'is_valid': is_valid
    }

    return jsonify(response), 200

@app.route('/add_transaction', methods=['POST'])
def add_transaction():
    json = request.get_json()
    transaction_keys = ['sender', 'receiver', 'amount', 'signature', 'public_key', 'nonce']

    if not all(key in json for key in transaction_keys):
        return 'Some elements of the transaction are missing', 400

    index = blockchain.add_transaction(
        json['sender'], 
        json['receiver'], 
        json['amount'],
        json['signature'],
        json['public_key'],
        json['nonce']
    )

    response = {
        'message': f'This transaction will be added to block {index}'
    }

    return jsonify(response), 201

@app.route('/connect_node', methods=['POST'])
def connect_node():
    json = request.get_json()
    nodes = json.get('nodes')

    if nodes is None:
        return 'No node', 400

    for node in nodes:
        blockchain.add_node(node)

    response = {
        'message': 'All nodes are now connected',
        'total_nodes': list(blockchain.nodes)
    }

    return jsonify(response), 201

@app.route('/replace_chain', methods=['GET'])
def replace_chain():
    is_chain_replaced = blockchain.replace_chain()

    response = {
        'is_chain_replaced': f'Chain is replaced: {is_chain_replaced}',
        'chain': blockchain.chain
    }

    return jsonify(response), 200

@app.route('/generate_keys', methods=['GET'])
def generate_keys():
    private_key, public_key = generate_keys()
    response = {
        'private_key': private_key,
        'public_key': public_key
    }
    return jsonify(response), 200

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)