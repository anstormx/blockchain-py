# pip install flask

import datetime # for timestamp of block
import hashlib # for hashing the block
import json # for encoding the block
from flask import Flask, jsonify # for web application
import time

# Blockchain class
class Blockchain:
    def __init__(self): # constructor
        self.chain = []
        self.pendings_transactions = []
        self.difficulty = 4  # Initial difficulty
        self.target_time = 0.5  # Target block time in seconds
        self.create_block(proof=1, previous_hash='0', nonce=0) # genesis block

    def create_block(self, proof, previous_hash, nonce):
        block = {
            'index': len(self.chain) + 1,
            'timestamp': str(datetime.datetime.now()),
            'proof': proof,
            'previous_hash': previous_hash,
            'transactions': self.pendings_transactions,
            'difficulty': self.difficulty,
            'nonce': nonce
        }

        self.pendings_transactions = [] # clear pending transactions
        self.chain.append(block) # append block to chain
        return block

    def get_previous_block(self):
        return self.chain[-1]

    def proof_of_work(self, previous_proof): # hard to find, easy to verify
        start_time = time.time()
        new_proof = 1
        nonce = 0
        check_proof = False

        while not check_proof:
            hash_operation = self.calculate_hash(previous_proof, new_proof, nonce)
            if int(hash_operation, 16) < 2**(256 - self.difficulty):
                check_proof = True
            else:
                nonce += 1

        end_time = time.time()
        block_time = end_time - start_time
        print('Block time: ', block_time)

        self.adjust_difficulty(block_time)

        return new_proof, nonce

    def calculate_hash(self, previous_proof, new_proof, nonce):
        hash_str = f"{previous_proof}{new_proof}{nonce}".encode()
        return hashlib.sha256(hash_str).hexdigest()

    def adjust_difficulty(self, block_time):
        if block_time < self.target_time:
            self.difficulty += 1
        elif block_time > self.target_time and self.difficulty > 1:
            self.difficulty -= 1

    def hash(self, block):
        encoded_block = json.dumps(block, sort_keys=True).encode() # encode block
        return hashlib.sha256(encoded_block).hexdigest()

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

            previous_block = block
            block_index += 1

        return True

    def add_transaction(self, sender, receiver, amount):
        self.pendings_transactions.append({
            'sender': sender,
            'receiver': receiver,
            'amount': amount
        })
        previous_block = self.get_previous_block()
        return previous_block['index'] + 1


# create web application
app = Flask(__name__)

# create blockchain
blockchain = Blockchain()

@app.route('/mine_block', methods=['GET'])
def mine_block():
    previous_block = blockchain.get_previous_block()
    previous_proof = previous_block['proof']
    proof, nonce = blockchain.proof_of_work(previous_proof)
    previous_hash = blockchain.hash(previous_block)
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
    transaction_keys = ['sender', 'receiver', 'amount']

    if not all(key in json for key in transaction_keys):
        return 'Some elements of the transaction are missing', 400

    index = blockchain.add_transaction(
        json['sender'], 
        json['receiver'], 
        json['amount']
    )

    response = {
        'message': f'This transaction will be added to block {index}'
    }

    return jsonify(response), 201

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)