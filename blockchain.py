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
        self.difficulty = 1  # Initial difficulty
        self.target_time = 0.4  # Target block time in seconds
        self.create_block(proof=1, previous_hash='0')

    def create_block(self, proof, previous_hash):
        block = {
            'index': len(self.chain) + 1,
            'timestamp': str(datetime.datetime.now()),
            'proof': proof,
            'previous_hash': previous_hash,
            'difficulty': self.difficulty
        }

        self.chain.append(block) # append block to chain
        return block

    def get_previous_block(self):
        return self.chain[-1]

    def proof_of_work(self, previous_proof): # hard to find, easy to verify
        start_time = time.time()
        new_proof = 1
        check_proof = False

        while not check_proof:
            hash_operation = hashlib.sha256(str(new_proof * previous_proof).encode()).hexdigest()
            if hash_operation[:self.difficulty] == '0' * self.difficulty:
                check_proof = True
            else:
                new_proof += 1

        end_time = time.time()
        block_time = end_time - start_time
        print('Block time: ', block_time)

        self.adjust_difficulty(block_time)

        return new_proof

    def adjust_difficulty(self, block_time):
        if block_time < self.target_time:
            self.difficulty += 1
        elif block_time > self.target_time:
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
            hash_operation = hashlib.sha256(str(proof * previous_proof).encode()).hexdigest()

            if hash_operation[:block['difficulty']] != '0' * block['difficulty']:
                return False

            previous_block = block
            block_index += 1

        return True

# create web application
app = Flask(__name__)

# create blockchain
blockchain = Blockchain()

# routes
@app.route('/mine_block', methods=['GET'])
def mine_block():
    previous_block = blockchain.get_previous_block()
    previous_proof = previous_block['proof']
    proof = blockchain.proof_of_work(previous_proof)
    previous_hash = blockchain.hash(previous_block)
    block = blockchain.create_block(proof, previous_hash)

    response = {
        'message': 'Congratulations, you just mined a block!',
        'index': block['index'],
        'timestamp': block['timestamp'],
        'proof': block['proof'],
        'previous_hash': block['previous_hash'],
        'difficulty': block['difficulty']
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

    
# run web application
app.run(host='0.0.0.0', port=5000) # localhost:5000