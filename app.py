from flask import Flask, jsonify, request
from blockchain import Blockchain
from crypto_utils import generate_keys, sign_transaction
import json
import sys

# Flask app setup and routes
app = Flask(__name__)
blockchain = None

@app.route('/mine_block', methods=['GET'])
def mine_block_route():
    block = blockchain.mine_block()

    if block:
        response = {
            'message': 'Congratulations, you just mined a block!',
            'index': block['index'],
            'timestamp': block['timestamp'],
            'previous_hash': block['previous_hash'],
            'transactions': block['transactions'],
            'merkle_root': block['merkleroot'],
            'difficulty': block['difficulty'],
            'nonce': block['nonce'],
            'block_time': block['block_time'],
            'uncles': block['uncles']
        }
    else:
        response = {
            'message': 'Error mining block'
        }

    return jsonify(response), 200

@app.route('/get_chain', methods=['GET'])
def get_chain_route():
    response = {
        'chain': blockchain.chain,
        'length': len(blockchain.chain)
    }

    return jsonify(response), 200

@app.route('/is_valid', methods=['GET'])
def is_valid_route():
    is_valid = blockchain.is_chain_valid(blockchain.chain)
    if is_valid:
        response = {
            'message': 'Blockchain is valid'
        }
    else:
        response = {
            'message': 'Blockchain is not valid'
        }

    return jsonify(response), 200

@app.route('/add_transaction', methods=['POST'])
def add_transaction_route():
    add_transaction_json = request.get_json()
    transaction_keys = ['sender', 'receiver', 'amount', 'signature', 'public_key', 'nonce']

    if not all(key in add_transaction_json for key in transaction_keys):
        return 'Some elements of the transaction are missing', 400

    index = blockchain.add_transaction(
        add_transaction_json['sender'], 
        add_transaction_json['receiver'], 
        add_transaction_json['amount'],
        add_transaction_json['signature'],
        add_transaction_json['public_key'],
        add_transaction_json['nonce']
    )

    if index is False:
        response = {'message': 'Invalid transaction'}
    else:
        response = {'message': f'Transaction will be added to Block {index}'}


    return jsonify(response), 201

@app.route('/sign_transaction', methods=['POST'])
def sign_transaction_route():
    transaction_data_json = request.get_json() 
    transaction_keys = ['sender', 'receiver', 'amount', 'nonce', 'private_key']

    if not all(key in transaction_data_json for key in transaction_keys):
        return 'Some elements of the transaction are missing', 400

    private_key = transaction_data_json['private_key']
    transaction_data = json.dumps({
        'sender': transaction_data_json['sender'],
        'receiver': transaction_data_json['receiver'],
        'amount': transaction_data_json['amount'],
        'nonce': transaction_data_json['nonce']
    }, sort_keys=True).encode()

    signature = sign_transaction(private_key, transaction_data)

    response = {
        'signature': signature.hex()
    }

    return jsonify(response), 200

@app.route('/connect_node', methods=['POST'])
def connect_node_route():
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

@app.route('/get_nodes', methods=['GET'])
def get_nodes_route():
    response = {
        'nodes': list(blockchain.nodes),
        'total_nodes': len(blockchain.nodes)
    }
    return jsonify(response), 200

@app.route('/replace_chain', methods=['GET'])
def replace_chain_route():
    is_chain_replaced = blockchain.replace_chain()

    response = {
        'is_chain_replaced': f'Chain is replaced: {is_chain_replaced}',
        'chain': blockchain.chain
    }

    return jsonify(response), 200

@app.route('/receive_transaction', methods=['POST'])
def receive_transaction_route():
    transaction = request.get_json()
    transaction_str = json.dumps(transaction, sort_keys=True)
    if transaction_str not in blockchain.transaction_pool:
        blockchain.pending_transactions.append(transaction)
        blockchain.transaction_pool.add(transaction_str)
        return jsonify({'message': 'Transaction received and added to pool'}), 200
    return jsonify({'message': 'Transaction already in pool'}), 200

@app.route('/receive_block', methods=['POST'])
def receive_block_route():
    block = request.get_json()
    if blockchain.is_chain_valid([blockchain.get_previous_block(), block]):
        blockchain.chain.append(block)
        blockchain.sync_transaction_pool()
        return jsonify({'message': 'Block received and added to chain'}), 200
    return jsonify({'message': 'Invalid block'}), 400

@app.route('/apply_consensus', methods=['GET'])
def apply_consensus_route():
    consensus_applied = blockchain.apply_consensus()
    
    if consensus_applied:
        response = {
            'message': 'The chain was replaced by the longest one in the network.',
            'new_chain': blockchain.chain
        }
    else:
        response = {
            'message': 'This chain is authoritative. No consensus changes needed.',
            'chain': blockchain.chain
        }
    
    return jsonify(response), 200

@app.route('/generate_keys', methods=['GET'])
def generate_keys_route():
    private_key, public_key = generate_keys()
    response = {
        'private_key': private_key,
        'public_key': public_key
    }
    return jsonify(response), 200

if __name__ == '__main__':
    port = 5000  # Default port
    if len(sys.argv) > 1:
        port = int(sys.argv[1])
    blockchain = Blockchain(port)
    app.run(host='0.0.0.0', port=port, debug=True)