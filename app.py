from flask import Flask, jsonify, request, render_template
from blockchain import Blockchain
from cryptoUtilsV2 import generate_keys, sign_transaction, validate_address
import json
import sys

# Flask app setup and routes
app = Flask(__name__)
blockchain = None

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/mine_block', methods=['POST'])
def mine_block_route():
    data = request.get_json()
    miner_address = data.get('miner_address')

    if not miner_address:
        return jsonify({'message': 'Miner address is required'}), 400
    if not validate_address(miner_address):
        return jsonify({'message': 'Invalid miner address'}), 400
        
    block = blockchain.mine_block(miner_address=miner_address)

    if block:
        response = {
            'index': block['index'],
            'timestamp': block['timestamp'],
            'previous_hash': block['previous_hash'],
            'transactions': block['transactions'],
            'transaction_count': len(block['transactions']),
            'merkle_root': block['merkleroot'],
            'difficulty': block['difficulty'],
            'nonce': block['nonce'],
            'block_time': block['block_time'],
            'uncles': block['uncles']
        }
        return jsonify(response), 200
    else:
        return jsonify({'message': 'Error mining block'}), 500

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
    transaction_keys = ['sender', 'receiver', 'amount', 'signature', 'nonce']

    if not all(key in add_transaction_json and add_transaction_json[key] not in [None, ''] for key in transaction_keys):
        print('Some elements of the transaction are missing')
        return jsonify({'message': 'Some elements of the transaction are missing'}), 400
    if not validate_address(add_transaction_json['sender']):
        print('Invalid sender address')
        return jsonify({'message': 'Invalid sender address'}), 400
    if not validate_address(add_transaction_json['receiver']):
        print('Invalid receiver address')
        return jsonify({'message': 'Invalid receiver address'}), 400

    result = blockchain.add_transaction(
        add_transaction_json['sender'], 
        add_transaction_json['receiver'], 
        add_transaction_json['amount'],
        add_transaction_json['signature'],
        add_transaction_json['nonce']
    )

    if result['success']:
        return jsonify({'message': f'Transaction will be added to Block {result["block_index"]}'}), 201
    else:
        return jsonify({'message': result['error']}), 400

@app.route('/sign_transaction', methods=['POST'])
def sign_transaction_route():
    transaction_data_json = request.get_json() 
    transaction_keys = ['sender', 'receiver', 'amount', 'nonce', 'private_key']

    # Check if all keys exist AND have non-empty values
    if not all(key in transaction_data_json and transaction_data_json[key] not in [None, ''] for key in transaction_keys):
        print('Some elements of the transaction are missing or empty')
        return jsonify({'message': 'Some elements of the transaction are missing or empty'}), 400
    if not validate_address(transaction_data_json['sender']):
        print('Invalid sender address')
        return jsonify({'message': 'Invalid sender address'}), 400
    if not validate_address(transaction_data_json['receiver']):
        print('Invalid receiver address')
        return jsonify({'message': 'Invalid receiver address'}), 400

    private_key = transaction_data_json['private_key'].replace('\\n', '\n')
    transaction_data = json.dumps({
        'sender_address': transaction_data_json['sender'],
        'receiver_address': transaction_data_json['receiver'],
        'amount': transaction_data_json['amount'],
        'nonce': transaction_data_json['nonce']
    }, sort_keys=True).encode()

    signature = sign_transaction(private_key, transaction_data)

    return jsonify({'signature': signature.hex()}), 200

@app.route('/connect_node', methods=['POST'])
def connect_node_route():
    json = request.get_json()
    nodes = json.get('nodes')

    if len(nodes) == 0:
        return jsonify({'message': 'No nodes provided'}), 400

    for node in nodes:
        blockchain.add_node(node)

    return jsonify({'message': 'All nodes are now connected', 'total_nodes': list(blockchain.nodes)}), 201

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
    
    # Check if block connects to our current chain
    if blockchain.is_chain_valid([blockchain.get_previous_block(), block]):
        blockchain.chain.append(block)
        blockchain.update_nonces_from_block(block)  # Update nonces from confirmed block
        blockchain.sync_transaction_pool()
        return jsonify({'message': 'Block received and added to chain'}), 200
    
    # If block doesn't connect, chains might be out of sync - trigger consensus
    print('Block does not connect to current chain, applying consensus...')
    blockchain.apply_consensus()
    
    # Try again after consensus
    if blockchain.is_chain_valid([blockchain.get_previous_block(), block]):
        blockchain.chain.append(block)
        blockchain.update_nonces_from_block(block)  # Update nonces from confirmed block
        blockchain.sync_transaction_pool()
        return jsonify({'message': 'Block received after consensus sync'}), 200
    
    return jsonify({'message': 'Invalid block - does not connect to any known chain'}), 400

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
    
    # Convert actual newlines to literal \n strings for easy copy-paste in JSON requests
    private_key_formatted = private_key.replace('\n', '\\n')
    public_key_formatted = public_key.replace('\n', '\\n')
    
    response = {
        'private_key': private_key_formatted,
        'public_key': public_key_formatted
    }
    return jsonify(response), 200

@app.route('/get_block_reward', methods=['GET'])
def get_block_reward_route():
    """Get the current block reward for the next block."""
    current_height = len(blockchain.chain) + 1
    reward = blockchain.calculate_block_reward(current_height)
    response = {
        'current_block_height': len(blockchain.chain),
        'next_block_height': current_height,
        'next_block_reward': reward,
        'initial_reward': blockchain.initial_block_reward,
        'halving_interval': blockchain.halving_interval,
        'halvings_occurred': current_height // blockchain.halving_interval
    }
    return jsonify(response), 200

@app.route('/get_mining_stats', methods=['GET'])
def get_mining_stats_route():
    """Get comprehensive mining statistics."""
    total_blocks = len(blockchain.chain)
    total_supply = 0
    
    # Calculate total supply and fees
    for block in blockchain.chain:
        for tx in block.get('transactions', []):
            if tx.get('sender') == 'coinbase':
                total_supply += tx.get('block_reward', 0)
    
    response = {
        'total_blocks': total_blocks,
        'total_supply': total_supply,
        'current_difficulty': blockchain.difficulty,
        'pending_transactions': len(blockchain.pending_transactions),
        'next_block_reward': blockchain.calculate_block_reward(total_blocks + 1)
    }
    return jsonify(response), 200

if __name__ == '__main__':
    port = 5000  # Default port
    if len(sys.argv) > 1:
        port = int(sys.argv[1])
    blockchain = Blockchain(port)
    app.run(host='0.0.0.0', port=port, debug=True)