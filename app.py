from flask import Flask, jsonify, request, render_template
from blockchain import Blockchain
from cryptoUtilsV2 import generate_keys, sign_transaction, validate_address
from gas_table import GAS_TRANSFER
import json
import sys

app = Flask(__name__)
blockchain = None


# ── Web dashboard ─────────────────────────────────────────────────────────────

@app.route('/')
def home():
    return render_template('index.html')


# ── Mining ────────────────────────────────────────────────────────────────────

@app.route('/mine_block', methods=['POST'])
def mine_block_route():
    data = request.get_json()
    miner_address = data.get('miner_address')

    if not miner_address:
        return jsonify({'message': 'Miner address is required'}), 400
    if not validate_address(miner_address):
        return jsonify({'message': 'Invalid miner address'}), 400

    block = blockchain.mine_block(miner_address=miner_address)
    if not block:
        return jsonify({'message': 'Error mining block'}), 500

    return jsonify({
        'index':             block['index'],
        'timestamp':         block['timestamp'],
        'previous_hash':     block['previous_hash'],
        'transactions':      block['transactions'],
        'transaction_count': len(block['transactions']),
        'merkle_root':       block['merkleroot'],
        'difficulty':        block['difficulty'],
        'nonce':             block['nonce'],
        'block_time':        block['block_time'],
        'gas_limit':         block.get('gas_limit', 0),
        'gas_used':          block.get('gas_used', 0),
        'uncles':            block['uncles'],
    }), 200


# ── Chain ─────────────────────────────────────────────────────────────────────

@app.route('/get_chain', methods=['GET'])
def get_chain_route():
    return jsonify({'chain': blockchain.chain, 'length': len(blockchain.chain)}), 200


@app.route('/is_valid', methods=['GET'])
def is_valid_route():
    is_valid = blockchain.is_chain_valid(blockchain.chain)
    return jsonify({'message': 'Blockchain is valid' if is_valid else 'Blockchain is not valid'}), 200


@app.route('/replace_chain', methods=['GET'])
def replace_chain_route():
    is_chain_replaced = blockchain.replace_chain()
    return jsonify({
        'is_chain_replaced': is_chain_replaced,
        'chain': blockchain.chain
    }), 200


@app.route('/apply_consensus', methods=['GET'])
def apply_consensus_route():
    consensus_applied = blockchain.apply_consensus()
    if consensus_applied:
        response = {
            'message': 'Chain replaced by the longest one in the network.',
            'new_chain': blockchain.chain
        }
    else:
        response = {
            'message': 'This chain is authoritative. No consensus changes needed.',
            'chain': blockchain.chain
        }
    return jsonify(response), 200


# ── Transactions ──────────────────────────────────────────────────────────────

@app.route('/sign_transaction', methods=['POST'])
def sign_transaction_route():
    data = request.get_json()
    required = ['sender', 'receiver', 'amount', 'nonce', 'private_key']
    if not all(k in data and data[k] not in (None, '') for k in required):
        return jsonify({'message': 'Missing or empty transaction fields'}), 400
    if not validate_address(data['sender']):
        return jsonify({'message': 'Invalid sender address'}), 400
    if not validate_address(data['receiver']):
        return jsonify({'message': 'Invalid receiver address'}), 400

    private_key = data['private_key'].replace('\\n', '\n')
    tx_data = json.dumps({
        'sender_address':   data['sender'],
        'receiver_address': data['receiver'],
        'amount':           data['amount'],
        'nonce':            data['nonce'],
    }, sort_keys=True).encode()

    signature = sign_transaction(private_key, tx_data)
    return jsonify({'signature': signature.hex()}), 200


@app.route('/add_transaction', methods=['POST'])
def add_transaction_route():
    data = request.get_json()
    required = ['sender', 'receiver', 'amount', 'signature', 'nonce']
    if not all(k in data and data[k] not in (None, '') for k in required):
        return jsonify({'message': 'Missing or empty transaction fields'}), 400
    if not validate_address(data['sender']):
        return jsonify({'message': 'Invalid sender address'}), 400
    if not validate_address(data['receiver']):
        return jsonify({'message': 'Invalid receiver address'}), 400

    gas_price = float(data.get('gas_price', 0.0))
    gas_limit = int(data.get('gas_limit', GAS_TRANSFER))

    result = blockchain.add_transaction(
        sender_address=data['sender'],
        receiver_address=data['receiver'],
        amount=data['amount'],
        signature=data['signature'],
        nonce=data['nonce'],
        gas_price=gas_price,
        gas_limit=gas_limit,
        tx_type=0,
    )
    if result['success']:
        return jsonify({'message': f'Transaction queued for Block {result["block_index"]}'}), 201
    return jsonify({'message': result['error']}), 400


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
    previous_block = blockchain.get_previous_block()

    if blockchain.is_chain_valid([previous_block, block] if previous_block else [block]):
        blockchain.chain.append(block)
        blockchain.update_nonces_from_block(block)
        # Persist incoming block and apply state
        try:
            from account_state import StateDiff
            miner_address = ''
            for tx in block.get('transactions', []):
                if tx.get('sender_address') == 'coinbase':
                    miner_address = tx.get('receiver_address', '')
            block_reward = blockchain.calculate_block_reward(block['index'])
            total_fees = sum(
                float(tx.get('gas_price', 0)) * int(tx.get('gas_limit', GAS_TRANSFER))
                for tx in block.get('transactions', [])
                if tx.get('sender_address') != 'coinbase'
            )
            diff = blockchain._compute_state_diff(
                block['transactions'], miner_address, block_reward, total_fees,
                block.get('gas_used', 0)
            )
            diff.block = block
            blockchain.db.apply_block_state_changes(diff)
        except Exception:
            pass
        blockchain.sync_transaction_pool()
        return jsonify({'message': 'Block received and added to chain'}), 200

    blockchain.apply_consensus()
    if blockchain.is_chain_valid([blockchain.get_previous_block(), block]):
        blockchain.chain.append(block)
        blockchain.update_nonces_from_block(block)
        blockchain.sync_transaction_pool()
        return jsonify({'message': 'Block received after consensus sync'}), 200

    return jsonify({'message': 'Invalid block'}), 400


# ── Account state ─────────────────────────────────────────────────────────────

@app.route('/get_account/<address>', methods=['GET'])
def get_account_route(address):
    account = blockchain.db.get_account(address)
    if not account:
        # Return default (zero) state for unknown addresses
        account = {'address': address, 'balance': 0.0, 'nonce': -1, 'account_type': 0}
    return jsonify(account), 200


@app.route('/get_all_accounts', methods=['GET'])
def get_all_accounts_route():
    accounts = blockchain.db.get_all_accounts()
    return jsonify({'accounts': accounts, 'count': len(accounts)}), 200


# ── Transaction lookup ────────────────────────────────────────────────────────

@app.route('/get_transaction/<tx_hash>', methods=['GET'])
def get_transaction_route(tx_hash):
    tx = blockchain.db.get_transaction_by_hash(tx_hash)
    if not tx:
        return jsonify({'message': 'Transaction not found'}), 404
    return jsonify(tx), 200


@app.route('/get_mempool', methods=['GET'])
def get_mempool_route():
    txs = sorted(
        blockchain.pending_transactions,
        key=lambda t: t.get('gas_price', 0.0),
        reverse=True,
    )
    return jsonify({'pending': txs, 'count': len(txs)}), 200


# ── Node management ───────────────────────────────────────────────────────────

@app.route('/connect_node', methods=['POST'])
def connect_node_route():
    data = request.get_json()
    nodes = data.get('nodes', [])
    if not nodes:
        return jsonify({'message': 'No nodes provided'}), 400
    for node in nodes:
        blockchain.add_node(node)
    return jsonify({'message': 'Nodes connected', 'total_nodes': list(blockchain.nodes)}), 201


@app.route('/get_nodes', methods=['GET'])
def get_nodes_route():
    return jsonify({'nodes': list(blockchain.nodes), 'total_nodes': len(blockchain.nodes)}), 200


# ── Keys ─────────────────────────────────────────────────────────────────────

@app.route('/generate_keys', methods=['GET'])
def generate_keys_route():
    private_key, public_key = generate_keys()
    return jsonify({
        'private_key': private_key.replace('\n', '\\n'),
        'public_key':  public_key.replace('\n', '\\n'),
    }), 200


# ── Mining stats ──────────────────────────────────────────────────────────────

@app.route('/get_block_reward', methods=['GET'])
def get_block_reward_route():
    current_height = len(blockchain.chain)
    next_height = current_height + 1
    return jsonify({
        'current_block_height':  current_height,
        'next_block_height':     next_height,
        'next_block_reward':     blockchain.calculate_block_reward(next_height),
        'initial_reward':        blockchain.initial_block_reward,
        'halving_interval':      blockchain.halving_interval,
        'halvings_occurred':     next_height // blockchain.halving_interval,
    }), 200


@app.route('/get_mining_stats', methods=['GET'])
def get_mining_stats_route():
    total_blocks = len(blockchain.chain)
    total_supply = sum(
        float(tx.get('amount', 0))
        for block in blockchain.chain
        for tx in block.get('transactions', [])
        if tx.get('sender_address') == 'coinbase'
    )
    return jsonify({
        'total_blocks':        total_blocks,
        'total_supply':        total_supply,
        'current_difficulty':  blockchain.difficulty,
        'block_gas_limit':     blockchain.block_gas_limit,
        'pending_transactions': len(blockchain.pending_transactions),
        'next_block_reward':   blockchain.calculate_block_reward(total_blocks + 1),
    }), 200


if __name__ == '__main__':
    port = 5000
    if len(sys.argv) > 1:
        port = int(sys.argv[1])
    blockchain = Blockchain(port)
    app.run(host='0.0.0.0', port=port, debug=True)
