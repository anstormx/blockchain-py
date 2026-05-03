import datetime
import hashlib
import json
import os
import requests
import time
from urllib.parse import urlparse
import logging
from cryptoUtilsV2 import verify_signature
from merkleTreeV2 import MerkleTree
from persistence import ChainDB
from account_state import StateDiff
from gas_table import DEFAULT_BLOCK_GAS_LIMIT, GAS_TRANSFER

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


class Blockchain:
    def __init__(self, port):
        self.chain = []
        self.pending_transactions = []
        self.difficulty = 20
        self.target_time = 2          # seconds
        self.nodes = set()
        self.nonces = {}              # write-through cache: address → confirmed nonce
        self.uncle_blocks = []
        self.max_uncles = 2
        self.transaction_pool = set()
        self.block_gas_limit = DEFAULT_BLOCK_GAS_LIMIT

        # Mining reward parameters
        self.initial_block_reward = 50.0
        self.halving_interval = 210

        self.port = port
        self.node_address = self.get_node_address()

        # Initialise SQLite persistence
        db_path = f"chain_{port}.db"
        self.db = ChainDB(db_path)
        self.db.connect()
        self.db.initialize_schema()

        # Load genesis allocations and/or restore chain from disk
        self._load_from_db()
        self.load_nodes_from_file()

    # ── Startup ───────────────────────────────────────────────────────────────

    def _load_from_db(self) -> None:
        """Restore chain and state from SQLite on startup."""
        chain = self.db.load_chain()
        if chain:
            self.chain = chain
            self._rebuild_nonces_cache()
            logger.info(f"Restored {len(self.chain)} blocks from DB")
        else:
            # Fresh node — apply genesis allocations
            self._apply_genesis()

    def _apply_genesis(self) -> None:
        """Load genesis.json and credit initial balances to the accounts table."""
        genesis_path = os.path.join(os.path.dirname(__file__), 'genesis.json')
        if not os.path.exists(genesis_path):
            logger.warning("genesis.json not found — starting with empty state")
            return
        with open(genesis_path) as f:
            genesis = json.load(f)
        with self.db.conn:
            for address, balance in genesis.get('allocations', {}).items():
                self.db.upsert_account(address, float(balance), -1)
        logger.info(f"Applied genesis allocations for {len(genesis.get('allocations', {}))} addresses")

    def _rebuild_nonces_cache(self) -> None:
        """Rebuild the in-memory nonces dict from the accounts table."""
        self.nonces = {}
        rows = self.db.get_all_accounts()
        for row in rows:
            if row['nonce'] >= 0:
                self.nonces[row['address']] = row['nonce']

    # ── Node management ───────────────────────────────────────────────────────

    def load_nodes_from_file(self):
        try:
            with open('nodes.json', 'r') as f:
                nodes_data = json.load(f)
            for node in nodes_data.get('nodes', []):
                self.add_node(node)
            logger.info(f"Loaded {len(self.nodes)} nodes from nodes.json")
        except Exception as e:
            logger.error(f"Could not load nodes.json: {e}")

    def add_node(self, address):
        try:
            parsed_url = urlparse(address)
            node = parsed_url.netloc or parsed_url.path
            if node:
                self.nodes.add(node)
        except Exception as e:
            logger.error(f"Failed to add node {address}: {e}")

    def get_node_address(self):
        return f"127.0.0.1:{self.port}"

    # ── Mining ────────────────────────────────────────────────────────────────

    def mine_block(self, miner_address):
        previous_block = self.get_previous_block()
        nonce, block_time, difficulty = self.proof_of_work(
            previous_block['nonce'] if previous_block else 0
        )
        previous_hash = self.hash(previous_block) if previous_block else '0' * 64

        # Select transactions ordered by gas_price, bounded by block gas limit
        selected_txs, total_gas_used = self._select_transactions_for_block()

        # Compute total fees collected from selected transactions
        total_fees = sum(
            tx.get('gas_price', 0.0) * tx.get('gas_limit', GAS_TRANSFER)
            for tx in selected_txs
        )

        coinbase_tx = self.create_coinbase_transaction(miner_address, total_fees)
        all_txs = [coinbase_tx] + selected_txs

        # Build StateDiff for this block
        block_height = len(self.chain) + 1
        block_reward = self.calculate_block_reward(block_height)

        state_diff = self._compute_state_diff(
            all_txs, miner_address, block_reward, total_fees, total_gas_used
        )

        # Assemble block dict
        merkle_tree = MerkleTree(all_txs)
        block = {
            'index': block_height,
            'timestamp': str(datetime.datetime.now()),
            'previous_hash': previous_hash,
            'transactions': all_txs,
            'merkleroot': merkle_tree.get_root(),
            'difficulty': difficulty,
            'nonce': nonce,
            'block_time': block_time,
            'uncles': self.get_valid_uncles(),
            'gas_limit': self.block_gas_limit,
            'gas_used': total_gas_used,
        }
        state_diff.block = block

        # Commit block + state changes to DB atomically
        self.db.apply_block_state_changes(state_diff)

        # Update in-memory caches
        self.chain.append(block)
        self.uncle_blocks = [u for u in self.uncle_blocks if u not in block['uncles']]
        self._apply_state_diff_to_cache(state_diff)
        self.sync_transaction_pool()

        logger.info(f"Block {block['index']} mined — {len(all_txs)} txs, gas_used={total_gas_used}")
        self.broadcast_block(block)
        return block

    def _select_transactions_for_block(self):
        """
        Pick transactions from the mempool:
        - sorted by gas_price descending (miner priority)
        - greedily include until block gas_limit is reached
        Returns (selected_txs, total_gas_used).
        """
        sorted_txs = sorted(
            self.pending_transactions,
            key=lambda tx: tx.get('gas_price', 0.0),
            reverse=True
        )
        selected = []
        gas_used = 0
        for tx in sorted_txs:
            tx_gas = tx.get('gas_limit', GAS_TRANSFER)
            if gas_used + tx_gas <= self.block_gas_limit:
                selected.append(tx)
                gas_used += tx_gas
        return selected, gas_used

    def _compute_state_diff(self, all_txs, miner_address, block_reward, total_fees, total_gas_used):
        """Build a StateDiff from the transactions that will be included in a block."""
        diff = StateDiff(block={})  # block assigned later

        # Coinbase: credit miner with block reward + fees
        diff.ensure_account(miner_address)
        diff.credit(miner_address, block_reward + total_fees)

        for tx in all_txs:
            sender = tx.get('sender_address', '')
            receiver = tx.get('receiver_address', '')
            amount = float(tx.get('amount', 0))
            gas_price = float(tx.get('gas_price', 0.0))
            gas_limit = int(tx.get('gas_limit', GAS_TRANSFER))
            fee = gas_price * gas_limit
            tx_type = tx.get('tx_type', 0)

            if sender == 'coinbase':
                continue  # already handled above

            # Ensure both accounts exist in the diff
            diff.ensure_account(sender)
            if receiver and receiver != '0x0':
                diff.ensure_account(receiver)

            if tx_type == 0:  # Transfer
                diff.debit(sender, amount + fee)
                diff.credit(receiver, amount)
                diff.set_nonce(sender, int(tx.get('nonce', 0)))

        return diff

    def _apply_state_diff_to_cache(self, state_diff: StateDiff) -> None:
        """Sync the in-memory nonces cache from a committed StateDiff."""
        for address, new_nonce in state_diff.nonce_updates.items():
            self.nonces[address] = new_nonce

    # ── Block creation helpers ────────────────────────────────────────────────

    def create_block(self, previous_hash, nonce, block_time, difficulty, coinbase_tx=None):
        """Legacy helper — used in receive_block path. mine_block assembles directly."""
        all_transactions = ([coinbase_tx] if coinbase_tx else []) + self.pending_transactions
        merkle_tree = MerkleTree(all_transactions)
        block = {
            'index': len(self.chain) + 1,
            'timestamp': str(datetime.datetime.now()),
            'previous_hash': previous_hash,
            'transactions': all_transactions,
            'merkleroot': merkle_tree.get_root(),
            'difficulty': difficulty,
            'nonce': nonce,
            'block_time': block_time,
            'uncles': self.get_valid_uncles(),
            'gas_limit': self.block_gas_limit,
            'gas_used': 0,
        }
        self.pending_transactions = []
        self.chain.append(block)
        self.uncle_blocks = [u for u in self.uncle_blocks if u not in block['uncles']]
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

    # ── Proof of Work ─────────────────────────────────────────────────────────

    def proof_of_work(self, previous_nonce):
        start_time = time.time()
        nonce = 0
        while True:
            hash_op = self.calculate_hash(previous_nonce, nonce)
            if int(hash_op, 16) < 2 ** (256 - self.difficulty):
                break
            nonce += 1

        block_time = time.time() - start_time
        current_difficulty = self.difficulty
        self.adjust_difficulty(block_time)
        return nonce, block_time, current_difficulty

    def calculate_hash(self, previous_nonce, nonce):
        hash_str = f"{previous_nonce}{nonce}".encode()
        return self.sha256d(hash_str)

    def sha256d(self, data):
        return hashlib.sha256(hashlib.sha256(data).digest()).hexdigest()

    def adjust_difficulty(self, block_time):
        if block_time < self.target_time * 0.8:
            self.difficulty += 1
        elif block_time > self.target_time * 1.2 and self.difficulty > 1:
            self.difficulty -= 1
        self.difficulty = max(self.difficulty, 1)
        logger.info(f"Difficulty adjusted to {self.difficulty}")

    def hash(self, block):
        encoded_block = json.dumps(block, sort_keys=True).encode()
        return self.sha256d(encoded_block)

    # ── Rewards ───────────────────────────────────────────────────────────────

    def calculate_block_reward(self, block_height):
        halvings = block_height // self.halving_interval
        return self.initial_block_reward / (2 ** halvings)

    def create_coinbase_transaction(self, miner_address, total_fees=0.0):
        block_height = len(self.chain) + 1
        block_reward = self.calculate_block_reward(block_height)
        return {
            'sender_address': 'coinbase',
            'receiver_address': miner_address,
            'amount': block_reward + total_fees,
            'nonce': block_height - 1,
            'signature': None,
            'tx_type': 1,
            'gas_price': 0.0,
            'gas_limit': 0,
            'gas_used': 0,
        }

    # ── Transactions ──────────────────────────────────────────────────────────

    def add_transaction(self, sender_address, receiver_address, amount, signature, nonce,
                        gas_price=0.0, gas_limit=GAS_TRANSFER, tx_type=0):
        transaction = {
            'sender_address': sender_address,
            'receiver_address': receiver_address,
            'amount': amount,
            'nonce': nonce,
        }

        # 1. Signature verification
        transaction_data = json.dumps(transaction, sort_keys=True).encode()
        if not verify_signature(sender_address, transaction_data, signature):
            return {'success': False, 'error': 'Signature verification failed'}

        # 2. Nonce validation (exact sequential)
        if not self.is_valid_nonce(sender_address, nonce):
            expected = self.nonces.get(sender_address, -1) + 1
            return {'success': False, 'error': f'Invalid nonce. Expected {expected}, got {nonce}'}

        # 3. Balance check
        required_balance = float(amount) + float(gas_limit) * float(gas_price)
        sender_balance = self.db.get_balance(sender_address)
        if sender_balance < required_balance:
            return {
                'success': False,
                'error': f'Insufficient balance. Have {sender_balance:.4f}, need {required_balance:.4f}'
            }

        # 4. Assemble full transaction
        transaction['signature'] = signature
        transaction['tx_type'] = tx_type
        transaction['gas_price'] = float(gas_price)
        transaction['gas_limit'] = int(gas_limit)

        # 5. Duplicate check
        transaction_str = json.dumps(transaction, sort_keys=True)
        if transaction_str in self.transaction_pool:
            return {'success': False, 'error': 'Transaction already exists in pool'}

        self.pending_transactions.append(transaction)
        self.transaction_pool.add(transaction_str)
        self.broadcast_transaction(transaction)

        return {'success': True, 'block_index': len(self.chain) + 1}

    def is_valid_nonce(self, sender_address, nonce):
        """Nonce must be exactly last_confirmed + 1 (or 0 for first transaction)."""
        last_nonce = self.nonces.get(sender_address, -1)
        return int(nonce) == last_nonce + 1

    def update_nonces_from_block(self, block):
        """Update nonce cache from a newly received/mined block."""
        for tx in block['transactions']:
            sender = tx.get('sender_address', '')
            if sender and sender != 'coinbase':
                self.nonces[sender] = int(tx.get('nonce', 0))
                # Persist to DB
                with self.db.conn:
                    current_balance = self.db.get_balance(sender)
                    self.db.upsert_account(sender, current_balance, int(tx.get('nonce', 0)))

    def rebuild_state(self):
        """
        Replay the entire chain to rebuild account state from scratch.
        Called after consensus replaces our chain.
        """
        self.nonces = {}
        self.db.reset_state()
        self._apply_genesis()

        for block in self.chain:
            miner_address = ''
            block_reward = self.calculate_block_reward(block['index'])
            total_fees = 0.0

            for tx in block['transactions']:
                if tx.get('sender_address') == 'coinbase':
                    miner_address = tx.get('receiver_address', '')

            state_diff = self._compute_state_diff(
                block['transactions'],
                miner_address,
                block_reward,
                total_fees,
                block.get('gas_used', 0),
            )
            state_diff.block = block

            with self.db.conn:
                # Don't re-save the block (already cleared), just apply state
                all_touched = set(state_diff.balance_changes) | set(state_diff.nonce_updates)
                for address in all_touched:
                    current_bal = self.db.get_balance(address)
                    new_bal = current_bal + state_diff.balance_changes.get(address, 0.0)
                    new_nonce = state_diff.nonce_updates.get(address, self.db.get_nonce(address))
                    account = state_diff.new_accounts.get(address, {})
                    self.db.upsert_account(address, new_bal, new_nonce,
                                           account.get('account_type', 0))

        self._rebuild_nonces_cache()
        logger.info("State rebuilt from chain replay")

    def replace_chain(self):
        """Alias for apply_consensus — called from /replace_chain route."""
        return self.apply_consensus()

    def sync_transaction_pool(self):
        confirmed = set()
        for block in self.chain:
            for tx in block['transactions']:
                confirmed.add(json.dumps(tx, sort_keys=True))
        self.transaction_pool -= confirmed
        self.pending_transactions = [
            tx for tx in self.pending_transactions
            if json.dumps(tx, sort_keys=True) not in confirmed
        ]

    # ── Networking ────────────────────────────────────────────────────────────

    def broadcast_block(self, block):
        current_node = self.get_node_address()
        for node in self.nodes:
            if node == current_node:
                continue
            try:
                response = requests.post(f'http://{node}/receive_block', json=block, timeout=3)
                if response.status_code == 200:
                    logger.info(f"Block broadcast to {node}")
            except requests.RequestException as e:
                logger.warning(f"Broadcast to {node} failed: {e}")

    def broadcast_transaction(self, transaction):
        for node in self.nodes:
            if node == self.get_node_address():
                continue
            try:
                requests.post(f'http://{node}/receive_transaction', json=transaction, timeout=3)
            except requests.RequestException:
                pass

    # ── Validation ────────────────────────────────────────────────────────────

    def is_chain_valid(self, chain):
        if not chain:
            return True
        previous_block = chain[0]
        address_nonces = {}

        for block_index in range(1, len(chain)):
            block = chain[block_index]

            # Hash link
            if block['previous_hash'] != self.hash(previous_block):
                logger.warning(f"Block {block_index}: previous_hash mismatch")
                return False

            # PoW
            hash_op = self.calculate_hash(previous_block['nonce'], block['nonce'])
            if int(hash_op, 16) >= 2 ** (256 - block['difficulty']):
                logger.warning(f"Block {block_index}: PoW failed")
                return False

            # Merkle root
            merkle_tree = MerkleTree(block['transactions'])
            if block['merkleroot'] != merkle_tree.get_root():
                logger.warning(f"Block {block_index}: Merkle root mismatch")
                return False

            # Transaction signatures and nonces
            for tx in block['transactions']:
                if tx.get('sender_address') == 'coinbase':
                    continue

                tx_data = json.dumps({
                    'sender_address': tx['sender_address'],
                    'receiver_address': tx['receiver_address'],
                    'amount': tx['amount'],
                    'nonce': tx['nonce'],
                }, sort_keys=True).encode()

                if not verify_signature(tx['sender_address'], tx_data, tx['signature']):
                    logger.warning(f"Block {block_index}: invalid tx signature")
                    return False

                sender = tx['sender_address']
                expected_nonce = address_nonces.get(sender, -1) + 1
                if int(tx['nonce']) != expected_nonce:
                    logger.warning(f"Block {block_index}: invalid nonce for {sender[:12]}")
                    return False
                address_nonces[sender] = int(tx['nonce'])

            previous_block = block

        return True

    def apply_consensus(self):
        network = self.nodes
        longest_chain = None
        max_length = len(self.chain)
        consensus_applied = False

        for node in network:
            try:
                response = requests.get(f'http://{node}/get_chain', timeout=5)
                if response.status_code == 200:
                    data = response.json()
                    length = data['length']
                    chain = data['chain']
                    if length > max_length and self.is_chain_valid(chain):
                        max_length = length
                        longest_chain = chain
            except requests.RequestException as e:
                logger.warning(f"Could not reach {node}: {e}")

        if longest_chain:
            self.chain = longest_chain
            # Rebuild full state from the new chain
            self.rebuild_state()
            # Rebuild DB blocks/transactions for the new chain
            with self.db.conn:
                self.db.reset_state()
                self._apply_genesis()
                for block in self.chain:
                    self.db.save_block(block)
            self.sync_transaction_pool()
            consensus_applied = True
            logger.info(f"Chain replaced — new length: {len(self.chain)}")
        else:
            # Collect potential uncle blocks from peers
            for node in network:
                try:
                    response = requests.get(f'http://{node}/get_chain', timeout=5)
                    if response.status_code == 200:
                        other_chain = response.json()['chain']
                        for block in other_chain:
                            if block not in self.chain and self.is_valid_uncle(block):
                                self.uncle_blocks.append(block)
                except requests.RequestException:
                    pass

        return consensus_applied
