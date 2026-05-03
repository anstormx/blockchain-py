import sqlite3
import json
import hashlib
import logging
from typing import Optional, List, Tuple, Dict

logger = logging.getLogger(__name__)


class ChainDB:
    def __init__(self, db_path: str):
        self.db_path = db_path
        self.conn: Optional[sqlite3.Connection] = None

    # ── Lifecycle ─────────────────────────────────────────────────────────────

    def connect(self) -> None:
        self.conn = sqlite3.connect(self.db_path, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA journal_mode=WAL")
        self.conn.execute("PRAGMA foreign_keys=ON")
        self.conn.execute("PRAGMA synchronous=NORMAL")

    def close(self) -> None:
        if self.conn:
            self.conn.close()
            self.conn = None

    def initialize_schema(self) -> None:
        self.conn.executescript("""
            CREATE TABLE IF NOT EXISTS blocks (
                height          INTEGER PRIMARY KEY,
                block_hash      TEXT NOT NULL UNIQUE,
                previous_hash   TEXT NOT NULL,
                timestamp       TEXT NOT NULL,
                nonce           INTEGER NOT NULL,
                difficulty      INTEGER NOT NULL,
                block_time      REAL NOT NULL DEFAULT 0,
                merkle_root     TEXT NOT NULL,
                state_root      TEXT,
                gas_limit       INTEGER NOT NULL DEFAULT 10000000,
                gas_used        INTEGER NOT NULL DEFAULT 0,
                miner_address   TEXT NOT NULL DEFAULT '',
                uncle_hashes    TEXT NOT NULL DEFAULT '[]'
            );

            CREATE TABLE IF NOT EXISTS transactions (
                tx_hash         TEXT PRIMARY KEY,
                block_height    INTEGER NOT NULL REFERENCES blocks(height),
                tx_index        INTEGER NOT NULL,
                tx_type         INTEGER NOT NULL DEFAULT 0,
                sender          TEXT NOT NULL,
                receiver        TEXT NOT NULL DEFAULT '',
                amount          REAL NOT NULL DEFAULT 0.0,
                nonce           INTEGER NOT NULL DEFAULT 0,
                gas_price       REAL NOT NULL DEFAULT 0.0,
                gas_limit       INTEGER NOT NULL DEFAULT 21000,
                gas_used        INTEGER NOT NULL DEFAULT 21000,
                signature       TEXT,
                data            TEXT,
                status          INTEGER NOT NULL DEFAULT 1,
                UNIQUE(block_height, tx_index)
            );

            CREATE TABLE IF NOT EXISTS accounts (
                address         TEXT PRIMARY KEY,
                balance         REAL NOT NULL DEFAULT 0.0,
                nonce           INTEGER NOT NULL DEFAULT -1,
                account_type    INTEGER NOT NULL DEFAULT 0,
                code_hash       TEXT,
                storage_root    TEXT
            );

            CREATE TABLE IF NOT EXISTS uncle_blocks (
                uncle_hash      TEXT PRIMARY KEY,
                included_in     INTEGER NOT NULL REFERENCES blocks(height),
                uncle_data      TEXT NOT NULL
            );

            CREATE INDEX IF NOT EXISTS idx_tx_block   ON transactions(block_height);
            CREATE INDEX IF NOT EXISTS idx_tx_sender  ON transactions(sender);
        """)
        self.conn.commit()

    # ── Block operations ──────────────────────────────────────────────────────

    def save_block(self, block: dict) -> None:
        """Persist a block dict to the database (without committing — called inside a transaction)."""
        miner_address = self._extract_miner(block)
        uncle_hashes = json.dumps([
            self.hash_block(u) if isinstance(u, dict) else u
            for u in block.get('uncles', [])
        ])

        self.conn.execute("""
            INSERT OR REPLACE INTO blocks
            (height, block_hash, previous_hash, timestamp, nonce, difficulty,
             block_time, merkle_root, state_root, gas_limit, gas_used, miner_address, uncle_hashes)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            block['index'],
            self.hash_block(block),
            block['previous_hash'],
            block['timestamp'],
            block['nonce'],
            block['difficulty'],
            block.get('block_time', 0.0),
            block.get('merkleroot', ''),
            block.get('state_root'),
            block.get('gas_limit', 10_000_000),
            block.get('gas_used', 0),
            miner_address,
            uncle_hashes,
        ))

        for i, tx in enumerate(block.get('transactions', [])):
            self._save_transaction(tx, block['index'], i)

        for uncle in block.get('uncles', []):
            if isinstance(uncle, dict):
                uncle_hash = self.hash_block(uncle)
                try:
                    self.conn.execute("""
                        INSERT OR IGNORE INTO uncle_blocks (uncle_hash, included_in, uncle_data)
                        VALUES (?, ?, ?)
                    """, (uncle_hash, block['index'], json.dumps(uncle)))
                except Exception as e:
                    logger.warning(f"Could not save uncle {uncle_hash[:8]}: {e}")

    def _save_transaction(self, tx: dict, block_height: int, tx_index: int) -> None:
        tx_hash = self._tx_hash(tx)
        sender = tx.get('sender_address', '')
        is_coinbase = (sender == 'coinbase')
        tx_type = tx.get('tx_type', 1 if is_coinbase else 0)

        self.conn.execute("""
            INSERT OR IGNORE INTO transactions
            (tx_hash, block_height, tx_index, tx_type, sender, receiver,
             amount, nonce, gas_price, gas_limit, gas_used, signature, data, status)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            tx_hash,
            block_height,
            tx_index,
            tx_type,
            sender,
            tx.get('receiver_address', ''),
            float(tx.get('amount', 0)),
            int(tx.get('nonce', 0)),
            float(tx.get('gas_price', 0.0)),
            int(tx.get('gas_limit', 21_000)),
            int(tx.get('gas_used', 21_000 if not is_coinbase else 0)),
            tx.get('signature'),
            tx.get('data') or tx.get('bytecode'),
            int(tx.get('status', 1)),
        ))

    def load_chain(self) -> List[dict]:
        """Reconstruct the full chain list from DB on startup."""
        blocks = []
        rows = self.conn.execute("SELECT * FROM blocks ORDER BY height").fetchall()
        for row in rows:
            block = self._row_to_block(dict(row))
            blocks.append(block)
        return blocks

    def _row_to_block(self, row: dict) -> dict:
        """Convert a blocks-table row back to the block dict format used in-memory."""
        txs = self.get_transactions_for_block(row['height'])

        uncle_hashes = json.loads(row.get('uncle_hashes', '[]'))
        uncles = []
        for uh in uncle_hashes:
            uncle_row = self.conn.execute(
                "SELECT uncle_data FROM uncle_blocks WHERE uncle_hash = ?", (uh,)
            ).fetchone()
            if uncle_row:
                uncles.append(json.loads(uncle_row['uncle_data']))

        return {
            'index': row['height'],
            'timestamp': row['timestamp'],
            'previous_hash': row['previous_hash'],
            'transactions': txs,
            'merkleroot': row['merkle_root'],
            'difficulty': row['difficulty'],
            'nonce': row['nonce'],
            'block_time': row['block_time'],
            'uncles': uncles,
            'gas_limit': row['gas_limit'],
            'gas_used': row['gas_used'],
        }

    def get_chain_length(self) -> int:
        row = self.conn.execute("SELECT COUNT(*) as cnt FROM blocks").fetchone()
        return row['cnt'] if row else 0

    def get_transactions_for_block(self, block_height: int) -> List[dict]:
        rows = self.conn.execute(
            "SELECT * FROM transactions WHERE block_height = ? ORDER BY tx_index",
            (block_height,)
        ).fetchall()
        return [self._row_to_tx(dict(r)) for r in rows]

    def _row_to_tx(self, row: dict) -> dict:
        tx = {
            'sender_address': row['sender'],
            'receiver_address': row['receiver'],
            'amount': row['amount'],
            'nonce': row['nonce'],
            'signature': row['signature'],
            'tx_type': row['tx_type'],
            'gas_price': row['gas_price'],
            'gas_limit': row['gas_limit'],
            'gas_used': row['gas_used'],
            'status': row['status'],
        }
        if row.get('data'):
            tx['data'] = row['data']
        return tx

    def get_transaction_by_hash(self, tx_hash: str) -> Optional[dict]:
        row = self.conn.execute(
            "SELECT * FROM transactions WHERE tx_hash = ?", (tx_hash,)
        ).fetchone()
        return self._row_to_tx(dict(row)) if row else None

    def get_recent_transactions(self, limit: int = 50) -> List[dict]:
        rows = self.conn.execute(
            "SELECT * FROM transactions ORDER BY block_height DESC, tx_index DESC LIMIT ?",
            (limit,)
        ).fetchall()
        return [self._row_to_tx(dict(r)) for r in rows]

    # ── Account operations ────────────────────────────────────────────────────

    def get_account(self, address: str) -> Optional[dict]:
        row = self.conn.execute(
            "SELECT * FROM accounts WHERE address = ?", (address,)
        ).fetchone()
        return dict(row) if row else None

    def upsert_account(self, address: str, balance: float, nonce: int,
                       account_type: int = 0, code_hash: Optional[str] = None) -> None:
        self.conn.execute("""
            INSERT INTO accounts (address, balance, nonce, account_type, code_hash)
            VALUES (?, ?, ?, ?, ?)
            ON CONFLICT(address) DO UPDATE SET
                balance      = excluded.balance,
                nonce        = excluded.nonce,
                account_type = excluded.account_type,
                code_hash    = COALESCE(excluded.code_hash, code_hash)
        """, (address, balance, nonce, account_type, code_hash))

    def get_balance(self, address: str) -> float:
        row = self.conn.execute(
            "SELECT balance FROM accounts WHERE address = ?", (address,)
        ).fetchone()
        return float(row['balance']) if row else 0.0

    def get_nonce(self, address: str) -> int:
        row = self.conn.execute(
            "SELECT nonce FROM accounts WHERE address = ?", (address,)
        ).fetchone()
        return int(row['nonce']) if row else -1

    def get_all_accounts(self) -> List[dict]:
        rows = self.conn.execute(
            "SELECT * FROM accounts ORDER BY balance DESC"
        ).fetchall()
        return [dict(r) for r in rows]

    # ── Atomic state commit ───────────────────────────────────────────────────

    def apply_block_state_changes(self, state_diff) -> None:
        """
        Apply all state changes for a block in a single SQLite transaction.
        If anything raises, the entire transaction is rolled back.
        """
        with self.conn:  # context manager: commits on exit, rolls back on exception
            self.save_block(state_diff.block)

            # Apply balance changes and nonce updates together
            all_touched = set(state_diff.balance_changes) | set(state_diff.nonce_updates)
            for address in all_touched:
                current_bal = self.get_balance(address)
                current_nonce = self.get_nonce(address)
                new_bal = current_bal + state_diff.balance_changes.get(address, 0.0)
                new_nonce = state_diff.nonce_updates.get(address, current_nonce)
                account = state_diff.new_accounts.get(address, {})
                self.upsert_account(
                    address,
                    new_bal,
                    new_nonce,
                    account.get('account_type', 0),
                    account.get('code_hash'),
                )

            # Create accounts that have no balance/nonce change
            for address, account in state_diff.new_accounts.items():
                if address not in all_touched:
                    self.upsert_account(
                        address,
                        account.get('balance', 0.0),
                        account.get('nonce', -1),
                        account.get('account_type', 0),
                        account.get('code_hash'),
                    )

    def reset_state(self) -> None:
        """
        Drop all state tables and reinitialise schema.
        Used when applying a longer chain from consensus — full state replay follows.
        """
        with self.conn:
            self.conn.executescript("""
                DELETE FROM transactions;
                DELETE FROM blocks;
                DELETE FROM accounts;
                DELETE FROM uncle_blocks;
            """)

    # ── Helpers ───────────────────────────────────────────────────────────────

    @staticmethod
    def hash_block(block: dict) -> str:
        encoded = json.dumps(block, sort_keys=True).encode()
        return hashlib.sha256(hashlib.sha256(encoded).digest()).hexdigest()

    @staticmethod
    def _tx_hash(tx: dict) -> str:
        # Hash the core fields that uniquely identify a transaction
        core = {k: tx[k] for k in ('sender_address', 'receiver_address', 'amount', 'nonce')
                if k in tx}
        if 'data' in tx:
            core['data'] = tx['data']
        if 'bytecode' in tx:
            core['bytecode'] = tx['bytecode']
        return hashlib.sha3_256(json.dumps(core, sort_keys=True).encode()).hexdigest()

    @staticmethod
    def _extract_miner(block: dict) -> str:
        for tx in block.get('transactions', []):
            if tx.get('sender_address') == 'coinbase':
                return tx.get('receiver_address', '')
        return ''
