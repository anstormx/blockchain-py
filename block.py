import time
import json
import hashlib
from dataclasses import dataclass, asdict
from typing import List, Optional

def double_sha256(data: bytes) -> bytes:
    return hashlib.sha256(hashlib.sha256(data).digest()).digest() # double SHA256

def to_compact_json(obj) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")

def merkle_root_from_txids(txids_hex: List[str]) -> str:
    if not txids_hex:
        return "00" * 32

    # Work on bytes
    level = [bytes.fromhex(h) for h in txids_hex]

    while len(level) > 1:
        next_level = []
        for i in range(0, len(level), 2):
            left = level[i]
            right = level[i + 1] if i + 1 < len(level) else level[i]  # duplicate last if odd
            next_level.append(double_sha256(left + right)) # double SHA256 of concatenated pair
        level = next_level

    return level[0].hex()

@dataclass(frozen=True)
class Transaction:
    sender: str
    recipient: str
    amount: float
    nonce: int
    timestamp: int

    @property
    def txid(self) -> str:
        payload = to_compact_json(asdict(self)) # convert transaction into canonical JSON string
        return double_sha256(payload).hex()

class Block:
    def __init__(
        self,
        version: int,
        difficulty_target: str,
        nonce: int,
        previous_hash: str,
        timestamp: int,
        transactions: Optional[List[Transaction]] = None,
    ):
        # Header fields
        self.timestamp = timestamp
        self.version = version
        self.merkle_root = None  # filled after adding txs
        self.difficulty_target = difficulty_target
        self.nonce = nonce
        self.previous_hash = previous_hash

        # Body
        self.transactions: List[Transaction] = transactions or []

        # Compute merkle root
        self.compute_merkle_root()

    def compute_merkle_root(self) -> None:
        txids = [tx.txid for tx in self.transactions]
        self.merkle_root = merkle_root_from_txids(txids)

    def get_header(self) -> dict:
        return {
            "timestamp": self.timestamp,
            "version": self.version,
            "merkle_root": self.merkle_root,
            "difficulty_target": self.difficulty_target,
            "nonce": self.nonce,
            "previous_hash": self.previous_hash,
        }


if __name__ == "__main__":
    t0 = int(time.time())

    # Sample transactions
    tx1 = Transaction(sender="alice", recipient="bob",   amount=1.25, nonce=1, timestamp=t0)
    tx2 = Transaction(sender="carol", recipient="dave",  amount=3.50, nonce=7, timestamp=t0 + 1)
    tx3 = Transaction(sender="miner", recipient="miner", amount=6.25, nonce=0, timestamp=t0 + 2)  # reward

    # Create a block with these transactions
    block = Block(
        version=1,
        difficulty_target="00000000000000000000000000000000000000000000000000000000000000",  # placeholder
        nonce=0,
        previous_hash="0000000000000000000000000000000000000000000000000000000000000000", # genesis
        timestamp=int(time.time()), # current time
        transactions=[tx1, tx2, tx3],
    )

    print("Transaction IDs:")
    for tx in block.transactions:
        print("  ", tx.txid)

    print("\nMerkle Root:", block.merkle_root)
    print("\nBlock Header:", block.get_header())
