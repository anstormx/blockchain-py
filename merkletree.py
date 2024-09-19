import hashlib
import json
from typing import List, Dict

class MerkleTree:
    def __init__(self, transactions: List[dict]):
        self.transactions = transactions
        self.tree = self.build_tree()

    def build_tree(self) -> List[List[str]]:
        tree = [self.hash_transaction(tx) for tx in self.transactions]
        
        while len(tree) > 1:
            tree = self.build_tree_level(tree)
        
        return tree

    def build_tree_level(self, level: List[str]) -> List[str]:
        new_level = []
        for i in range(0, len(level), 2):
            left = level[i]
            right = level[i + 1] if i + 1 < len(level) else left
            new_level.append(self.hash_pair(left, right))
        return new_level

    def hash_transaction(self, transaction: dict) -> str:
        return hashlib.sha256(json.dumps(transaction, sort_keys=True).encode()).hexdigest()

    def hash_pair(self, left: str, right: str) -> str:
        return hashlib.sha256(f"{left}{right}".encode()).hexdigest()

    def get_root(self) -> str:
        return self.tree[0] if self.tree else ""

    def get_proof(self, transaction: dict) -> List[Dict[str, str]]:
        tx_hash = self.hash_transaction(transaction)
        index = self.transactions.index(transaction)
        proof = []
        for level in range(len(self.tree)):
            companion_index = index + 1 if index % 2 == 0 else index - 1
            if companion_index < len(self.tree[level]):
                proof.append({
                    'position': 'right' if index % 2 == 0 else 'left',
                    'data': self.tree[level][companion_index]
                })
            index //= 2
        return proof

    @staticmethod
    def verify_proof(tx_hash: str, proof: List[Dict[str, str]], root: str) -> bool:
        result = tx_hash
        for step in proof:
            if step['position'] == 'right':
                result = hashlib.sha256(f"{result}{step['data']}".encode()).hexdigest()
            else:
                result = hashlib.sha256(f"{step['data']}{result}".encode()).hexdigest()
        return result == root