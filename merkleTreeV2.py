import hashlib
import json
from typing import List, Dict, Optional

class MerkleTree:
    """
    SHA-3 based Merkle Tree implementation for blockchain transaction integrity.
    
    Features:
    - SHA3-256 hashing (quantum-resistant, future-proof)
    - Canonical hash ordering for deterministic roots
    - Full tree storage for Merkle proof generation
    - Efficient verification of transaction inclusion
    """
    
    def __init__(self, transactions: List[dict]):
        """
        Initialize Merkle tree from a list of transactions.
        
        Args:
            transactions: List of transaction dictionaries
        """
        if not transactions:
            raise ValueError("Cannot create Merkle tree from empty transaction list")
        
        self.transactions = transactions
        self.leaves = [self.hash_transaction(tx) for tx in transactions]
        self.tree = self.build_tree()

    def build_tree(self) -> List[List[str]]:
        """
        Build complete Merkle tree structure (all levels).
        
        Returns:
            List of levels, where tree[0] is leaves and tree[-1] is root
        """
        if not self.leaves:
            return []
        
        tree = [self.leaves]
        current_level = self.leaves
        
        # Build tree bottom-up until we reach the root
        while len(current_level) > 1:
            current_level = self.build_tree_level(current_level)
            tree.append(current_level)
        
        return tree

    def build_tree_level(self, level: List[str]) -> List[str]:
        """
        Build next level of tree by pairing and hashing nodes.
        
        Args:
            level: Current level of hashes
            
        Returns:
            Next level with paired hashes
        """
        new_level = []
        for i in range(0, len(level), 2):
            left = level[i]
            right = level[i + 1] if i + 1 < len(level) else left
            new_level.append(self.hash_pair(left, right))
        return new_level

    def hash_transaction(self, transaction: dict) -> str:
        """
        Hash a transaction using SHA3-256.
        
        Args:
            transaction: Transaction dictionary
            
        Returns:
            Hex string of transaction hash
        """
        # Canonical JSON encoding for consistent hashing
        tx_json = json.dumps(transaction, sort_keys=True, separators=(',', ':'))
        return hashlib.sha3_256(tx_json.encode('utf-8')).hexdigest()

    def hash_pair(self, left: str, right: str) -> str:
        """
        Hash a pair of nodes with canonical ordering.
        
        Canonical ordering ensures deterministic roots regardless of 
        left/right assignment in the tree structure.
        
        Args:
            left: Left child hash
            right: Right child hash
            
        Returns:
            SHA3-256 hash of the sorted pair
        """
        # Sort hashes for canonical ordering (prevents malleability)
        if left <= right:
            combined = left + right
        else:
            combined = right + left
        
        return hashlib.sha3_256(combined.encode('utf-8')).hexdigest()

    def get_root(self) -> str:
        """
        Get the Merkle root hash.
        
        Returns:
            Root hash as hex string, or empty string if tree is empty
        """
        if not self.tree or not self.tree[-1]:
            return ""
        return self.tree[-1][0]

    def get_proof(self, transaction: dict) -> List[Dict[str, str]]:
        """
        Generate Merkle proof for a transaction.
        
        Args:
            transaction: Transaction to prove inclusion of
            
        Returns:
            List of proof steps with sibling hashes and positions
            
        Raises:
            ValueError: If transaction not found in tree
        """
        try:
            index = self.transactions.index(transaction)
        except ValueError:
            raise ValueError("Transaction not found in Merkle tree")
        
        proof = []
        
        # Traverse from leaves to root, collecting sibling hashes
        for level in range(len(self.tree) - 1):  # Exclude root level
            # Calculate sibling index
            if index % 2 == 0:  # Current node is left child
                sibling_index = index + 1
                position = 'right'
            else:  # Current node is right child
                sibling_index = index - 1
                position = 'left'
            
            # Add sibling to proof if it exists
            if sibling_index < len(self.tree[level]):
                proof.append({
                    'position': position,
                    'data': self.tree[level][sibling_index]
                })
            
            # Move to parent index in next level
            index //= 2
        
        return proof

    def verify_proof(tx_hash: str, proof: List[Dict[str, str]], root: str) -> bool:
        """
        Verify a Merkle proof.
        
        Args:
            tx_hash: Hash of the transaction to verify
            proof: Merkle proof (list of sibling hashes with positions)
            root: Expected Merkle root
            
        Returns:
            True if proof is valid, False otherwise
        """
        current_hash = tx_hash
        
        for step in proof:
            sibling = step['data']
            
            # Apply canonical ordering (same as hash_pair)
            if current_hash <= sibling:
                combined = current_hash + sibling
            else:
                combined = sibling + current_hash
            
            current_hash = hashlib.sha3_256(combined.encode('utf-8')).hexdigest()
        
        return current_hash == root
