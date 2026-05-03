from dataclasses import dataclass, field
from typing import Dict, List


@dataclass
class AccountState:
    address: str
    balance: float = 0.0
    nonce: int = -1           # -1 means no confirmed transactions yet
    account_type: int = 0

    def to_dict(self) -> dict:
        return {
            'address': self.address,
            'balance': self.balance,
            'nonce': self.nonce,
            'account_type': self.account_type,
        }


@dataclass
class StateDiff:
    block: dict

    # Balance deltas: positive = credit, negative = debit
    balance_changes: Dict[str, float] = field(default_factory=dict)

    # Nonce updates: address → new confirmed nonce value
    nonce_updates: Dict[str, int] = field(default_factory=dict)

    # New accounts to create (addresses not yet in the accounts table)
    new_accounts: Dict[str, dict] = field(default_factory=dict)

    # Transaction hashes that reverted (status=0)
    failed_txs: List[str] = field(default_factory=list)

    # Total gas consumed by all transactions in this block
    total_gas_used: int = 0

    def credit(self, address: str, amount: float) -> None:
        self.balance_changes[address] = self.balance_changes.get(address, 0.0) + amount

    def debit(self, address: str, amount: float) -> None:
        self.balance_changes[address] = self.balance_changes.get(address, 0.0) - amount

    def set_nonce(self, address: str, nonce: int) -> None:
        self.nonce_updates[address] = nonce

    def ensure_account(self, address: str, account_type: int = 0) -> None:
        """Register a new account if it doesn't already exist."""
        if address not in self.new_accounts:
            self.new_accounts[address] = {
                'balance': 0.0,
                'nonce': -1,
                'account_type': account_type,
            }
