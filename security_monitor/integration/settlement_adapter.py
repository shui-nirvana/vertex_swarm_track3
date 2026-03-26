import logging
import hashlib
import time
from typing import Dict, Any, Optional

logger = logging.getLogger(__name__)


class SettlementAdapter:
    """
    Adapter for settlement integration.
    Handles balance checks, token transfers, and gas estimation.

    Modes:
    - simulation: Uses in-memory ledger (default if no RPC URL provided).
    - real: Connects to a blockchain node via RPC (requires implementation).
    """

    def __init__(self, rpc_url: Optional[str] = None, private_key: Optional[str] = None):
        self.rpc_url = rpc_url
        self.private_key = private_key
        self.mode = "real" if rpc_url else "simulation"

        self._balances = {
            "agent-scout": {"USDT": 1000.0, "ETH": 10.0},
            "agent-guardian": {"USDT": 5000.0, "ETH": 50.0},
            "agent-worker-0": {"USDT": 100.0, "ETH": 1.0},
            "agent-worker-1": {"USDT": 100.0, "ETH": 1.0},
        }

        if self.mode == "real":
            logger.warning("Settlement adapter initialized in REAL mode. Ensure RPC URL is valid.")

    def get_balance(self, address: str, token: str) -> float:
        if self.mode == "simulation":
            return self._balances.get(address, {}).get(token, 0.0)
        logger.error("Real get_balance not implemented")
        return 0.0

    def check_allowance(self, _owner: str, _spender: str, token: str) -> float:
        if self.mode == "simulation":
            return float("inf")
        logger.error("Real check_allowance not implemented")
        return 0.0

    def estimate_gas(self, from_address: str, to_address: str, amount: float, token: str) -> int:
        if self.mode == "simulation":
            return 21000
        return 0

    def transfer(self, from_address: str, to_address: str, amount: float, token: str) -> Dict[str, Any]:
        if self.mode == "simulation":
            current_bal = self.get_balance(from_address, token)
            if current_bal < amount:
                return {
                    "success": False,
                    "error": f"Insufficient balance: {current_bal} < {amount}"
                }

            self._balances.setdefault(to_address, {})
            self._balances[to_address][token] = self._balances.get(to_address, {}).get(token, 0.0) + amount
            self._balances[from_address][token] -= amount

            tx_seed = f"{from_address}|{to_address}|{amount}|{token}|{time.time()}"
            tx_hash = "0x" + hashlib.sha256(tx_seed.encode()).hexdigest()

            logger.info(f"Simulated transfer: {amount} {token} from {from_address} to {to_address} (Tx: {tx_hash})")

            return {
                "success": True,
                "tx_hash": tx_hash,
                "block_number": 12345678,
                "gas_used": 21000
            }

        raise NotImplementedError("Real settlement provider transfer not implemented")

    def sign_message(self, message: str) -> str:
        if self.mode == "simulation":
            return f"0x{hashlib.sha256((message + 'signed').encode()).hexdigest()}"
        return ""

    def wait_for_tx(self, tx_hash: str, _timeout: int = 30) -> Dict[str, Any]:
        if self.mode == "simulation":
            return {"status": 1, "blockNumber": 12345678}
        return {}


EVMSettlementAdapter = SettlementAdapter
