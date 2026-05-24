import hashlib, hmac, os, secrets, base64, struct, time
from typing import Dict, List, Optional, Tuple


class NeonHashPro:
    """Professional-grade hashing, KDF, and cryptographic utilities."""

    def __init__(self, iterations: int = 260000, memory_cost: int = 65536):
        self.iterations = iterations
        self.memory_cost = memory_cost

    def pbkdf2(self, password: str, salt: Optional[bytes] = None, iterations: Optional[int] = None) -> Dict:
        s = salt or secrets.token_bytes(32)
        itr = iterations or self.iterations
        dk = hashlib.pbkdf2_hmac("sha256", password.encode(), s, itr)
        return {
            "hash": dk.hex(), "salt": s.hex(),
            "iterations": itr, "algorithm": "PBKDF2-HMAC-SHA256",
            "length": len(dk)
        }

    def scrypt(self, password: str, salt: Optional[bytes] = None) -> Dict:
        s = salt or secrets.token_bytes(32)
        dk = hashlib.scrypt(password.encode(), salt=s, n=16384, r=8, p=1)
        return {"hash": dk.hex(), "salt": s.hex(), "algorithm": "scrypt", "n": 16384, "r": 8, "p": 1}

    def verify_pbkdf2(self, password: str, stored_hash: str, salt_hex: str, iterations: int = None) -> bool:
        salt = bytes.fromhex(salt_hex)
        itr = iterations or self.iterations
        new = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, itr)
        return hmac.compare_digest(new.hex(), stored_hash)

    def totp(self, secret: str, window: int = 30) -> str:
        """Generate TOTP token (RFC 6238)."""
        key = base64.b32decode(secret.upper() + "=" * ((8 - len(secret) % 8) % 8))
        t = int(time.time()) // window
        msg = struct.pack(">Q", t)
        h = hmac.new(key, msg, hashlib.sha1).digest()
        offset = h[-1] & 0x0F
        code = struct.unpack(">I", h[offset:offset+4])[0] & 0x7FFFFFFF
        return f"{code % 1000000:06d}"

    def generate_secret(self, length: int = 32) -> str:
        return base64.b32encode(secrets.token_bytes(length)).decode().rstrip("=")

    def chain_hash(self, data_list: List[str], algo: str = "sha256") -> List[str]:
        """Create a hash chain (blockchain-style)."""
        chain = []
        prev = "0" * 64
        for data in data_list:
            combined = prev + data
            h = hashlib.new(algo, combined.encode()).hexdigest()
            chain.append(h)
            prev = h
        return chain

    def merkle_root(self, leaves: List[str]) -> str:
        """Compute Merkle tree root hash."""
        if not leaves:
            return ""
        nodes = [hashlib.sha256(l.encode()).hexdigest() for l in leaves]
        while len(nodes) > 1:
            if len(nodes) % 2 == 1:
                nodes.append(nodes[-1])
            nodes = [hashlib.sha256((nodes[i] + nodes[i+1]).encode()).hexdigest() for i in range(0, len(nodes), 2)]
        return nodes[0]

    def argon2_simulate(self, password: str, salt: Optional[bytes] = None) -> Dict:
        """Simulated Argon2-like hash (uses scrypt internally)."""
        s = salt or secrets.token_bytes(16)
        dk = hashlib.scrypt(password.encode(), salt=s, n=self.memory_cost, r=8, p=1)
        return {"hash": dk.hex(), "salt": s.hex(), "algorithm": "Argon2-simulated", "memory": self.memory_cost}

    def fingerprint(self, data: str) -> str:
        """Generate human-readable fingerprint."""
        h = hashlib.sha256(data.encode()).hexdigest()
        return ":".join(h[i:i+4].upper() for i in range(0, 32, 4))
