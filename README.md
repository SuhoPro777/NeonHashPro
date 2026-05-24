# NeonHashPro 🔐

Professional darajadagi hash va kriptografik operatsiyalar kutubxonasi.

## Kalit so'zlar
`pbkdf2`, `scrypt`, `argon2`, `totp`, `merkle`, `chain`, `kdf`, `fingerprint`, `2fa`, `blockchain`

## O'rnatish
```bash
pip install neonhashpro
```

## Ishlatish

```python
from NeonHashPro import NeonHashPro

pro = NeonHashPro(iterations=260000)

hashed = pro.pbkdf2("supersecret_password")
print(f"PBKDF2 hash: {hashed['hash'][:32]}...")

is_valid = pro.verify_pbkdf2("supersecret_password", hashed['hash'], hashed['salt'])
print(f"Tekshiruv: {is_valid}")

secret = pro.generate_secret()
token = pro.totp(secret)
print(f"2FA token: {token}")

merkle = pro.merkle_root(["tx1", "tx2", "tx3", "tx4"])
print(f"Merkle root: {merkle[:32]}...")

fp = pro.fingerprint("user@example.com")
print(f"Fingerprint: {fp}")
```

## Real misol

```python
from NeonHashPro import NeonHashPro

pro = NeonHashPro()

# Foydalanuvchi ro'yxatdan o'tish
pwd = "P@ssw0rd!2024"
stored = pro.pbkdf2(pwd)

# Login
login_pwd = "P@ssw0rd!2024"
ok = pro.verify_pbkdf2(login_pwd, stored['hash'], stored['salt'])
print(f"Login: {'✅' if ok else '❌'}")

# 2FA
secret = pro.generate_secret()
code = pro.totp(secret)
print(f"2FA kodi: {code}")

# Blockchain tranzaksiyalar
txs = ["Alice→Bob: 5BTC", "Bob→Carol: 2BTC", "Carol→Dave: 1BTC"]
chain = pro.chain_hash(txs)
for i, (tx, h) in enumerate(zip(txs, chain)):
    print(f"Block {i+1}: {h[:16]}...")
```
