import bcrypt

password = "Jitesh123".encode("utf-8")
hashed = bcrypt.hashpw(password, bcrypt.gensalt())
hash_str = hashed.decode()

print("="*70)
print("NEW PASSWORD HASH FOR secrets.toml")
print("="*70)
print(hash_str)
print("="*70)
print(f"Length: {len(hash_str)} characters (should be 60)")
print("="*70)