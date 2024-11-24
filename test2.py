
import hashlib

def sha256(data):
    return hashlib.sha256(data.encode()).hexdigest()

def ripemd160(data):
    ripemd = hashlib.new('ripemd160')
    ripemd.update(data)
    return ripemd.hexdigest()

def sha256_then_ripemd160(data):

    sha256_hash = hashlib.sha256(data.encode()).digest()
    

    ripemd160_hash = hashlib.new('ripemd160')
    ripemd160_hash.update(sha256_hash)
    return ripemd160_hash.hexdigest()

data = "Hello"

print("Original Data:", data)
print("SHA-256 Hash:", sha256(data))
print("RIPEMD-160 Hash (from plain text):", ripemd160(data.encode()))
print("RIPEMD-160 Hash (from SHA-256):", sha256_then_ripemd160(data))
