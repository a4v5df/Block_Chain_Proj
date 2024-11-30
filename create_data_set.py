import hashlib
import json
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.backends import default_backend

def hash_function(data):
    sha256_hash = hashlib.sha256(data.encode()).digest()   # ripemd로 한번 더 hash할 경우 .digest() 사용해서 바이너리로 전달
    ripemd160_hash = hashlib.new('ripemd160')
    ripemd160_hash.update(sha256_hash)
    return ripemd160_hash.hexdigest()


def generate_key_pair():
    private_key = ec.generate_private_key(ec.SECP256K1(), default_backend())
    public_key = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode()
    return private_key, public_key

def create_signature(private_key, message):
    signature = private_key.sign(
        message.encode(),
        ec.ECDSA(hashes.SHA256())
    )
    return signature.hex()

def create_utxo_dataset():
    private_key, public_key = generate_key_pair()
    print("private:",private_key)
    print("public:",public_key)
    print("\n"*10)
    public_key_hash = hash_function(public_key)
    utxos = [
        {
            "txid": "tx1",
            "output_index": 0,
            "amount": 50,
            "locking_script": f"DUP HASH {public_key_hash} EQUALVERIFY CHECKSIG"  # P2PKH
        },
        {
            "txid": "tx2",
            "output_index": 1,
            "amount": 40,
            "locking_script": f"IF DUP HASH {public_key_hash} EQUALVERIFY CHECKSIG ELSE CHECKMULTISIG ENDIF"  # P2SH
        },
        {
            "txid": "tx3",
            "output_index": 2,
            "amount": 60,
            "locking_script": f"2 pubkey1 pubkey2 pubkey3 3 CHECKMULTISIG"  # Multisig
        }
    ]    
    return utxos, private_key, public_key, public_key_hash

def create_transaction_dataset(private_key, public_key, public_key_hash):
    message = "test_message"
    signature = create_signature(private_key, message)
    print("sig-------------------------->>:" ,signature)
    print(len(signature))
    
    public_key = delete_pem_headers(public_key)
    print("pubkey:", public_key)
    print("pubkey hash : ",hash_function(public_key))
    transactions = [
        {
            "tx": {
                "input": {
                    "utxo": "tx1:0",
                    "unlocking_script": f"{signature} {public_key}"  # P2PKH
                },
                "outputs": [
                    {
                        "amount": 30,
                        "locking_script": f"DUP HASH alice_hash EQUALVERIFY CHECKSIG"  # P2PKH
                    },
                    {
                        "amount": 20,
                        "locking_script": f"IF DUP HASH script_hash CHECKSIG ELSE CHECKMULTISIG ENDIF"  # P2SH
                    }
                ]
            }
        },
        {
            "tx": {
                "input": {
                    "utxo": "tx2:1",
                    "unlocking_script": f"{signature} {public_key} OP_IF OP_CHECKSIG OP_ELSE OP_CHECKMULTISIG OP_ENDIF"  # P2SH
                },
                "outputs": [
                    {
                        "amount": 40,
                        "locking_script": f"CHECKMULTISIG"  # Multisig
                    }
                ]
            }
        },
        {
            "tx": {
                "input": {
                    "utxo": "tx3:2",
                    "unlocking_script": f"{signature} pubkey1 pubkey2"  # Multisig 
                },
                "outputs": [
                    {
                        "amount": 60,
                        "locking_script": f"DUP HASH dave_hash EQUALVERIFY CHECKSIG"  # P2PKH
                    }
                ]
            }
        }
    ]    
    return transactions

def delete_pem_headers(public_key):
    lines = public_key.splitlines()
    key_data = ''.join(line for line in lines if not line.startswith("-----"))
    return key_data


utxo, private_key, public_key, public_key_hash = create_utxo_dataset()
print()
with open("UTXOes.json", 'w') as file:
        json.dump(utxo, file, indent=4)
        
transaction = create_transaction_dataset(private_key, public_key, public_key_hash)
with open("transactions.json", 'w') as file:
        json.dump(transaction, file, indent=4)
