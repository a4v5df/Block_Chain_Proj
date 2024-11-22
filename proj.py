import json

# UTXO 집합 및 스택 초기화
global_utxo_set = []
global_stack = []

# UTXO 파일에서 데이터를 로드하여 UTXO 집합 초기화
def load_utxo(utxo_file):
    global global_utxo_set
    with open(utxo_file, 'r') as file:
        utxo = json.load(file)
        global_utxo_set = utxo

# 트랜잭션 파일에서 데이터 로드
def load_transactions(transaction_file):
    with open(transaction_file, 'r') as file:
        transactions = json.load(file)
        return transactions
    
# 특정 UTXO ID를 찾아서 반환
def find_utxo(utxo_id):
    for utxo in global_utxo_set:
        if f"{utxo['txid']}:{utxo['output_index']}" == utxo_id:
            return utxo
    return None

# SHA256, RIPEMD160 해시 함수 구현(라이브러리 찾앙서 채워넣기)
def hash_function(data):
    return 1

# (secp256k1 <- 얘로 써야함) ECDSA 서명 검증 (라이브러리 찾아보고 채워넣기)
def verify_signature():
    
    if 1 == 1:
        return True
    else:
        return False

# 스크립트를 실행하여 검증(명령어, 조건문 로직 추가하고 수정하기)
def execute_scripts(unlocking_script, locking_script):
    global global_stack
    combined_script = unlocking_script.split() + locking_script.split()

    for op in combined_script:
        if op == "DUP":
            if global_stack:
                global_stack.append(global_stack[-1])
            else:
                return False
        elif op == "HASH":
            if global_stack:
                global_stack.append(hash_function())
            else:
                return False
        elif op == "EQUAL":
            if len(global_stack) >= 2:
                a, b = global_stack.pop(), global_stack.pop()
                global_stack.append(a == b)
            else:
                return False
        elif op == "EQUALVERIFY":
            if len(global_stack) >= 2:
                a, b = global_stack.pop(), global_stack.pop()
                if a != b:
                    return False
            else:
                return False
        elif op == "CHECKSIG":
            if len(global_stack) >= 2:
                signature = global_stack.pop()
                public_key = global_stack.pop()
                message = ""  # 실제 트랜잭션 데이터넣기 ???
                if not verify_signature():
                    return False
                global_stack.append(True)
            else:
                return False
        elif op == "TRUE":
            global_stack.append(True)
        elif op == "FALSE":
            global_stack.append(False)
        else:
            global_stack.append(op)

    return global_stack == [True]

# 트랜잭션 검증
def verify_transaction(transaction):
    for tx_input in transaction['inputs']:
        utxo = find_utxo(tx_input['utxo'])
        if not utxo:
            return False

        unlocking_script = tx_input['unlocking_script']
        locking_script = utxo['locking_script']
        global global_stack
        global_stack.clear()
        if not execute_scripts(unlocking_script, locking_script):
            return False

    return True

# UTXO 집합 업데이트
def update_utxo_set(transaction):
    global global_utxo_set
    for tx_input in transaction['inputs']:
        utxo = find_utxo(tx_input['utxo'])
        if utxo:
            global_utxo_set.remove(utxo)

    for idx, tx_output in enumerate(transaction['outputs']):
        new_utxo = {
            "txid": "tx_hash_placeholder",
            "output_index": idx,
            "amount": tx_output['amount'],
            "locking_script": tx_output['locking_script']
        }
        global_utxo_set.append(new_utxo)
