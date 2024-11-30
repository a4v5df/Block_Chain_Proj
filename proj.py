import json
import hashlib
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import ec

# UTXO 집합, TX 집합, 스택 초기화
global_utxo_set = []
global_transaction_set = []
global_stack = []

def load_utxo(utxo_file="UTXOes.json"):
    global global_utxo_set
    with open(utxo_file, 'r') as file:
        utxos = json.load(file)
 
        parsing_utxos = []
        for utxo in utxos:
            if all(key in utxo for key in ["txid", "output_index", "amount", "locking_script"]):
                parsing_utxos.append({
                    "txid": utxo["txid"],
                    "output_index": int(utxo["output_index"]),
                    "amount": int(utxo["amount"]),
                    "locking_script": utxo["locking_script"]
                })
            else:
                print(f"UTXO 데이터 에러: {utxo}")
        global_utxo_set = parsing_utxos


# 트랜잭션 파일에서 데이터를 로드
def load_transactions(transaction_file="transactions.json"):
    global global_transaction_set

    with open(transaction_file, 'r') as file:
        transactions = json.load(file)

    parsing_transactions = []
    for transaction in transactions:
        # TX 형식 디버깅용
        if "tx" not in transaction or not isinstance(transaction["tx"], dict):
            print(f"트랜잭션 데이터 에러: {transaction}")
            continue  

        tx_data = transaction["tx"]

        # input 파싱
        if "input" in tx_data and all(key in tx_data["input"] for key in ["utxo", "unlocking_script"]):
            parsed_input = {
                "utxo": tx_data["input"]["utxo"],
                "unlocking_script": tx_data["input"]["unlocking_script"]
            }
        else:
            print(f"트랜잭션 input 데이터 에러: {tx_data.get('input', 'None')}")
            continue  # 잘못된 데이터는 건너뜀

        # output 파싱 
        outputs = []
        if "outputs" in tx_data and isinstance(tx_data["outputs"], list):
            for tx_output in tx_data["outputs"]:
                if all(sub_key in tx_output for sub_key in ["amount", "locking_script"]):
                    outputs.append({
                        "amount": int(tx_output["amount"]),
                        "locking_script": tx_output["locking_script"]
                    })
                else:
                    print(f"트랜잭션 output 데이터 에러: {tx_output}")
        else:
            print(f"트랜잭션 outputs 데이터 에러: {tx_data.get('outputs', 'None')}")
            continue  # 잘못된 데이터는 건너뜀

        parsing_transactions.append({
            "input": parsed_input,
            "outputs": outputs
        })
    
    global_transaction_set = parsing_transactions



# SHA256, RIPEMD160 해시 함수 구현
def hash_function(data):
    
    sha256_hash = hashlib.sha256(data.encode()).digest()   # ripemd로 한번 더 hash할 경우 .digest() 사용해서 바이너리로 전달
    ripemd160_hash = hashlib.new('ripemd160')
    ripemd160_hash.update(sha256_hash)
    return ripemd160_hash.hexdigest()


# ECDSA 서명 검증
def verify_signature(public_key, signature, message):
    try:
        public_key = load_pem_public_key(public_key.encode(), backend=default_backend())  # 해당 함수에서 pk가 secp256k1 기반이면 그에 맞춰 자동으로 처리 
        public_key.verify(bytes.fromhex(signature), message.encode(), ec.ECDSA(hashes.SHA256()))
        return True
    except Exception as e:
        print(f"서명 검증 실패: {e}")
        return False

# 스크립트를 실행하여 검증(명령어, 조건문 로직 추가하고 수정하기)
def execute_scripts(unlocking_script, locking_script):
    
    global global_stack
    combined_script = unlocking_script.split() + locking_script.split()
    
    pc = 0  # 조건문에서 Program counter로 사용
    skip_block = False  # 플래그를 사용하여 조건문 블록 건너뛰기

    while pc < len(combined_script):
        op = combined_script[pc]

        if op == "IF":
            if not global_stack:
                return False
            
            condition = global_stack.pop()
            if not condition:  # False인 경우 ELSE 또는 ENDIF로 스킵
                skip_block = True
                while pc < len(combined_script) and combined_script[pc] not in ["ELSE", "ENDIF"]:
                    pc += 1
            else:  # True인 경우 블록 실행
                skip_block = False

        elif op == "ELSE":
            if not skip_block:  # 이미 실행 중인 경우 ELSE 이후를 건너뜀
                skip_block = True
                while pc < len(combined_script) and combined_script[pc] != "ENDIF":
                    pc += 1
            else:  # 실행하지 않는 ELSE 블록에 도달하면 플래그 초기화
                skip_block = False

        elif op == "ENDIF":
            skip_block = False  # 조건문 종료, 플래그 초기화

        if skip_block:  # 블록을 건너뛰는 상태라면 pc를 증가시키고 continue
            pc += 1
            continue

        if op == "DUP":
            if global_stack:
                global_stack.append(global_stack[-1])
            else:
                return False
            
        elif op == "HASH":
            if global_stack:
                global_stack.append(hash_function(global_stack.pop()))   # 여기쯤 뭔가 잘못됨, TX 생성 코드에도 같은 해시 함수를 쓰는데 값이 다르게 나옴
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
                message = create_message(transaction)
                if not verify_signature(public_key, signature, message):
                    return False
                global_stack.append(True)
            else:
                return False
                
        elif op == "CHECKSIGVERIFY":
            if len(global_stack) >= 2:
                signature = global_stack.pop()
                public_key = global_stack.pop()
                message = create_message(transaction)
                if not verify_signature(public_key, signature, message):
                    return False
            else:
                return False


        elif op == "CHECKMULTISIG":
            if len(global_stack) < 3:
                return False
            
            num_signatures = int(global_stack.pop())
            num_pubkeys = int(global_stack.pop())
            
            if len(global_stack) < num_pubkeys + num_signatures:
                return False

            pubkeys = [global_stack.pop() for _ in range(num_pubkeys)]
            signatures = [global_stack.pop() for _ in range(num_signatures)]
            # 각각 검증
            for signature in signatures:
                verified = False
                for pubkey in pubkeys:
                    create_message(transaction)
                    if verify_signature(pubkey, signature, message):  
                        verified = True
                        pubkeys.remove(pubkey)  # 사용한 키 제거
                        break
                if not verified:
                    return False
            
            global_stack.append(True)


        elif op == "CHECKMULTISIGVERIFY":
            if len(global_stack) < 3:
                return False

            num_signatures = int(global_stack.pop())
            num_pubkeys = int(global_stack.pop())

            if len(global_stack) < num_pubkeys + num_signatures:
                return False

            pubkeys = [global_stack.pop() for _ in range(num_pubkeys)]
            signatures = [global_stack.pop() for _ in range(num_signatures)]

            # 각각 검증
            for signature in signatures:
                verified = False
                for pubkey in pubkeys:
                    create_message(transaction)
                    if verify_signature(pubkey, signature, message):
                        verified = True
                        pubkeys.remove(pubkey)  
                        break
                if not verified:
                    return False 

        elif op == "TRUE":
            global_stack.append(True)
        elif op == "FALSE":
            global_stack.append(False)
        else:
            global_stack.append(op)
    
        pc += 1
        print(f"{op},{global_stack}","\n"*5)
        print(f"{pc}")
    return global_stack == [True]

# 메시지 생성 함수
def create_message(transaction):
    tx_str = json.dumps(transaction)
    return hashlib.sha256(tx_str.encode()).hexdigest()


# 트랜잭션 검증
def verify_transaction(transaction):
    tx_input = transaction['input']
    utxo = find_utxo(tx_input['utxo'])
    if not utxo:
        return False
    
    # 금액 검증
    if utxo['amount'] < sum([i['amount'] for i in transaction['outputs']]):
        return False
    
    # 스크립트 검증
    unlocking_script = tx_input['unlocking_script']
    locking_script = utxo['locking_script']
    global global_stack
    global_stack.clear()
    if not execute_scripts(unlocking_script, locking_script):
        return False
    
    update_utxo_set(transaction, utxo)  # 검증이 참인 경우 UTXO 업데이트 여기서 실행
    return True


# Txid 생성
def calculate_txid(transaction):
    tx_str = json.dumps(transaction)
    return hashlib.sha256(tx_str.encode()).hexdigest()  


# 특정 UTXO ID를 찾아서 반환
def find_utxo(utxo_id):
    for utxo in global_utxo_set:
        if f"{utxo['txid']}:{utxo['output_index']}" == utxo_id:
            print("만족하는 UTXO 있음!!")
            return utxo
    print("만족하는 UTXO가 없음")

# UTXO 집합 업데이트
def update_utxo_set(transaction, utxo):
    global global_utxo_set  
    global_utxo_set.remove(utxo)
    txid = calculate_txid(transaction)
    # 새로운 UTXO 추가
    for idx, tx_output in enumerate(transaction['outputs']):
        new_utxo = {
            "txid": txid,
            "output_index": idx,
            "amount": tx_output['amount'],
            "locking_script": tx_output['locking_script']
        }
        global_utxo_set.append(new_utxo)

def process_transactions():
    load_transactions()
    load_utxo()
    global global_transaction_set

    for transaction in global_transaction_set:
        print(f"Processing transaction : {transaction}")
        if verify_transaction(transaction):
            print("Transaction valid")

        else:
            print("Transaction invalid")
        print("="*100,"\n"*5)

process_transactions()
