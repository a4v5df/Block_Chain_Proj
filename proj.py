import json
import re
import hashlib
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import ec

# UTXO 집합, TX 집합, 스택 초기화
global_utxo_set = []
global_transaction_set = []
global_stack = []
done_transaction = []

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

# PEM 형식에 맞춰서 스크립트를 적절히 파싱
def parsing_script(script):
 
    pem_pattern = r"(-----BEGIN PUBLIC KEY-----[\s\S]+?-----END PUBLIC KEY-----\n)"
    pem_blocks = re.findall(pem_pattern, script)
    
    # PEM 블록을 대체한 띄워쓰기 단위로 나눠진 스크립트
    script_without_pem = re.sub(pem_pattern, " <PEM_BLOCK> ", script)
    command_list = script_without_pem.split()
    
    # PEM 블록을 tokens에 다시 삽입
    parsed_script = []
    pem_index = 0
    for command in command_list:
        if command == "<PEM_BLOCK>":
            parsed_script.append(pem_blocks[pem_index])
            pem_index += 1
        else:
            parsed_script.append(command)
    
    return parsed_script


# 스크립트를 실행하여 검증(명령어, 조건문 로직 추가하고 수정하기)
def execute_scripts(unlocking_script = None, locking_script = None, transaction = None):

    global global_stack

    p2sh_flag = False # P2SH 플래그
    locking_script = parsing_script(locking_script)
    if locking_script[-2] == 'EQUALVERIFY':  # P2SH인지 확인(마지막 값은 "CHECKFINALRESULT"니까 인덱스는 -2)
        p2sh_flag = True
        combined_script = [unlocking_script] + locking_script

    else:
        unlocking_script = parsing_script(unlocking_script)
        combined_script = unlocking_script + locking_script
        
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
                print("failed")
                print(f"failed at {op}")
                return False
            
        elif op == "HASH":
            if global_stack:
                global_stack.append(hash_function(global_stack.pop()))  
            else:
                print("failed")
                print(f"failed at {op}")
                return False
            
        elif op == "EQUAL":
            if len(global_stack) >= 2:
                a, b = global_stack.pop(), global_stack.pop()
                if a == b:
                    global_stack.append(a == b) 
                else: 
                    print("failed")
                    print(f"failed at {op}")
                    return False
            else:
                print("failed")
                print(f"failed at {op}")
                return False
            
        elif op == "EQUALVERIFY":
            if len(global_stack) >= 2:
                a, b = global_stack.pop(), global_stack.pop()
                if a != b:
                    print("failed")
                    print(f"failed at {op}")
                    return False
            else:
                print("failed")
                print(f"failed at {op}")
                return False
            
        elif op == "CHECKSIG":
            if len(global_stack) >= 2:
                public_key = global_stack.pop()
                signature = global_stack.pop()
                message = "test_message"
                if not verify_signature(public_key, signature, message):
                    print("failed")
                    print(f"failed at {op}")    
                    return False
                else:
                    global_stack.append(True)
            else:
                print("failed")
                print(f"failed at {op}")
                return False
                
        elif op == "CHECKSIGVERIFY":
            if len(global_stack) >= 2:
                public_key = global_stack.pop()
                signature = global_stack.pop()
                message = "test_message"
                if not verify_signature(public_key, signature, message):
                    print("failed")
                    print(f"failed at {op}")
                    return False  
            else:
                print("failed")
                print(f"failed at {op}")
                return False


        elif op == "CHECKMULTISIG":
            if len(global_stack) < 3:
                print("failed")
                print(f"failed at {op}")
                return False
            
            num_pubkeys = int(global_stack.pop())
            pubkey_list = [global_stack.pop() for _ in range(num_pubkeys)]

            num_signatures = int(global_stack.pop())
            signature_list = [global_stack.pop() for _ in range(num_signatures)]
            # 각각 검증
            for signature in signature_list:
                for pubkey in pubkey_list:
                    message = "test_message"
                    if verify_signature(pubkey, signature, message):  
                        pubkey_list.remove(pubkey)  # 사용한 키 제거
                        signature_list.remove(signature) # 참인 서명 제거
                        break

            if signature_list == []:    
                global_stack.append(True)
            else:
                print("failed")
                print(f"failed at {op}")
                return False


        elif op == "CHECKMULTISIGVERIFY":
            if len(global_stack) < 3:
                print("failed")
                print(f"failed at {op}")
                return False
            
            num_pubkeys = int(global_stack.pop())
            pubkey_list = [global_stack.pop() for _ in range(num_pubkeys)]

            num_signatures = int(global_stack.pop())
            signature_list = [global_stack.pop() for _ in range(num_signatures)]
            # 각각 검증
            for signature in signature_list:
                for pubkey in pubkey_list:
                    message = "test_message"
                    if verify_signature(pubkey, signature, message):  
                        pubkey_list.remove(pubkey)  # 사용한 키 제거
                        signature_list.remove(signature) # 참인 서명 제거
                        break
                    
            if signature_list != []:    
                print("failed")
                print(f"failed at {op}")
                return False
            else:
                global_stack.append(True)
        
        elif op == "CHECKFINALRESULT":
            if len(global_stack) == 1 and global_stack.pop() == True:
                
                # P2SH이고, 실행결과가 True일때 Redeem해서 재귀함수로 스크립트 실행
                if p2sh_flag == True:
                    if execute_scripts(unlocking_script, "", transaction):
                        return True
                    else:
                        return False
                    
                return True
            else:
                return False
        
        else:
            global_stack.append(op)
    
        pc += 1


# 트랜잭션 검증
def verify_transaction(transaction):
    tx_input = transaction['input']
    utxo = find_utxo(tx_input['utxo'])

    print(f"transaction : {calculate_txid(transaction)}")  # 출력형식
    print(f"input : {tx_input}")
    for idx, i in enumerate(transaction['outputs']):
        print(f"output: {idx}  {i}")
    print("validity check :", end =" ")

    if not utxo:
        return False
    
    # 금액 검증
    if utxo['amount'] < sum([i['amount'] for i in transaction['outputs']]):
        print("failed")
        print("failed at amount verify")
        return False
    
    # 스크립트 검증
    unlocking_script = tx_input['unlocking_script']
    locking_script = utxo['locking_script']
    global global_stack
    global_stack.clear()
    if not execute_scripts(unlocking_script, locking_script, transaction):
        return False
    
    print("passed")
    update_utxo_set(transaction, utxo)  # 검증이 참인 경우 UTXO 업데이트 여기서 실행
    return True


# Txid 
def calculate_txid(transaction):
    tx_str = json.dumps(transaction)
    return hashlib.sha256(tx_str.encode()).hexdigest()  


# 특정 UTXO ID를 찾아서 반환
def find_utxo(utxo_id):
    for utxo in global_utxo_set:
        if f"{utxo['txid']}:{utxo['output_index']}" == utxo_id:
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

def snapshot_transactions():
    print("=== Snapshot Transactions ===")
    for transaction in done_transaction:  # done_trasaction[0]은 transaction, [1]은 vaildity(passed 또는 failed)
        txid = calculate_txid(transaction[0])
        print(f"transaction: {txid}, validity check: {transaction[1]}")
    
    print("="*50)

def snapshot_utxoset():
    print("=== Snapshot UTXO Set ===")
    for idx, utxo in enumerate(global_utxo_set):    
        print(f"utxo{idx}: {utxo['txid']}, output index: {utxo['output_index']}, amount: {utxo['amount']}, locking script: {utxo['locking_script']}")
    print("="*50)


def process_transactions():  # 트랜잭션 처리 실행 프로세스
    load_transactions()
    load_utxo()
    global global_transaction_set

    for transaction in global_transaction_set:
        if verify_transaction(transaction):
            print("Transaction valid")
            done_transaction.append([transaction,"passed"])
            snapshot_transactions()
            snapshot_utxoset()
        else:
            print("Transaction invalid")
            done_transaction.append([transaction,"failed"])
            snapshot_transactions()
            snapshot_utxoset()


process_transactions()
