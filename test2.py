import json

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


def load_transactions(transaction_file="transactions.json"):
    global global_transaction_set

    with open(transaction_file, 'r') as file:
        transactions = json.load(file)

    parsing_transactions = []
    for transaction in transactions:
        # TX 형식 디버깅
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
            print(f"트랜잭션 input 데이터 에러: {tx_data.get('input', {})}")
            continue  # 잘못된 데이터는 건너뜀

        # output 파싱 (리스트 형태 처리)
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

load_utxo()
print(global_utxo_set,"\n\n")
load_transactions()
test = global_transaction_set
print(test)
print(test['input'])
print(test['input']['utxo'])

a= "sig_alice alice"
b = "DUP HASH alice_hash EQUALVERIFY CHECKSIG"
print(a.split()+b.split())

a = {'outputs': [{'amount': 30, 'locking_script': 'DUP HASH bob_hash EQUALVERIFY CHECKSIG'}, {'amount': 20, 'locking_script': 'DUP HASH charlie_hash EQUALVERIFY CHECKSIG'}]}

print(sum([i['amount'] for i in a['outputs']]))