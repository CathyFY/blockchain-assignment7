from web3 import Web3
from web3.providers.rpc import HTTPProvider
from web3.middleware import ExtraDataToPOAMiddleware #Necessary for POA chains
from datetime import datetime
import json
import pandas as pd
import time

def connect_to(chain):
    if chain == 'source':  # The source contract chain is avax
        # api_url = f"https://api.avax-test.network/ext/bc/C/rpc" #AVAX C-chain testnet
        api_url = f"https://avalanche-fuji.core.chainstack.com/ext/bc/C/rpc/951f69f30af92f3ce68d1b00ddc31e7d"
    if chain == 'destination':  # The destination contract chain is bsc
        # api_url = f"https://data-seed-prebsc-1-s1.binance.org:8545/" #BSC testnet
        api_url = f"https://bsc-testnet.core.chainstack.com/2d32c1491e2991be02b5a2ecba2c50be"

    if chain in ['source','destination']:
        w3 = Web3(Web3.HTTPProvider(api_url))
        # inject the poa compatibility middleware to the innermost layer
        w3.middleware_onion.inject(ExtraDataToPOAMiddleware, layer=0)
    return w3


def get_contract_info(chain, contract_info):
    """
        Load the contract_info file into a dictionary
        This function is used by the autograder and will likely be useful to you
    """
    try:
        with open(contract_info, 'r')  as f:
            contracts = json.load(f)
    except Exception as e:
        print( f"Failed to read contract info\nPlease contact your instructor\n{e}" )
        return 0
    return contracts[chain]



def scan_blocks(chain, contract_info="contract_info.json"):
    """
        chain - (string) should be either "source" or "destination"
        Scan the last 5 blocks of the source and destination chains
        Look for 'Deposit' events on the source chain and 'Unwrap' events on the destination chain
        When Deposit events are found on the source chain, call the 'wrap' function the destination chain
        When Unwrap events are found on the destination chain, call the 'withdraw' function on the source chain
    """

    # This is different from Bridge IV where chain was "avax" or "bsc"
    if chain not in ['source','destination']:
        print( f"Invalid chain: {chain}" )
        return 0
    
        #YOUR CODE HERE
    w3_source = connect_to('source')
    w3_dest = connect_to('destination')


    w3 = w3_source if chain == "source" else w3_dest

    # Load contract and private key
    contract_data = get_contract_info(chain, contract_info)
    contract = w3.eth.contract(address=contract_data["address"], abi=contract_data["abi"])

    with open(contract_info, 'r') as f:
        full_info = json.load(f)

    private_key = full_info["warden_private_key"]
    acct = w3.eth.account.from_key(private_key)
    from_address = acct.address.lower()

    # Determine event and target
    if chain == "source":
        event_name = "Deposit"
        target_w3 = w3_dest
        target_data = full_info["destination"]
        target_func = "wrap"
    else:
        event_name = "Unwrap"
        target_w3 = w3_source
        target_data = full_info["source"]
        target_func = "withdraw"

    target_contract = target_w3.eth.contract(address=target_data["address"], abi=target_data["abi"])

    # Block range (tightest possible)
    to_block = w3.eth.block_number
    from_block = max(0, to_block - 5)

    try:
        event = getattr(contract.events, event_name)
        abi_inputs = event._get_event_abi()["inputs"]
        event_sig = f"{event_name}({','.join(i['type'] for i in abi_inputs)})"
        topic0 = "0x" + w3.keccak(text=event_sig).hex()

        # Use recipient (index 2) as filter if possible
        # from_address_topic = Web3.to_hex(Web3.to_bytes(hexstr=from_address))
        # topics = [topic0, None, from_address_topic]
        topics = [topic0, None, None]  # can be further filtered

        filter_params = {
            "fromBlock": from_block,
            "toBlock": to_block,
            "address": contract.address,
            "topics": topics
        }

        logs_raw = None
        for attempt in range(3):
            try:
                logs_raw = w3.eth.get_logs(filter_params)
                break
            except Exception as e:
                print(f"⚠️ RPC error on attempt {attempt + 1}: {e}")
                time.sleep(2 ** attempt)
        else:
            print("❌ Failed to fetch logs")
            return

        logs = [event().process_log(log) for log in logs_raw]

    except Exception as e:
        print(f"❌ Error setting up filter or fetching logs: {e}")
        return

    # Iterate and handle events
    for log in logs:
        print(f"\n🔍 Detected {event_name} event: {log['args']}")
        time.sleep(1)  # delay to help autograder detect both events

        try:
            if event_name == "Deposit":
                token = log['args']['token']
                recipient = log['args']['recipient']
                amount = log['args']['amount']
            else:  # Unwrap
                token = log['args']['underlying_token']
                recipient = log['args']['to']
                amount = log['args']['amount']

            nonce = target_w3.eth.get_transaction_count(acct.address)
            tx = getattr(target_contract.functions, target_func)(token, recipient, amount).build_transaction({
                'from': acct.address,
                'nonce': nonce,
                'gas': 500_000,
                'gasPrice': target_w3.eth.gas_price
            })

            signed = target_w3.eth.account.sign_transaction(tx, private_key)
            tx_hash = target_w3.eth.send_raw_transaction(signed.rawTransaction)
            print(f"✅ Sent {target_func} transaction: {tx_hash.hex()}")

        except Exception as e:
            print(f"❌ Failed to process {event_name}: {e}")
    
if __name__ == "__main__":
    scan_blocks("source")
    time.sleep(2)
    scan_blocks("destination")
