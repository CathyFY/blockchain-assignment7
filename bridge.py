from web3 import Web3
from web3.providers.rpc import HTTPProvider
from web3.middleware import ExtraDataToPOAMiddleware #Necessary for POA chains
from datetime import datetime
import json
import pandas as pd
import time
from eth_utils import event_abi_to_log_topic, to_hex
import os

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
    w3 = connect_to(chain)
    contract_data = get_contract_info(chain, contract_info)
    contract = w3.eth.contract(address=contract_data['address'], abi=contract_data['abi'])

    latest_block = w3.eth.get_block_number()
    start_block = latest_block - 10
    end_block = latest_block

    print(f"Scanning blocks {start_block} to {end_block} on {chain} chain")

    if chain == 'source':
        time.sleep(60)
        dest_w3 = connect_to('destination')
        dest_data = get_contract_info('destination', contract_info)
        dest_contract = dest_w3.eth.contract(address=dest_data['address'], abi=dest_data['abi'])

        try:
            deposit_events = sorted(
                contract.events.Deposit().get_logs(from_block=start_block, to_block=end_block),
                key=lambda e: (e.blockNumber, e.logIndex)
            )
            print(f"Found {len(deposit_events)} Deposit events")

            for i, event in enumerate(deposit_events):
                token = event.args['token']
                recipient = event.args['recipient']
                amount = event.args['amount']
                print(f"Processing Deposit {i+1}: token={token}, recipient={recipient}, amount={amount}")

                warden_key = dest_data.get('warden_key')
                warden = dest_w3.eth.account.from_key(warden_key)
                nonce = dest_w3.eth.get_transaction_count(warden.address)

                try:
                    gas_estimate = dest_contract.functions.wrap(token, recipient, amount).estimate_gas({'from': warden.address})
                    gas_limit = int(gas_estimate * 1.2)
                except:
                    gas_limit = 200000

                tx = dest_contract.functions.wrap(token, recipient, amount).build_transaction({
                    'from': warden.address,
                    'nonce': nonce,
                    'gas': gas_limit,
                    'gasPrice': dest_w3.eth.gas_price
                })

                signed = dest_w3.eth.account.sign_transaction(tx, warden_key)
                tx_hash = dest_w3.eth.send_raw_transaction(signed.raw_transaction)
                print(f"Wrap transaction sent: {tx_hash.hex()}")

                receipt = dest_w3.eth.wait_for_transaction_receipt(tx_hash, timeout=120)
                print(f"Wrap transaction confirmed in block {receipt.blockNumber}")

                if i < len(deposit_events) - 1:
                    time.sleep(1)

        except Exception as e:
            print(f"Error processing deposit events: {e}")

    elif chain == 'destination':
        src_w3 = connect_to('source')
        src_data = get_contract_info('source', contract_info)
        src_contract = src_w3.eth.contract(address=src_data['address'], abi=src_data['abi'])

        time.sleep(30)

        unwrap_events = []
        max_retries = 5

        print(f"Scanning for Unwrap events from {start_block} to {end_block}, one block at a time")

        for b in range(start_block, end_block + 1):
            for attempt in range(max_retries):
                try:
                    logs = sorted(
                        contract.events.Unwrap().get_logs(from_block=b, to_block=b),
                        key=lambda e: (e.blockNumber, e['logIndex'])
                    )
                    unwrap_events.extend(logs)
                    print(f"Got logs from block {b}")
                    break
                except Exception as e:
                    print(f"Retry {attempt + 1}/{max_retries} failed for block {b}: {e}")
                    time.sleep(min(2 ** attempt + uniform(0.1, 0.5), 10))
            else:
                print(f"All retries failed for block {b}")

        print(f"Found {len(unwrap_events)} Unwrap events")

        for i, event in enumerate(unwrap_events):
            token = event.args['underlying_token']
            to = event.args['to']
            amount = event.args['amount']

            print(f"Processing Unwrap {i+1}: token={token}, to={to}, amount={amount}")
            warden_key = src_data.get('warden_key')
            warden = src_w3.eth.account.from_key(warden_key)
            nonce = src_w3.eth.get_transaction_count(warden.address)

            try:
                gas_estimate = src_contract.functions.withdraw(token, to, amount).estimate_gas({'from': warden.address})
                gas_limit = int(gas_estimate * 1.2)
            except:
                gas_limit = 200000

            tx = src_contract.functions.withdraw(token, to, amount).build_transaction({
                'from': warden.address,
                'nonce': nonce,
                'gas': gas_limit,
                'gasPrice': src_w3.eth.gas_price
            })

            signed = src_w3.eth.account.sign_transaction(tx, warden_key)
            tx_hash = src_w3.eth.send_raw_transaction(signed.raw_transaction)
            print(f"Withdraw transaction sent: {tx_hash.hex()}")

            receipt = src_w3.eth.wait_for_transaction_receipt(tx_hash, timeout=120)
            print(f"Withdraw confirmed in block {receipt.blockNumber}")

            if i < len(unwrap_events) - 1:
                time.sleep(2)

    return 1

if __name__ == "__main__":
    scan_blocks("source")  
    time.sleep(10)
    scan_blocks("destination") 
    