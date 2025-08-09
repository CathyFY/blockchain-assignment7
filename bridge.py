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
    print(f"Starting bridge scan for {chain}...")

    w3_source = connect_to('source')
    w3_dest   = connect_to('destination')
    w3 = w3_source if chain == "source" else w3_dest

    # Load contract + key
    contract_data = get_contract_info(chain, contract_info)
    contract = w3.eth.contract(address=Web3.to_checksum_address(contract_data["address"]),
                               abi=contract_data["abi"])

    with open(contract_info, 'r') as f:
        full_info = json.load(f)

    private_key = full_info["warden_private_key"]
    acct = w3.eth.account.from_key(private_key)

    # Direction mapping
    if chain == "source":
        event_name   = "Deposit"          # Source emits Deposit
        target_w3    = w3_dest            # mirror to Destination.wrap
        target_data  = full_info["destination"]
        target_func  = "wrap"
        use_legacy   = True               # BSC testnet likes legacy gas
        gas_limit    = 300_000
    else:
        event_name   = "Unwrap"           # Destination emits Unwrap
        target_w3    = w3_source          # mirror to Source.withdraw
        target_data  = full_info["source"]
        target_func  = "withdraw"
        use_legacy   = False              # Fuji: EIP-1559 ok
        gas_limit    = 300_000

    target_contract = target_w3.eth.contract(
        address=Web3.to_checksum_address(target_data["address"]),
        abi=target_data["abi"]
    )

        # Block window
    to_block   = w3.eth.block_number
    lookback   = int(os.environ.get("LOOKBACK_BLOCKS", "1000"))  # keep small; RPCs cap ranges
    from_block = max(0, to_block - lookback)

    try:
        # Build topic0 from ABI (guaranteed 0x-prefixed & 32 bytes)
        event = getattr(contract.events, event_name)
        eabi  = event._get_event_abi()
        topic0 = to_hex(event_abi_to_log_topic(eabi))

        # ---- adaptive chunked getLogs to avoid provider range limits ----
        max_chunk = int(os.environ.get("LOG_CHUNK", "900"))  # Chainstack safe ~<=1000
        min_chunk = 100
        all_logs = []
        start = from_block
        while start <= to_block:
            end = min(start + max_chunk, to_block)
            fp = {
                "fromBlock": start,
                "toBlock":   end,
                "address":   Web3.to_checksum_address(contract.address),
                "topics":    [topic0, None, None, None],
            }

            ok = False
            last_err = ""
            for attempt in range(3):
                try:
                    got = w3.eth.get_logs(fp)
                    all_logs.extend(got)
                    ok = True
                    break
                except Exception as e:
                    last_err = str(e)
                    print(f"⚠️ get_logs {start}-{end} attempt {attempt+1}: {e}")
                    time.sleep(2 ** attempt)

            if not ok:
                # If range-limited, halve the chunk and retry this window
                if "range limit" in last_err.lower():
                    if max_chunk <= min_chunk:
                        print(f"❌ Provider limit even at {max_chunk}; skipping {start}-{end}")
                        start = end + 1
                    else:
                        max_chunk = max(min_chunk, max_chunk // 2)
                        print(f"↘️  Reducing chunk to {max_chunk} and retrying {start}-{min(start+max_chunk, to_block)}")
                    continue
                # Otherwise skip this window
                start = end + 1
                continue

            start = end + 1

        logs = [event().process_log(l) for l in all_logs]
        print(f"🔎 {chain}: found {len(logs)} {event_name} event(s) in [{from_block},{to_block}] via {len(all_logs)} raw logs")

    except Exception as e:
        print(f"❌ Error setting up filter or fetching logs: {e}")
        return

    # Prepare a pending nonce on the *target* chain and increment locally
    next_nonce = target_w3.eth.get_transaction_count(acct.address, "pending")

    for log in logs:
        print(f"\n📜 {event_name}: args keys={list(log['args'].keys())} values={dict(log['args'])}")
        time.sleep(0.3)

        try:
            if event_name == "Deposit":
                # Source.Deposit(token, recipient, amount)
                token     = Web3.to_checksum_address(log['args'].get('token') or log['args'].get('_token'))
                recipient = Web3.to_checksum_address(log['args'].get('recipient') or log['args'].get('_recipient'))
                amount    = int(log['args'].get('amount') or log['args'].get('_amount'))
                fn = target_contract.functions.wrap(token, recipient, amount)
            else:
                # Destination.Unwrap(underlying, wrapped, from, to, amount)
                token     = Web3.to_checksum_address(
                    log['args'].get('underlying') or log['args'].get('underlying_token') or log['args'].get('token')
                )
                recipient = Web3.to_checksum_address(log['args'].get('to') or log['args'].get('_recipient'))
                amount    = int(log['args'].get('amount') or log['args'].get('_amount'))
                fn = target_contract.functions.withdraw(token, recipient, amount)

            # Gas / fee params
            tx_params = {
                "from":  acct.address,
                "nonce": next_nonce,
                "gas":   gas_limit,
            }
            if use_legacy:
                tx_params["gasPrice"] = max(target_w3.eth.gas_price, target_w3.to_wei(3, "gwei"))
            else:
                latest = target_w3.eth.get_block("latest")
                base   = latest.get("baseFeePerGas")
                if base is None:
                    tx_params["gasPrice"] = target_w3.eth.gas_price
                else:
                    tx_params["maxPriorityFeePerGas"] = target_w3.to_wei(2, "gwei")
                    tx_params["maxFeePerGas"]        = int(base * 2)

            tx = fn.build_transaction(tx_params)
            signed = target_w3.eth.account.sign_transaction(tx, private_key)
            txh = target_w3.eth.send_raw_transaction(signed.rawTransaction)
            rcpt = target_w3.eth.wait_for_transaction_receipt(txh)
            print(f"✅ {target_func} → {txh.hex()} status={rcpt.status} gasUsed={rcpt.gasUsed}")
            next_nonce += 1

        except Exception as e:
            print(f"❌ Failed to process {event_name}: {e}")

            
if __name__ == "__main__":
    scan_blocks("source")
    time.sleep(2)
    scan_blocks("destination")
    