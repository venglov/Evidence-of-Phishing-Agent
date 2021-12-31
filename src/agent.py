import asyncio
import json
import forta_agent
from forta_agent import get_json_rpc_url
from web3 import Web3
from src.db.config import config
from src.db.controller import init_async_db
from src.utils import is_EOA
from src.config import MONITOR_PERIOD_IN_BLOCKS, TRANSFERS_AMOUNT_TH
from src.findings import EvidenceOfPhishingFindings
from collections import Counter
from src.blacklist import blacklist

inited = False  # Initialization Pattern
web3 = Web3(Web3.HTTPProvider(get_json_rpc_url()))
with open("./src/ABI/abi.json", 'r') as abi_file:  # get abi from the file
    abi = json.load(abi_file)

# approve(address spender, uint256 amount) → bool
approve = next((x for x in abi if x.get('name', "") == "approve"), None)
# increaseAllowance(address spender, uint256 addedValue) → bool
increase_allowance = next((x for x in abi if x.get('name', "") == "increaseAllowance"), None)


async def analyze_db():
    """
    This function analyses the db and looks for the senders, that have a big amount of transfers to theirs adresses
    :return: findings: list
    """
    findings = []
    transfers_table = config.get_transfers()  # get transfers table from the db
    transfers = await transfers_table.get_all_rows()

    spenders = [transfer.spender for transfer in transfers]  # get all known spenders
    spenders_counter = Counter(spenders)  # represent they as {spender_address: amount of transfers}

    for key, value in spenders_counter.items():
        # create a finding if this amount of transfers is grater than TH
        if value > TRANSFERS_AMOUNT_TH:
            transfers_with_spender = list(filter(lambda x: x.spender == key, transfers))
            # get the list of the sender's victims
            victims = set([tws.victim for tws in transfers_with_spender])
            # get the dict of the affected contracts with total amounts of transfers to sender inside
            affected_contracts_with_amounts = {}
            for contract, amount in zip([tws.token_address for tws in transfers_with_spender],
                                        [tws.amount for tws in transfers_with_spender]):
                affected_contracts_with_amounts.update(
                    {contract: affected_contracts_with_amounts.get(contract, 0) + amount})
            findings.append(
                EvidenceOfPhishingFindings.main_finding(value, key, victims, affected_contracts_with_amounts))

    return findings


async def detect_evidence_of_phishing(transaction_event: forta_agent.transaction_event.TransactionEvent, w3):
    """
    This function detects the evidence of fishing and add them to the db
    :param transaction_event: forta_agent.transaction_event.TransactionEvent
    :return: findings: list
    """

    if not transaction_event.status:
        return []

    transfers = config.get_transfers()  # get transfers table from the db

    # get all transfers from the log
    for function in transaction_event.filter_function([json.dumps(approve), json.dumps(increase_allowance)]):
        args = function[1]
        spender = args.get('spender', [])  # get the spender
        # get the transfer amount
        amount = args.get('rawAmount', []) if args.get('rawAmount', []) else args.get('addedValue', [])

        token_address = transaction_event.to  # get the contract
        victim = transaction_event.from_  # get the potential victim

        # skip if victim isn't EOA || amount is null or 0 || spender isn't EOA || spender is centralized exchange
        if not is_EOA(spender, w3) or not amount or amount == 0 or not is_EOA(victim, w3) or spender in blacklist:
            continue

        # add the transfer to the db
        await transfers.paste_row(
            {'spender': spender, 'victim': victim, 'amount': amount, 'block': transaction_event.block_number,
             'token_address': token_address})
        await transfers.commit()

    return await analyze_db()


async def clear_db(transaction_event: forta_agent.transaction_event.TransactionEvent):
    """
    This function deletes old transfers and votes from the db
    :param transaction_event: forta_agent.transaction_event.TransactionEvent
    :return: []
    """
    transfers = config.get_transfers()
    await transfers.delete_old_transfers(transaction_event.block_number, MONITOR_PERIOD_IN_BLOCKS)
    await transfers.commit()
    return []


async def main(transaction_event: forta_agent.transaction_event.TransactionEvent, w3):
    """
    This function is used to start detect-functions in the different threads and then gather the findings
    """
    global inited
    if not inited:
        transfers = await init_async_db()
        config.set_tables(transfers)
        inited = True

    return await asyncio.gather(
        detect_evidence_of_phishing(transaction_event, w3),
        clear_db(transaction_event)
    )


def provide_handle_transaction(w3):
    def handle_transaction(transaction_event: forta_agent.transaction_event.TransactionEvent) -> list:
        return [finding for findings in asyncio.run(main(transaction_event, w3)) for finding in findings]

    return handle_transaction


real_handle_transaction = provide_handle_transaction(web3)


def handle_transaction(transaction_event: forta_agent.transaction_event.TransactionEvent):
    return real_handle_transaction(transaction_event)


# this function is needed for the test purposes
def hard_reset_db():
    global inited
    inited = False
