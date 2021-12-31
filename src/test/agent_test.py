import random
import eth_abi
from eth_utils import encode_hex, function_abi_to_4byte_selector
from forta_agent import create_transaction_event
from src.agent import provide_handle_transaction, approve, increase_allowance, hard_reset_db
from src.blacklist import blacklist
from src.test.web3_mock import Web3Mock

VICTIM = "0x0000000000000000000000000000000000000000"
SPENDER_1 = "0x1111111111111111111111111111111111111111"
SPENDER_2 = "0x2222222222222222222222222222222222222222"
SPENDERS = [SPENDER_1, SPENDER_2]

CONTRACT_1 = "0x3333333333333333333333333333333333333333"
CONTRACT_2 = "0x4444444444444444444444444444444444444444"

w3 = Web3Mock()


class TestEvidenceOfPhishingAgent:
    def test_returns_finding_if_evidence_of_phishing_exist_approve(self):
        hard_reset_db()
        findings = []
        for i in range(20):
            approve_func = function_abi_to_4byte_selector(approve)
            params = eth_abi.encode_abi(["address", "uint256"],
                                        [SPENDER_1, 100])
            data = encode_hex(approve_func + params)

            tx_event = create_transaction_event({
                'transaction': {
                    'from': VICTIM,
                    'to': CONTRACT_1,
                    'data': data,
                    'hash': "0",
                },
                'block': {
                    'number': i
                },
                'receipt': {
                    'logs': [],
                    'status': 1,
                },

            })
            tmp_findings = provide_handle_transaction(w3)(tx_event)
            if tmp_findings:
                findings.append(*tmp_findings)
        assert findings

    def test_returns_finding_if_evidence_of_phishing_exist_increase_allowance(self):
        hard_reset_db()
        findings = []
        for i in range(20):
            increase_allowance_func = function_abi_to_4byte_selector(increase_allowance)
            params = eth_abi.encode_abi(["address", "uint256"],
                                        [SPENDER_1, 100])
            data = encode_hex(increase_allowance_func + params)

            tx_event = create_transaction_event({
                'transaction': {
                    'from': VICTIM,
                    'to': CONTRACT_1,
                    'data': data,
                    'hash': "0",
                },
                'block': {
                    'number': i
                },
                'receipt': {
                    'logs': [],
                    'status': 1,
                },

            })
            tmp_findings = provide_handle_transaction(w3)(tx_event)
            if tmp_findings:
                findings.append(*tmp_findings)
        assert findings

    def test_returns_zero_findings_if_senders_are_different(self):
        hard_reset_db()
        findings = []
        for i in range(18):
            approve_func = function_abi_to_4byte_selector(approve)
            params = eth_abi.encode_abi(["address", "uint256"],
                                        [SPENDERS[i % 2], 100])
            data = encode_hex(approve_func + params)

            tx_event = create_transaction_event({
                'transaction': {
                    'from': VICTIM,
                    'to': CONTRACT_1,
                    'data': data,
                    'hash': "0",
                },
                'block': {
                    'number': i
                },
                'receipt': {
                    'logs': [],
                    'status': 1,
                },

            })
            tmp_findings = provide_handle_transaction(w3)(tx_event)
            if tmp_findings:
                findings.append(*tmp_findings)
        assert not findings

    def test_returns_zero_findings_if_transfers_out_period(self):
        hard_reset_db()
        findings = []
        for i in range(18):
            approve_func = function_abi_to_4byte_selector(approve)
            params = eth_abi.encode_abi(["address", "uint256"],
                                        [SPENDER_1, 100])
            data = encode_hex(approve_func + params)

            tx_event = create_transaction_event({
                'transaction': {
                    'from': VICTIM,
                    'to': CONTRACT_1,
                    'data': data,
                    'hash': "0",
                },
                'block': {
                    'number': i * 2000
                },
                'receipt': {
                    'logs': [],
                    'status': 1,
                },

            })
            tmp_findings = provide_handle_transaction(w3)(tx_event)
            if tmp_findings:
                findings.append(*tmp_findings)
        assert not findings

    def test_returns_zero_findings_if_spenders_are_centralized_exchanges(self):
        hard_reset_db()
        findings = []
        for i in range(18):
            approve_func = function_abi_to_4byte_selector(approve)
            params = eth_abi.encode_abi(["address", "uint256"],
                                        [random.choice(blacklist), 100])
            data = encode_hex(approve_func + params)

            tx_event = create_transaction_event({
                'transaction': {
                    'from': VICTIM,
                    'to': CONTRACT_1,
                    'data': data,
                    'hash': "0",
                },
                'block': {
                    'number': i
                },
                'receipt': {
                    'logs': [],
                    'status': 1,
                },

            })
            tmp_findings = provide_handle_transaction(w3)(tx_event)
            if tmp_findings:
                findings.append(*tmp_findings)
        assert not findings

    def test_returns_findings_if_approve_is_mixed_with_increase_allowance(self):
        hard_reset_db()
        findings = []
        for i in range(20):
            approve_or_ia_func = function_abi_to_4byte_selector(random.choice([approve, increase_allowance]))
            params = eth_abi.encode_abi(["address", "uint256"],
                                        [SPENDER_1, 100])
            data = encode_hex(approve_or_ia_func + params)

            tx_event = create_transaction_event({
                'transaction': {
                    'from': VICTIM,
                    'to': CONTRACT_1,
                    'data': data,
                    'hash': "0",
                },
                'block': {
                    'number': i
                },
                'receipt': {
                    'logs': [],
                    'status': 1,
                },

            })
            tmp_findings = provide_handle_transaction(w3)(tx_event)
            if tmp_findings:
                findings.append(*tmp_findings)
        assert findings
