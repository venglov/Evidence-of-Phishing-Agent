# **Influencing Governance Proposals Agent**

---

## Description

Users approving token transfers to an externally owned address (EOA) may be a behavior indicative of a phishing attack.

This agent detects when a high number (e.g. 10 or more) of EOAs call the approve() or increaseAllowance() methods for the same target EOA over an extend period of time (e.g. 6 hours ~ 1600 blocks). The finding should include the affected addresses, the alleged attacker's address, and the addresses and amounts of tokens involved. It also doesn't include smart contracts (i.e. approve() called by a smart contract or a smart contract that is the designated spender for an approve() call) and EOAs for any centralized exchanges (e.g. FTX exchange: 0x2FAF487A4414Fe77e2327F0bf4AE2a264a776AD2).

The agent is separated into three threads:
1. First thread detects the evidence of fishing and add them to the db
2. Second thread analyses the db and looks for the senders, that have a big amount of transfers to theirs addresses
3. Third thread deletes old transfers from the db

## Agent Flow
![Phishing-Agent-Flow.png]()

## Setup

You can specify your own values in the `config.py`:

```python
MONITOR_PERIOD_IN_BLOCKS = 4800
TRANSFERS_AMOUNT_TH = 10
TRANSFERS_AMOUNT_TH_HIGH = 20
TRANSFERS_AMOUNT_TH_CRITICAL = 30
```

---

Due to the need to store information for a long time the agent uses asynchronous database.
This gives the advantage that even a restart or crash of the agent will not prevent him from discovering the vulnerability.
However, checking the same transactions multiple times in a row can cause a uniqueness error in the database. To get around this 
you need to remove the unique flag in `src/db/models.py` or add force drop_all in `src/db/controller.py`:
```python
await conn.run_sync(base.metadata.drop_all)
```
Note that you should disable this line for the production, and it is highly recommended resetting the db after tests

## Supported Chains

- Ethereum

## Alerts

- `FORTA-PHISHING-ALERT`
  - Fired when a high number the approve() or increaseAllowance() method calls for the same target EOA
  - Severity depends on the calls amount:
    - `Medium`: 10 <= amounts < 20
    - `High`: 20 <= amount < 30
    - `Critical`: 30 <= amount
  - Type is always set to `Suspicious`
  - Metadata:
    - `target_EOA` - EOA, that is target for the transfers
    - `monitor_period` - a period of block that contains the transfers
    - `victims` - potential victims - addresses that emits the transfers
    - `affected_contracts_with_amounts` - dictionary represented as `{contract_address: total funds transferred}`
  

## Tests

There are 6 test that should pass:

- `test_returns_finding_if_evidence_of_phishing_exist_approve()`
- `test_returns_finding_if_evidence_of_phishing_exist_increase_allowance()`
- `test_returns_zero_findings_if_senders_are_different()`
- `test_returns_zero_findings_if_transfers_out_period()`
- `test_returns_zero_findings_if_spenders_are_centralized_exchanges()`
- `test_returns_findings_if_approve_is_mixed_with_increase_allowance()`


## Test Data

Running the agent from 13650638 to 13652198 using
```bash
forta-agent run --range 13650638..13652198
```
will provide alerts for the Badger-Dao exploiters like `0x1fcdb04d0c5364fbd92c73ca8af9baa72c269107`

Read more here:
https://rekt.news/badger-rekt/
