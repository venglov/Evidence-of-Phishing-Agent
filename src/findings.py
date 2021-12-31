from forta_agent import Finding, FindingType, FindingSeverity
from src.config import MONITOR_PERIOD_IN_BLOCKS, TRANSFERS_AMOUNT_TH_HIGH, TRANSFERS_AMOUNT_TH_CRITICAL


class EvidenceOfPhishingFindings:

    @staticmethod
    def main_finding(amount, target_eoa, victims, affected_contracts_amounts) -> Finding:
        return Finding({
            'name': 'Evidence of Phishing Alert',
            'description': f'A high number the approve() or increaseAllowance() method calls for the same target EOA',
            'alert_id': 'FORTA-PHISHING-ALERT',
            'type': FindingType.Suspicious,
            'severity': EvidenceOfPhishingFindings._get_severity(amount),
            'metadata': {
                'target_EOA': target_eoa,
                'monitor_period': MONITOR_PERIOD_IN_BLOCKS,
                'victims': victims,
                'affected_contracts_with_amounts': affected_contracts_amounts
            }
        })

    @staticmethod
    def _get_severity(amount):
        if amount < TRANSFERS_AMOUNT_TH_HIGH:
            return FindingSeverity.Medium
        elif amount < TRANSFERS_AMOUNT_TH_CRITICAL:
            return FindingSeverity.High
        else:
            return FindingSeverity.Critical
