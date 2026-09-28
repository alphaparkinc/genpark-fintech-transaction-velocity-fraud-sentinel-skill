import sys, json
from client import FintechTransactionVelocityFraudSentinel

def main():
    print("Testing FintechTransactionVelocityFraudSentinel...")
    sentinel = FintechTransactionVelocityFraudSentinel()
    res = sentinel.run_benchmark_fraud_sentinel()
    print(json.dumps(res, indent=2))
    assert res["benchmark_status"] == "PASSED"
    assert res["normal_tx_verdict"] == "ALLOW_IMMEDIATELY"
    assert res["attack_verdict"] == "AUTO_DECLINE_AND_FREEZE"
    assert res["attack_risk_score"] >= 80
    print("All Fintech Transaction Velocity Fraud Sentinel tests passed successfully!")

if __name__ == "__main__":
    main()
