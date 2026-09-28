import sys, json
from client import FintechTransactionVelocityFraudSentinel

def main():
    sentinel = FintechTransactionVelocityFraudSentinel()
    if len(sys.argv) > 1 and sys.argv[1] == "--test":
        print(json.dumps(sentinel.run_benchmark_fraud_sentinel(), indent=2))
        return

    for line in sys.stdin:
        if not line.strip(): continue
        try:
            req = json.loads(line)
            method = req.get("method")
            params = req.get("params", {})
            rid = req.get("id")

            if method == "tools/list":
                res = {
                    "tools": [
                        {"name": "evaluate_transaction_risk", "description": "Evaluate sliding-window velocity and fraud risk score."},
                        {"name": "run_benchmark_fraud_sentinel", "description": "Run anti-fraud sentinel benchmark."}
                    ]
                }
            elif method == "tools/call":
                tname = params.get("name")
                args = params.get("arguments", {})
                if tname == "evaluate_transaction_risk":
                    out = sentinel.evaluate_transaction_risk(args.get("user_id", ""), args.get("amount", 0.0), args.get("card_bin", ""), args.get("ip_country", "US"), args.get("current_timestamp"))
                elif tname == "run_benchmark_fraud_sentinel":
                    out = sentinel.run_benchmark_fraud_sentinel()
                else:
                    out = {"error": f"Unknown tool {tname}"}
                res = {"content": [{"type": "text", "text": json.dumps(out)}]}
            else:
                res = {"error": "Unsupported method"}
            print(json.dumps({"jsonrpc": "2.0", "id": rid, "result": res}), flush=True)
        except Exception as e:
            print(json.dumps({"jsonrpc": "2.0", "error": {"code": -32603, "message": str(e)}}), flush=True)

if __name__ == "__main__":
    main()
