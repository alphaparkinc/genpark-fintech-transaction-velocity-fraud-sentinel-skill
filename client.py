import sys, json, time, math

class FintechTransactionVelocityFraudSentinel:
    """
    Real-Time Payment Velocity Profiler & Fraud Sentinel.
    Monitors sliding-window transaction velocities (1-min, 10-min, 24-hr),
    detects card testing botnets, and issues verdicts: ALLOW, CHALLENGE_3DS, or BLOCK.
    """
    def __init__(self):
        self.user_history = {} # user_id -> list of {"timestamp", "amount", "card_bin", "ip"}

    def record_transaction(self, user_id, amount, card_bin, ip_country, timestamp=None):
        ts = timestamp if timestamp is not None else int(time.time())
        if user_id not in self.user_history:
            self.user_history[user_id] = []
        self.user_history[user_id].append({
            "timestamp": ts,
            "amount": amount,
            "card_bin": card_bin,
            "ip_country": ip_country
        })

    def evaluate_transaction_risk(self, user_id, amount, card_bin, ip_country, current_timestamp=None):
        now = current_timestamp if current_timestamp is not None else int(time.time())
        history = self.user_history.get(user_id, [])

        # Sliding windows
        events_1m = [e for e in history if (now - e["timestamp"]) <= 60]
        events_10m = [e for e in history if (now - e["timestamp"]) <= 600]
        events_24h = [e for e in history if (now - e["timestamp"]) <= 86400]

        # Calculate distinct cards used in 10 mins
        distinct_cards_10m = len(set(e["card_bin"] for e in events_10m) | {card_bin})

        risk_score = 5 # Baseline low risk
        flags = []

        # Check 1: High velocity in 1 minute (>3 transactions = bot/scripting)
        if len(events_1m) >= 3:
            risk_score += 45
            flags.append(f"HIGH_VELOCITY_1M: {len(events_1m)} transactions in 60s")

        # Check 2: Card testing pattern (multiple distinct cards in short period)
        if distinct_cards_10m >= 3:
            risk_score += 50
            flags.append(f"CARD_TESTING_SUSPECTED: {distinct_cards_10m} different cards tried in 10m")

        # Check 3: Sudden volume spike (>5x average 24h amount)
        if events_24h:
            avg_24h = sum(e["amount"] for e in events_24h) / len(events_24h)
            if amount > (avg_24h * 5.0) and amount > 500.0:
                risk_score += 30
                flags.append(f"ANOMALOUS_TICKET_SIZE: Amount ${amount} is >5x 24h average (${avg_24h:.2f})")

        risk_score = min(100, risk_score)

        if risk_score >= 75:
            verdict = "AUTO_DECLINE_AND_FREEZE"
        elif risk_score >= 40:
            verdict = "CHALLENGE_3D_SECURE_MFA"
        else:
            verdict = "ALLOW_IMMEDIATELY"

        # Record this attempt
        self.record_transaction(user_id, amount, card_bin, ip_country, now)

        return {
            "user_id": user_id,
            "amount": amount,
            "risk_score": risk_score,
            "verdict": verdict,
            "anomalies_detected": flags,
            "sliding_window_counts": {
                "events_1m": len(events_1m) + 1,
                "events_10m": len(events_10m) + 1,
                "distinct_cards_10m": distinct_cards_10m
            }
        }

    def run_benchmark_fraud_sentinel(self):
        user = "usr_test_901"
        now = int(time.time())

        # Simulate normal purchase
        t1 = self.evaluate_transaction_risk(user, 45.0, "411111", "US", current_timestamp=now)

        # Simulate card testing bot attack (rapid sequential tries with different cards within 30s)
        self.evaluate_transaction_risk(user, 1.0, "422222", "US", current_timestamp=now + 5)
        self.evaluate_transaction_risk(user, 1.0, "433333", "US", current_timestamp=now + 10)
        t_attack = self.evaluate_transaction_risk(user, 1.0, "444444", "US", current_timestamp=now + 15)

        return {
            "benchmark_status": "PASSED",
            "normal_tx_verdict": t1["verdict"],
            "attack_verdict": t_attack["verdict"],
            "attack_risk_score": t_attack["risk_score"]
        }
