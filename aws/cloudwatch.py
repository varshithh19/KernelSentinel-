#!/usr/bin/env python3
# =============================================================
# KernelSentinel — AWS CloudWatch Integration
# Module 5: Cloud Monitoring & Alerts
#
# Sends:
#   - Risk scores as CloudWatch metrics (visible on AWS console)
#   - Attack alerts as CloudWatch log events
#   - Custom dashboard metrics
# =============================================================

import json
import time
import os
from datetime import datetime, timezone

try:
    import boto3
    from botocore.exceptions import ClientError, NoCredentialsError
    BOTO3_AVAILABLE = True
except ImportError:
    BOTO3_AVAILABLE = False

LOG_GROUP  = "/kernelsentinel/detections"
LOG_STREAM = "risk-scores"
NAMESPACE  = "KernelSentinel"

GREEN = "\033[92m"
YELLOW= "\033[93m"
RED   = "\033[91m"
RESET = "\033[0m"


class CloudWatchReporter:

    def __init__(self, region="ap-south-1"):
        self.enabled = False
        self.region  = region

        if not BOTO3_AVAILABLE:
            print("  ⚠️  boto3 not installed — CloudWatch disabled")
            print("       Install: pip3 install boto3")
            return

        try:
            self.cw_client  = boto3.client("cloudwatch",  region_name=region)
            self.logs_client = boto3.client("logs", region_name=region)
            self._ensure_log_group()
            self.enabled = True
            print(f"  ✅ CloudWatch connected (region: {region})")
        except NoCredentialsError:
            print("  ⚠️  AWS credentials not found.")
            print("       On EC2: IAM role handles this automatically.")
            print("       Locally: run 'aws configure'")
        except Exception as e:
            print(f"  ⚠️  CloudWatch setup failed: {e}")

    def _ensure_log_group(self):
        """Create CloudWatch log group if it doesn't exist."""
        try:
            self.logs_client.create_log_group(logGroupName=LOG_GROUP)
            self.logs_client.create_log_stream(
                logGroupName=LOG_GROUP, logStreamName=LOG_STREAM)
        except ClientError as e:
            if e.response["Error"]["Code"] not in \
               ("ResourceAlreadyExistsException",):
                raise

    def send_risk_score(self, risk_score: float, pid: int,
                        is_attack: bool, breakdown: dict):
        """
        Send risk score as a CloudWatch metric.
        Visible in AWS Console → CloudWatch → Metrics → KernelSentinel
        """
        if not self.enabled:
            print(f"  [CloudWatch OFFLINE] Would send: risk_score={risk_score}")
            return

        try:
            self.cw_client.put_metric_data(
                Namespace=NAMESPACE,
                MetricData=[
                    {
                        "MetricName": "RiskScore",
                        "Value":      risk_score,
                        "Unit":       "None",
                        "Dimensions": [
                            {"Name": "AgentPID", "Value": str(pid)},
                            {"Name": "Detection", "Value":
                             "Attack" if is_attack else "Normal"},
                        ],
                    },
                    {
                        "MetricName": "ExecutionScore",
                        "Value":      breakdown.get("execution", 0),
                        "Unit":       "None",
                    },
                    {
                        "MetricName": "NetworkScore",
                        "Value":      breakdown.get("network", 0),
                        "Unit":       "None",
                    },
                    {
                        "MetricName": "FileScore",
                        "Value":      breakdown.get("file", 0),
                        "Unit":       "None",
                    },
                ],
            )
            status = f"{RED}ATTACK{RESET}" if is_attack else f"{GREEN}NORMAL{RESET}"
            print(f"  ✅ CloudWatch metric sent: risk={risk_score} [{status}]")

        except Exception as e:
            print(f"  ⚠️  CloudWatch metric failed: {e}")

    def send_alert(self, pid: int, risk_score: float,
                   breakdown: dict, containment_result: dict):
        """
        Send attack alert as a CloudWatch log event.
        Visible in AWS Console → CloudWatch → Log groups → /kernelsentinel/detections
        """
        if not self.enabled:
            print(f"  [CloudWatch OFFLINE] Would send alert for PID {pid}")
            return

        alert_event = {
            "event_type":          "ATTACK_DETECTED",
            "pid":                 pid,
            "risk_score":          risk_score,
            "breakdown":           breakdown,
            "containment_latency": containment_result.get("latency_ms", "N/A"),
            "containment_actions": [a["action"]
                                    for a in containment_result.get("actions", [])],
            "timestamp":           datetime.now(timezone.utc).isoformat(),
        }

        try:
            self.logs_client.put_log_events(
                logGroupName=LOG_GROUP,
                logStreamName=LOG_STREAM,
                logEvents=[{
                    "timestamp": int(time.time() * 1000),
                    "message":   json.dumps(alert_event),
                }],
            )
            print(f"  ✅ Attack alert logged to CloudWatch")
            print(f"     View: AWS Console → CloudWatch → Log groups"
                  f" → {LOG_GROUP}")

        except Exception as e:
            print(f"  ⚠️  CloudWatch log failed: {e}")

    def send_normal_heartbeat(self, risk_score: float, pid: int):
        """Send a heartbeat metric for normal behaviour (monitoring continuity)."""
        self.send_risk_score(risk_score, pid, is_attack=False,
                             breakdown={"execution": 0, "network": 0,
                                        "file": 0, "sequence": 0})


def main():
    """Test CloudWatch connection."""
    print("\nTesting CloudWatch connection...")
    cw = CloudWatchReporter()
    if cw.enabled:
        cw.send_risk_score(
            risk_score=0.21, pid=os.getpid(), is_attack=False,
            breakdown={"execution": 0.05, "network": 0.08,
                       "file": 0.12, "sequence": 0.03}
        )
        print("✅ CloudWatch test successful")
    else:
        print("ℹ️  CloudWatch offline — will log locally instead")


if __name__ == "__main__":
    main()
