"""Read only the fixed staging container; never publish raw logs or settings."""
import collections
import datetime
import json
import re
import subprocess
from pathlib import Path

GROUP = "oa-verifier"
CONTAINER = "oa-verifier-2"
CATEGORIES = (
    "failed to create provisioning key", "OpenRouter session rejected",
    "create_provisioning_key", "management_key_create_failed",
    "register_management_key_create_failed", "management_key_list_failed",
    "failed cleanup", "registration successful", "registered station",
    "privacy toggles", "Unauthorized", "Forbidden", "permission",
    "expired", "invalid session", "TLS handshake error", "ACME",
    "certificate", "panic", "out of memory", "OOMKilled",
    "i/o timeout", "context deadline exceeded", "connection refused",
    "failed to notify org", "org event notification failed",
)


def summarize_logs(logs):
    lines = logs.splitlines()
    categories = {}
    statuses = collections.Counter()
    for line in lines:
        for category in CATEGORIES:
            if category.lower() in line.lower():
                entry = categories.setdefault(category, {"count": 0})
                entry["count"] += 1
                stamp = re.search(r"\b20\d{2}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z", line)
                if stamp:
                    entry["last_utc"] = stamp.group()
        for status in re.findall(r"(?:status(?:_code)?[= :\"]+|HTTP\s+)([45]\d{2})\b", line):
            statuses[status] += 1
    return {"line_count": len(lines), "categories": categories, "error_status_counts": dict(statuses)}


def az_read(args):
    result = subprocess.run(["az", "container", *args, "--resource-group", GROUP,
                             "--name", CONTAINER, "--only-show-errors"],
                            capture_output=True, text=True, timeout=90)
    if result.returncode:
        return None
    return result.stdout


def monitor_read(args):
    result = subprocess.run(["az", "monitor", *args, "--only-show-errors", "--output", "json"],
                            capture_output=True, text=True, timeout=90)
    if result.returncode:
        return None
    return json.loads(result.stdout)


def summarize_metrics(payload):
    output = []
    for metric in payload.get("value", []):
        name = metric.get("name", {}).get("value")
        if name not in {"CpuUsage", "MemoryUsage"}:
            continue
        for series in metric.get("timeseries", []):
            points = [{k: p[k] for k in ("timeStamp", "average", "maximum") if k in p}
                      for p in series.get("data", []) if "average" in p or "maximum" in p]
            output.append({"metric": name, "points": points})
    return output


def main():
    result = {"target": CONTAINER, "collected_at": datetime.datetime.now(datetime.timezone.utc).isoformat()}
    query = "{state:instanceView.state,events:instanceView.events[].{name:name,type:type,count:count,first:firstTimestamp,last:lastTimestamp},containers:containers[].{name:name,state:instanceView.currentState.state,start:instanceView.currentState.startTime,exit:instanceView.currentState.exitCode,previous:instanceView.previousState.state,restarts:instanceView.restartCount,cpu:resources.requests.cpu,memory_gb:resources.requests.memoryInGb,events:instanceView.events[].{name:name,type:type,count:count,first:firstTimestamp,last:lastTimestamp}}}"
    state = az_read(["show", "--query", query, "--output", "json"])
    result["state_read_ok"] = state is not None
    if state is not None:
        result["state"] = json.loads(state)
    logs = az_read(["logs", "--container-name", "oa-verifier"])
    result["logs_read_ok"] = logs is not None
    if logs is not None:
        result["logs"] = summarize_logs(logs)
    resource_id = az_read(["show", "--query", "id", "--output", "tsv"])
    if resource_id:
        resource_id = resource_id.strip()
        start = "2026-09-26T00:00:00Z"
        end = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        activity = monitor_read(["activity-log", "list", "--resource-id", resource_id,
                                 "--start-time", start, "--end-time", end, "--max-events", "200",
                                 "--query", "[].{time:eventTimestamp,operation:operationName.value,status:status.value,substatus:subStatus.value}"])
        result["activity_read_ok"] = activity is not None
        if activity is not None:
            result["activity"] = activity
        metrics = monitor_read(["metrics", "list", "--resource", resource_id,
                                "--metric", "CpuUsage", "MemoryUsage", "--interval", "PT1H",
                                "--aggregation", "Average", "Maximum", "--start-time", start, "--end-time", end])
        result["metrics_read_ok"] = metrics is not None
        if metrics is not None:
            result["metrics"] = summarize_metrics(metrics)
    Path("diagnostic-summary.json").write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps(result))
    if state is None or logs is None:
        raise SystemExit("One or more read-only diagnostic calls failed; see category flags.")


if __name__ == "__main__":
    main()
