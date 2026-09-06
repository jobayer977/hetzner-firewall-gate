import json
import os
import time
import urllib.request

TEMP_RULE_DESCRIPTION = "ci-runner-temp"
API_ROOT = "https://api.hetzner.cloud/v1/firewalls"
PUBLIC_IP_SERVICE = "https://api.ipify.org"
WRITE_ATTEMPTS = 5
RETRY_DELAY_SECONDS = 3

TOKEN = os.environ["HETZNER_TOKEN"]
FIREWALL_ID = os.environ["FIREWALL_ID"]
GATE_PORT = os.environ["GATE_PORT"]


def read_json(url, method="GET", body=None):
    payload = json.dumps(body).encode() if body is not None else None
    request = urllib.request.Request(url, method=method, data=payload)
    request.add_header("Authorization", f"Bearer {TOKEN}")
    request.add_header("Content-Type", "application/json")
    with urllib.request.urlopen(request, timeout=30) as response:
        return json.load(response)


def read_rules():
    return read_json(f"{API_ROOT}/{FIREWALL_ID}")["firewall"]["rules"]


def write_rules(rules):
    read_json(f"{API_ROOT}/{FIREWALL_ID}/actions/set_rules", "POST", {"rules": rules})


def read_runner_ip():
    with urllib.request.urlopen(PUBLIC_IP_SERVICE, timeout=30) as response:
        return response.read().decode().strip()


def temp_rule(runner_ip):
    return {
        "direction": "in",
        "protocol": "tcp",
        "port": GATE_PORT,
        "source_ips": [f"{runner_ip}/32"],
        "description": TEMP_RULE_DESCRIPTION,
    }


def is_temp_rule(rule):
    return rule.get("description") == TEMP_RULE_DESCRIPTION


def permanent_rules(rules):
    return [rule for rule in rules if not is_temp_rule(rule)]


def allows_runner(rules, runner_ip):
    return any(is_temp_rule(rule) and f"{runner_ip}/32" in rule["source_ips"] for rule in rules)


def settle(wanted_rules, is_settled):
    for attempt in range(1, WRITE_ATTEMPTS + 1):
        write_rules(wanted_rules)
        if is_settled(read_rules()):
            return attempt
        time.sleep(RETRY_DELAY_SECONDS)
    raise SystemExit(f"firewall {FIREWALL_ID} did not settle after {WRITE_ATTEMPTS} attempts")


def open_gate():
    runner_ip = read_runner_ip()
    wanted_rules = permanent_rules(read_rules()) + [temp_rule(runner_ip)]
    attempts = settle(wanted_rules, lambda rules: allows_runner(rules, runner_ip))
    print(f"opened tcp/{GATE_PORT} on firewall {FIREWALL_ID} for {runner_ip} after {attempts} attempt(s)")


def close_gate():
    wanted_rules = permanent_rules(read_rules())
    attempts = settle(wanted_rules, lambda rules: not any(is_temp_rule(rule) for rule in rules))
    print(f"closed firewall {FIREWALL_ID} after {attempts} attempt(s)")


MODES = {"open": open_gate, "close": close_gate}
mode = os.environ["GATE_MODE"]
if mode not in MODES:
    raise SystemExit(f"mode must be one of {sorted(MODES)}, got {mode!r}")
MODES[mode]()
