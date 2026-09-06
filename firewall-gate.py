import ipaddress
import json
import os
import time
import urllib.request

TAG_PREFIX = "ci-runner-temp"
API_ROOT = "https://api.hetzner.cloud/v1/firewalls"
PUBLIC_IP_SERVICE = "https://api.ipify.org"
WRITE_ATTEMPTS = 5
SETTLE_DELAY_SECONDS = 2
RETRY_DELAY_SECONDS = 3

TOKEN = os.environ["HETZNER_TOKEN"]
FIREWALL_ID = os.environ["FIREWALL_ID"]
GATE_PORT = os.environ["GATE_PORT"]
REPOSITORY = os.environ.get("GITHUB_REPOSITORY", "local")
RUN_ID = os.environ.get("GITHUB_RUN_ID", "local")
RUN_ATTEMPT = os.environ.get("GITHUB_RUN_ATTEMPT", "1")

REPOSITORY_TAG = f"{TAG_PREFIX}:{REPOSITORY}"
OWN_TAG = f"{REPOSITORY_TAG}:{RUN_ID}:{RUN_ATTEMPT}"


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
        return ipaddress.ip_address(response.read().decode().strip())


def temp_rule(runner_ip):
    return {
        "direction": "in",
        "protocol": "tcp",
        "port": GATE_PORT,
        "source_ips": [str(ipaddress.ip_network(runner_ip))],
        "description": OWN_TAG,
    }


def is_own_rule(rule):
    return rule.get("description") == OWN_TAG


def is_stale_rule(rule):
    description = rule.get("description") or ""
    return description.startswith(f"{REPOSITORY_TAG}:") and description != OWN_TAG


def rules_without_own(rules):
    return [rule for rule in rules if not is_own_rule(rule)]


def rules_without_this_repository(rules):
    return [rule for rule in rules if not is_own_rule(rule) and not is_stale_rule(rule)]


def settle(build_wanted_rules, is_settled):
    for attempt in range(1, WRITE_ATTEMPTS + 1):
        write_rules(build_wanted_rules(read_rules()))
        time.sleep(SETTLE_DELAY_SECONDS)
        if is_settled(read_rules()):
            return attempt
        time.sleep(RETRY_DELAY_SECONDS)
    raise SystemExit(f"firewall {FIREWALL_ID} did not settle after {WRITE_ATTEMPTS} attempts")


def own_rule_present(rules):
    return any(is_own_rule(rule) for rule in rules)


def open_gate():
    runner_ip = read_runner_ip()
    gate_rule = temp_rule(runner_ip)

    def wanted_rules(rules):
        return rules_without_this_repository(rules) + [gate_rule]

    attempts = settle(wanted_rules, own_rule_present)
    print(f"opened tcp/{GATE_PORT} on firewall {FIREWALL_ID} for {runner_ip} after {attempts} attempt(s)")


def close_gate():
    attempts = settle(rules_without_own, lambda rules: not own_rule_present(rules))
    print(f"closed firewall {FIREWALL_ID} after {attempts} attempt(s)")


MODES = {"open": open_gate, "close": close_gate}
mode = os.environ["GATE_MODE"]
if mode not in MODES:
    raise SystemExit(f"mode must be one of {sorted(MODES)}, got {mode!r}")
MODES[mode]()
