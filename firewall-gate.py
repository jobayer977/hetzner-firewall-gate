import ipaddress
import json
import os
import random
import time
import urllib.request

TAG_PREFIX = "ci-runner-temp"
LOCK_PREFIX = f"{TAG_PREFIX}:lock"
EXPIRY_MARKER = "exp="
LOCK_PLACEHOLDER_IP = "192.0.2.1/32"

API_ROOT = os.environ.get("HETZNER_API_ROOT", "https://api.hetzner.cloud/v1/firewalls")
PUBLIC_IP_SERVICE = os.environ.get("RUNNER_IP_SERVICE", "https://api.ipify.org")
WRITE_ATTEMPTS = int(os.environ.get("GATE_WRITE_ATTEMPTS", "5"))
LOCK_ATTEMPTS = int(os.environ.get("GATE_LOCK_ATTEMPTS", "60"))
SETTLE_DELAY_SECONDS = float(os.environ.get("GATE_SETTLE_DELAY", "2"))
RETRY_DELAY_SECONDS = float(os.environ.get("GATE_RETRY_DELAY", "3"))
GATE_TTL_SECONDS = float(os.environ.get("GATE_TTL_SECONDS", "3600"))
LOCK_TTL_SECONDS = float(os.environ.get("GATE_LOCK_TTL_SECONDS", "900"))

TOKEN = os.environ["HETZNER_TOKEN"]
FIREWALL_ID = os.environ["FIREWALL_ID"]
GATE_PORT = os.environ["GATE_PORT"]
REPOSITORY = os.environ.get("GITHUB_REPOSITORY", "local")
RUN_ID = os.environ.get("GITHUB_RUN_ID", "local")
RUN_ATTEMPT = os.environ.get("GITHUB_RUN_ATTEMPT", "1")

REPOSITORY_TAG = f"{TAG_PREFIX}:{REPOSITORY}"
RUN_TAG = f"{REPOSITORY_TAG}:{RUN_ID}:{RUN_ATTEMPT}"
LOCK_TAG = f"{LOCK_PREFIX}:{REPOSITORY}:{RUN_ID}:{RUN_ATTEMPT}"


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


def stamped(tag, ttl_seconds):
    return f"{tag}:{EXPIRY_MARKER}{int(time.time() + ttl_seconds)}"


def description_of(rule):
    return rule.get("description") or ""


def expiry_of(rule):
    _, marker, raw = description_of(rule).rpartition(f":{EXPIRY_MARKER}")
    return int(raw) if marker and raw.isdigit() else None


def is_expired(rule):
    expiry = expiry_of(rule)
    return expiry is not None and expiry <= time.time()


def is_lock_rule(rule):
    return description_of(rule).startswith(f"{LOCK_PREFIX}:")


def is_own_lock(rule):
    return description_of(rule).startswith(f"{LOCK_TAG}:")


def is_own_gate(rule):
    return description_of(rule).startswith(f"{RUN_TAG}:")


def is_own_repository_rule(rule):
    return description_of(rule).startswith(f"{REPOSITORY_TAG}:")


def is_reclaimable(rule):
    if is_own_lock(rule) or is_own_gate(rule):
        return False
    if is_own_repository_rule(rule):
        return True
    return description_of(rule).startswith(f"{TAG_PREFIX}:") and is_expired(rule)


def temp_rule(runner_ip):
    return {
        "direction": "in",
        "protocol": "tcp",
        "port": GATE_PORT,
        "source_ips": [str(ipaddress.ip_network(runner_ip))],
        "description": stamped(RUN_TAG, GATE_TTL_SECONDS),
    }


def lock_rule():
    return {
        "direction": "in",
        "protocol": "tcp",
        "port": GATE_PORT,
        "source_ips": [LOCK_PLACEHOLDER_IP],
        "description": stamped(LOCK_TAG, LOCK_TTL_SECONDS),
    }


def kept_rules(rules):
    return [rule for rule in rules if not is_reclaimable(rule) and not is_own_gate(rule)]


def rules_without_locks(rules):
    return [rule for rule in rules if not is_lock_rule(rule)]


def live_foreign_lock(rules):
    for rule in rules:
        if is_lock_rule(rule) and not is_own_lock(rule) and not is_expired(rule):
            return rule
    return None


def holds_lock(rules):
    locks = [rule for rule in rules if is_lock_rule(rule) and not is_expired(rule)]
    return len(locks) == 1 and is_own_lock(locks[0])


def backoff():
    time.sleep(RETRY_DELAY_SECONDS * (0.5 + random.random()))


def settle(build_wanted_rules, is_settled):
    for attempt in range(1, WRITE_ATTEMPTS + 1):
        write_rules(build_wanted_rules(read_rules()))
        time.sleep(SETTLE_DELAY_SECONDS)
        if is_settled(read_rules()):
            return attempt
        time.sleep(RETRY_DELAY_SECONDS)
    raise SystemExit(f"firewall {FIREWALL_ID} did not settle after {WRITE_ATTEMPTS} attempts")


def claim_lock():
    for attempt in range(1, LOCK_ATTEMPTS + 1):
        rules = read_rules()
        if live_foreign_lock(rules) is None:
            write_rules(rules_without_locks(rules) + [lock_rule()])
            time.sleep(SETTLE_DELAY_SECONDS)
            if holds_lock(read_rules()):
                return attempt
        backoff()
    raise SystemExit(f"firewall {FIREWALL_ID} lock not acquired after {LOCK_ATTEMPTS} attempts")


def release_lock():
    settle(lambda rules: [rule for rule in rules if not is_own_lock(rule)],
           lambda rules: not any(is_own_lock(rule) for rule in rules))


def apply_under_lock(build_wanted_rules, is_settled):
    claim_lock()
    try:
        return settle(build_wanted_rules, is_settled)
    finally:
        release_lock()


def own_gate_present(rules):
    return any(is_own_gate(rule) for rule in rules)


def open_gate():
    runner_ip = read_runner_ip()
    gate_rule = temp_rule(runner_ip)
    attempts = apply_under_lock(lambda rules: kept_rules(rules) + [gate_rule], own_gate_present)
    print(f"opened tcp/{GATE_PORT} on firewall {FIREWALL_ID} for {runner_ip} after {attempts} attempt(s)")


def close_gate():
    attempts = apply_under_lock(kept_rules, lambda rules: not own_gate_present(rules))
    print(f"closed firewall {FIREWALL_ID} after {attempts} attempt(s)")


MODES = {"open": open_gate, "close": close_gate}
mode = os.environ["GATE_MODE"]
if mode not in MODES:
    raise SystemExit(f"mode must be one of {sorted(MODES)}, got {mode!r}")
MODES[mode]()
