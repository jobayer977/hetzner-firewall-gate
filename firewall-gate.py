import hashlib
import ipaddress
import json
import os
import random
import re
import time
import urllib.request

TAG_PREFIX = "ci-runner-temp"
EXPIRY_MARKER = "exp="
LOCK_LABEL = "ci-gate-lock"
LOCK_SEPARATOR = ".exp-"
OWNER_LIMIT = 46
DIGEST_LENGTH = 8
LABEL_ALLOWED = re.compile(r"[^A-Za-z0-9_.-]")

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


def read_json(url, method="GET", body=None):
    payload = json.dumps(body).encode() if body is not None else None
    request = urllib.request.Request(url, method=method, data=payload)
    request.add_header("Authorization", f"Bearer {TOKEN}")
    request.add_header("Content-Type", "application/json")
    with urllib.request.urlopen(request, timeout=30) as response:
        return json.load(response)


def read_firewall():
    return read_json(f"{API_ROOT}/{FIREWALL_ID}")["firewall"]


def read_rules():
    return read_firewall()["rules"]


def read_labels():
    return read_firewall().get("labels") or {}


def write_rules(rules):
    read_json(f"{API_ROOT}/{FIREWALL_ID}/actions/set_rules", "POST", {"rules": rules})


def write_labels(labels):
    read_json(f"{API_ROOT}/{FIREWALL_ID}", "PUT", {"labels": labels})


def read_runner_ip():
    with urllib.request.urlopen(PUBLIC_IP_SERVICE, timeout=30) as response:
        return ipaddress.ip_address(response.read().decode().strip())


def label_safe(value):
    cleaned = LABEL_ALLOWED.sub("_", value)
    if len(cleaned) <= OWNER_LIMIT:
        return cleaned
    digest = hashlib.sha1(cleaned.encode()).hexdigest()[:DIGEST_LENGTH]
    return f"{cleaned[:OWNER_LIMIT - DIGEST_LENGTH - 1]}-{digest}"


LOCK_OWNER = label_safe(f"{REPOSITORY}:{RUN_ID}:{RUN_ATTEMPT}")


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


def is_own_gate(rule):
    return description_of(rule).startswith(f"{RUN_TAG}:")


def is_own_repository_rule(rule):
    return description_of(rule).startswith(f"{REPOSITORY_TAG}:")


def is_reclaimable(rule):
    if is_own_gate(rule):
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


def kept_rules(rules):
    return [rule for rule in rules if not is_reclaimable(rule) and not is_own_gate(rule)]


def lock_parts(labels):
    holder, separator, raw = (labels.get(LOCK_LABEL) or "").rpartition(LOCK_SEPARATOR)
    if not separator or not raw.isdigit():
        return "", 0
    return holder, int(raw)


def lock_is_ours(labels):
    return lock_parts(labels)[0] == LOCK_OWNER


def lock_is_takeable(labels):
    holder, deadline = lock_parts(labels)
    return not holder or holder == LOCK_OWNER or deadline <= time.time()


def backoff():
    time.sleep(RETRY_DELAY_SECONDS * (0.5 + random.random()))


def lock_value():
    return f"{LOCK_OWNER}{LOCK_SEPARATOR}{int(time.time() + LOCK_TTL_SECONDS)}"


def claim_lock():
    for attempt in range(1, LOCK_ATTEMPTS + 1):
        labels = read_labels()
        if lock_is_takeable(labels):
            write_labels({**labels, LOCK_LABEL: lock_value()})
            time.sleep(SETTLE_DELAY_SECONDS)
            if lock_is_ours(read_labels()):
                return attempt
        backoff()
    raise SystemExit(f"firewall {FIREWALL_ID} gate lock not acquired after {LOCK_ATTEMPTS} attempts")


def release_lock():
    labels = read_labels()
    if not lock_is_ours(labels):
        return
    write_labels({key: value for key, value in labels.items() if key != LOCK_LABEL})


def settle(build_wanted_rules, is_settled):
    for attempt in range(1, WRITE_ATTEMPTS + 1):
        claim_lock()
        write_rules(build_wanted_rules(read_rules()))
        time.sleep(SETTLE_DELAY_SECONDS)
        if is_settled(read_rules()):
            return attempt
        time.sleep(RETRY_DELAY_SECONDS)
    raise SystemExit(f"firewall {FIREWALL_ID} did not settle after {WRITE_ATTEMPTS} attempts")


def apply_under_lock(build_wanted_rules, is_settled):
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
