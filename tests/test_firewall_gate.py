import os
import subprocess
import sys
import threading
import time
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from hetzner_stub import Firewall, serve

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SCRIPT = os.path.join(ROOT, "firewall-gate.py")
APP = "Chatflowapp/app"
API = "Chatflowapp/core-api-service"
API_RUN_TAG = f"ci-runner-temp:{API}:900:1"
LOCK_LABEL = "ci-gate-lock"
BASE_RULE = {"direction": "in", "protocol": "tcp", "port": "443",
             "source_ips": ["0.0.0.0/0"], "description": "public https"}


def temp_rule(description):
    return {"direction": "in", "protocol": "tcp", "port": "22",
            "source_ips": ["203.0.113.9/32"], "description": description}


def run_gate(base_url, mode, repository, run_id, lock_attempts="60"):
    env = dict(os.environ,
               HETZNER_TOKEN="token", FIREWALL_ID="1", GATE_PORT="22", GATE_MODE=mode,
               GITHUB_REPOSITORY=repository, GITHUB_RUN_ID=run_id, GITHUB_RUN_ATTEMPT="1",
               HETZNER_API_ROOT=f"{base_url}/v1/firewalls", RUNNER_IP_SERVICE=f"{base_url}/ip",
               GATE_SETTLE_DELAY="0.2", GATE_RETRY_DELAY="0.3", GATE_LOCK_ATTEMPTS=lock_attempts)
    return subprocess.run([sys.executable, SCRIPT], env=env, capture_output=True, text=True, timeout=180)


class GateTest(unittest.TestCase):
    def start(self, rules, labels=None):
        self.firewall = Firewall(rules, labels)
        server = serve(self.firewall)
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        return f"http://127.0.0.1:{server.server_address[1]}"

    def assertGateSucceeded(self, result):
        self.assertEqual(result.returncode, 0, result.stderr)

    def assertHasRuleFor(self, repository):
        descriptions = self.firewall.descriptions()
        self.assertTrue(any(repository in description for description in descriptions), descriptions)

    def open_while_a_slow_write_is_in_flight(self, slow_repository):
        base_url = self.start([BASE_RULE])
        self.firewall.hold_needle = APP
        self.firewall.hold_seconds = 6
        slow = {}
        thread = threading.Thread(target=lambda: slow.update(
            result=run_gate(base_url, "open", slow_repository, "800")))
        thread.start()
        time.sleep(0.8)
        self.assertGateSucceeded(run_gate(base_url, "open", APP, "901"))
        thread.join(180)
        return slow["result"]

    def test_a_concurrent_deploy_in_another_repository_never_drops_our_open_rule(self):
        self.assertGateSucceeded(self.open_while_a_slow_write_is_in_flight(API))
        self.assertHasRuleFor(APP)
        self.assertHasRuleFor(API)

    def test_a_close_in_one_repository_never_drops_another_repositorys_open(self):
        base_url = self.start([BASE_RULE, temp_rule(f"{API_RUN_TAG}:exp={int(time.time()) + 3600}")])
        self.firewall.hold_needle = API_RUN_TAG
        self.firewall.hold_seconds = 6

        closer = {}
        thread = threading.Thread(target=lambda: closer.update(
            result=run_gate(base_url, "close", API, "900")))
        thread.start()
        time.sleep(1)
        self.assertGateSucceeded(run_gate(base_url, "open", APP, "901"))
        thread.join(180)
        self.assertGateSucceeded(closer["result"])
        descriptions = self.firewall.descriptions()
        self.assertTrue(any(APP in description for description in descriptions), descriptions)
        self.assertFalse(any(API in description for description in descriptions), descriptions)

    def test_an_expired_rule_from_another_repository_is_reclaimed(self):
        leaked = f"ci-runner-temp:{API}:700:1:exp={int(time.time()) - 60}"
        base_url = self.start([BASE_RULE, temp_rule(leaked)])
        self.assertGateSucceeded(run_gate(base_url, "open", APP, "901"))
        self.assertNotIn(leaked, self.firewall.descriptions())

    def test_a_live_rule_from_another_repository_is_preserved(self):
        live = f"ci-runner-temp:{API}:700:1:exp={int(time.time()) + 3600}"
        base_url = self.start([BASE_RULE, temp_rule(live)])
        self.assertGateSucceeded(run_gate(base_url, "open", APP, "901"))
        self.assertIn(live, self.firewall.descriptions())

    def test_an_unstamped_rule_from_another_repository_is_preserved(self):
        legacy = f"ci-runner-temp:{API}:700:1"
        base_url = self.start([BASE_RULE, temp_rule(legacy)])
        self.assertGateSucceeded(run_gate(base_url, "open", APP, "901"))
        self.assertIn(legacy, self.firewall.descriptions())

    def test_a_leaked_lock_rule_from_the_previous_gate_is_reclaimed(self):
        leaked = f"ci-runner-temp:lock:{API}:700:1:exp={int(time.time()) - 60}"
        base_url = self.start([BASE_RULE, temp_rule(leaked)])
        self.assertGateSucceeded(run_gate(base_url, "open", APP, "901"))
        self.assertNotIn(leaked, self.firewall.descriptions())

    def test_open_then_close_leaves_the_firewall_as_it_was_found(self):
        base_url = self.start([BASE_RULE], {"env": "staging"})
        self.assertGateSucceeded(run_gate(base_url, "open", APP, "901"))
        self.assertEqual(len(self.firewall.snapshot()), 2)
        self.assertGateSucceeded(run_gate(base_url, "close", APP, "901"))
        self.assertEqual(self.firewall.snapshot(), [BASE_RULE])
        self.assertEqual(self.firewall.label_snapshot(), {"env": "staging"})

    def test_an_expired_lock_does_not_block_a_later_deploy(self):
        stale = f"{API}:700:1".replace("/", "_") + f".exp-{int(time.time()) - 60}"
        base_url = self.start([BASE_RULE], {LOCK_LABEL: stale})
        self.assertGateSucceeded(run_gate(base_url, "open", APP, "901"))
        self.assertHasRuleFor(APP)

    def test_a_live_lock_from_another_repository_blocks_until_it_is_released(self):
        live = f"{API}:700:1".replace("/", "_") + f".exp-{int(time.time()) + 3600}"
        base_url = self.start([BASE_RULE], {LOCK_LABEL: live})
        result = run_gate(base_url, "open", APP, "901", lock_attempts="3")
        self.assertEqual(result.returncode, 1, result.stdout)
        self.assertIn("lock not acquired", result.stderr)
        self.assertEqual(self.firewall.snapshot(), [BASE_RULE])


if __name__ == "__main__":
    unittest.main()
