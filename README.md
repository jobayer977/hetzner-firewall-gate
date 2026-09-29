# Hetzner Firewall Gate

A GitHub Action that opens a Hetzner Cloud firewall for the current runner's public IP just long enough to deploy, then closes it again.

Use it when a server is closed to the internet by a Hetzner firewall allowlist and a GitHub-hosted runner still needs to reach it over SSH. Hosted runners get an unpredictable public IP from a range of thousands, so a static allowlist can never cover them.

## How it works

The action never rewrites your permanent rules. It appends one extra rule whose description identifies the run that created it, and removes that rule again on close.

1. `open` takes a lock on the firewall, reads the current rules, appends a rule allowing TCP on the chosen port from the runner's IP only, writes the set back, and releases the lock.
2. Your deploy steps run.
3. `close` takes the same lock and removes the rule this run created.

The description looks like `ci-runner-temp:<owner>/<repo>:<run id>:<run attempt>:exp=<unix time>`. Because the tag names the run, a job closing its gate can never strip a rule belonging to a different repository or a different run.

### The lock

Hetzner's rule API replaces the whole rule set and offers no compare-and-swap, so two jobs that read the rules at the same moment can each write a set that drops the other's rule. GitHub's `concurrency` groups are scoped to one repository, so they cannot serialise repositories that share a firewall.

The action therefore serialises on the firewall itself. Every read-modify-write happens while holding a lease, recorded as a rule tagged `ci-runner-temp:lock:<owner>/<repo>:<run id>:<run attempt>:exp=<unix time>` and pointing at `192.0.2.1/32`, an address from the documentation range that routes nowhere. A caller claims the lease only when it sees no live foreign lease, then reads the rules back to confirm the lease is its own before mutating anything. A caller that loses the claim backs off with jitter and tries again. The lease carries a fifteen minute expiry, so a killed runner cannot wedge the firewall.

### Expiry and reclamation

Every rule the action writes carries an expiry in its description: one hour for a gate rule, fifteen minutes for a lease. Any caller holding the lease reclaims expired rules, whichever repository wrote them. A rule left behind by a cancelled job or a killed runner is therefore cleared by the next deploy of any repository sharing the firewall, not only by the repository that leaked it.

Rules written by older versions of this action carry no expiry. They are left alone, and swept as before by the repository that owns them.

The runner's address is parsed before use, so a malformed or unexpected response from the address service fails the step rather than producing a rule. IPv4 becomes a `/32` and IPv6 a `/128`.

## Usage

```yaml
jobs:
  deploy:
    runs-on: ubuntu-latest
    concurrency:
      group: staging-firewall
      cancel-in-progress: false
    steps:
      - uses: actions/checkout@v4

      - name: Open firewall
        uses: jobayer977/hetzner-firewall-gate@<commit sha>
        with:
          mode: open
          hetzner_token: ${{ secrets.HETZNER_TOKEN }}
          firewall_id: ${{ secrets.HETZNER_FIREWALL_ID }}

      - name: Deploy
        uses: appleboy/ssh-action@v1.0.3
        with:
          host: ${{ secrets.STAGING_HOST }}
          username: root
          key: ${{ secrets.PRIVATE_KEY }}
          script: echo deploying

      - name: Close firewall
        if: always()
        uses: jobayer977/hetzner-firewall-gate@<commit sha>
        with:
          mode: close
          hetzner_token: ${{ secrets.HETZNER_TOKEN }}
          firewall_id: ${{ secrets.HETZNER_FIREWALL_ID }}
```

## Inputs

| Input | Required | Default | Description |
|---|---|---|---|
| `mode` | yes | | `open` or `close` |
| `hetzner_token` | yes | | Hetzner Cloud API token with firewall write access |
| `firewall_id` | yes | | Numeric id of the firewall to gate |
| `port` | no | `22` | TCP port opened for the runner while the gate is open |

Find the firewall id in the Hetzner Cloud console URL, or through `GET https://api.hetzner.cloud/v1/firewalls`.

## Notes on safe use

**Always pair `open` with a `close` step that carries `if: always()`.** Without it a cancelled or failed job leaves the gate open until the next deploy of that repository sweeps it.

**Pin the action to a commit SHA rather than a tag.** Every caller hands this action a Hetzner API token, so a moving tag means whoever controls the tag controls that token.

**Give the token the smallest scope you can.** Hetzner tokens are project-wide, so create a token used by nothing else and rotate it on a schedule.

**A `concurrency` group is still worth setting.** The lease makes concurrent deploys correct; a `concurrency` group makes them cheap, by keeping jobs in one repository from queueing on the lease at all.

## Requirements

Python 3, which is preinstalled on all GitHub-hosted runners. No other dependencies.

## Licence

MIT
