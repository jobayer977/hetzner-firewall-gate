# Hetzner Firewall Gate

A GitHub Action that opens a Hetzner Cloud firewall for the current runner's public IP just long enough to deploy, then closes it again.

Use it when a server is closed to the internet by a Hetzner firewall allowlist and a GitHub-hosted runner still needs to reach it over SSH. Hosted runners get an unpredictable public IP from a range of thousands, so a static allowlist can never cover them.

## How it works

The action never rewrites your permanent rules. It appends one extra rule whose description identifies the run that created it, and removes that rule again on close.

1. `open` reads the firewall's current rules, appends a rule allowing TCP on the chosen port from the runner's IP only, and writes the set back.
2. Your deploy steps run.
3. `close` reads the rules again and removes the rule this run created.

The description looks like `ci-runner-temp:<owner>/<repo>:<run id>:<run attempt>`. Because the tag names the run, a job closing its gate can never strip a rule belonging to a different repository or a different run.

On `open` the action also sweeps rules tagged for the same repository but a different run, so a temporary rule left behind by a cancelled job is cleaned up by the next deploy of that repository rather than lingering.

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

**Understand what the concurrency group is protecting.** Hetzner's rule API replaces the whole rule set and offers no compare-and-swap, so two jobs that read the rules at the same moment can each write a set that drops the other's rule. Run-scoped tags stop a close from stripping someone else's gate, but they cannot prevent that lost update on open.

The action's defence is limited and worth stating plainly. After writing, it pauses, reads the rules back, and writes again if its own rule is missing, up to five times. That catches a competing write landing within a couple of seconds. It cannot catch one that lands later, while the deploy is already running.

A `concurrency` group is therefore the real protection, and a group only serialises jobs within one repository. Several repositories sharing one firewall need either a shared external lock or the acceptance that a rare collision will fail a deploy, which is the safe direction to fail.

## Requirements

Python 3, which is preinstalled on all GitHub-hosted runners. No other dependencies.

## Licence

MIT
