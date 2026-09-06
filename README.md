# Hetzner Firewall Gate

A GitHub Action that opens a Hetzner Cloud firewall for the current runner's public IP just long enough to deploy, then closes it again.

Use it when a server is closed to the internet by a Hetzner firewall allowlist and a GitHub-hosted runner still needs to reach it over SSH. Hosted runners get an unpredictable public IP from a range of thousands, so a static allowlist can never cover them.

## How it works

The action never rewrites your permanent rules. It appends one extra rule tagged `ci-runner-temp`, and on close removes any rule carrying that tag.

1. `open` reads the firewall's current rules, appends a rule allowing TCP on the chosen port from the runner's IP only, and writes the set back.
2. Your deploy steps run.
3. `close` reads the rules again and removes every `ci-runner-temp` rule.

Because close strips rules by tag rather than restoring a remembered list, a temporary rule left behind by an interrupted run is swept up by the next run that closes the gate.

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
        uses: jobayer977/hetzner-firewall-gate@v1
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
        uses: jobayer977/hetzner-firewall-gate@v1
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

**Always pair `open` with a `close` step that carries `if: always()`.** Without it a cancelled or failed job leaves the gate open until the next successful run.

**Pin the action to a commit SHA rather than a tag.** Every caller hands this action a Hetzner API token, so a moving tag means whoever controls the tag controls that token.

**Give the token the smallest scope you can.** Hetzner tokens are project-wide, so create a token used by nothing else and rotate it on a schedule.

**Serialise deploys that share one firewall.** Hetzner's rule API has no compare-and-swap, so two jobs writing at the same moment can lose an update. A `concurrency` group covers one repository; several repositories sharing a firewall need the group in each of them, and even then the action's write-then-verify retry is what catches a genuine collision.

## Requirements

Python 3, which is preinstalled on all GitHub-hosted runners. No other dependencies.

## Licence

MIT
