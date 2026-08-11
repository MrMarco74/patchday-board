# CLAUDE.md

Guidance for Claude Code (and other coding agents) working in this directory.

## Deployment is owned by LabControl

`patchday_backend.py` here is a helper copy that feeds into the
`patchday-backend` service and CyberPulse SSVC scoring on `worker` — actual
production deployment of both is managed by LabControl's
`app_patchday_backend` / `app_cyberpulse` Ansible roles
(`app/seed_playbooks/roles/` in the `labcontrol` repo).

**Workflow: commit → push → run the relevant playbook (`patchday-backend.yml`
/ `cyberpulse.yml`) via LabControl** (`lifecycle_action=update`), through
its MCP server (`mcp__labcontrol__run_playbook`) or the LabControl web UI.

Never hand-run `rsync`/`ssh` against `worker` and never edit the code
directly on the production host — changes made that way are not tracked in
git and get silently overwritten by the next deploy anyway. There used to
be `deploy_cyberpulse_ssvc.sh` and `deploy_patchday.sh` here that did
exactly that; both have been removed for this reason.
