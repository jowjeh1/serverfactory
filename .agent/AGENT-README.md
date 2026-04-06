# .agent/ -- Multi-Agent Development Infrastructure

This directory is used by autonomous AI agents to coordinate work on this repo.

## Structure

| Directory | Purpose | Who writes |
|-----------|---------|------------|
| memory/ | Per-agent state | Each agent writes own |
| bugs/ | Bug reports | Echo (QA) |
| test-reports/ | Test summaries | Echo (QA) |
| inbox/ | Cross-agent messages | Any agent |
| costs/ | Daily cost tracking | All agents |

## Rules

- DO NOT manually edit agent memory files during active hours
- Files prefixed with done- are resolved
- See AGENT-PLAYBOOK.md in infrastructure repo for full docs
