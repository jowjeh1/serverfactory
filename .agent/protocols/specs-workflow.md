# Protocol: Specs Workflow

Specs are dynamic work items that live in the project repo at `.agent/specs/`.

## Lifecycle

1. **Created by**: Advisors, orchestrators, or Josh (manually)
2. **Read by**: Agents at the start of each cycle
3. **Completed**: Move to `.agent/specs/done/` when finished
4. **Format**: Markdown files with structured frontmatter

## Spec Format

```markdown
# SPEC-001: Short Title

**Priority**: high | medium | low
**Assigned**: backend | frontend | qa | devops | any
**Created**: 2026-03-09

## Problem
What needs to be fixed or built.

## Acceptance Criteria
- [ ] Criterion 1
- [ ] Criterion 2

## Notes
Any additional context.
```

## Agent Behavior

Each cycle, agents should:
1. Check `.agent/specs/` for specs matching their role
2. Pick the highest-priority unfinished spec
3. Work on it (may take multiple cycles)
4. When all criteria are met, move the file to `.agent/specs/done/`
5. Log the completion in their HEARTBEAT.md

## Toolkit Request Signal

When agents hit infrastructure gaps, they emit a toolkit request signal:
```json
{
  "type": "toolkit-request",
  "agent": "qa-agent",
  "description": "Need pytest infrastructure for Python project",
  "stack": "fastapi-api",
  "suggested_toolkit": "pytest"
}
```

These signals are collected by `activity-reporter.js` and visible in the console.
