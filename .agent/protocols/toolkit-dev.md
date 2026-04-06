# Protocol: Toolkit Development

How to create new toolkits for the Synthcore engine.

## Structure

```
engine/toolkits/<toolkit-id>/
  manifest.json          # Required: toolkit metadata and file list
  templates/             # Required: template files to copy
    template-file.ext
    variant-file.ext     # Optional: stack-specific variants
```

## Manifest Schema

```json
{
  "id": "toolkit-id",
  "name": "Human-Readable Name",
  "version": "1.0.0",
  "stacks": ["fastapi-*", "python-cli"],  // or ["*"] for universal
  "files": [
    {
      "template": "default-file.ext",
      "target": "path/in/project/file.ext",
      "strategy": "create",
      "variants": {
        "fastapi-*": "python-variant.ext",
        "react-native*": "mobile-variant.ext"
      }
    }
  ],
  "dependencies": [
    { "file": "requirements.txt", "line": "package>=1.0", "strategy": "line-ensure" }
  ],
  "directories": ["tests", ".github/workflows"],
  "post_apply": ["command-to-run-after"]
}
```

## Key Rules

1. **strategy: create** — only creates if target doesn't exist (safe for existing projects)
2. **strategy: overwrite** — always overwrites (use sparingly)
3. **line-ensure** — appends a line to a file only if not already present
4. **variants** — stack patterns support wildcards (`fastapi-*` matches `fastapi-api`, `fastapi-react`, etc.)
5. **Templates are static** — no variable interpolation. Keep them generic.

## Testing

```powershell
# List all toolkits
.\apply-toolkit.ps1 -List

# Dry run with variant selection
.\apply-toolkit.ps1 -ToolkitId <id> -Stack <stack-id> -DryRun -ProjectRoot /tmp/test

# Apply for real
.\apply-toolkit.ps1 -ToolkitId <id> -Stack <stack-id> -ProjectRoot /path/to/project
```
