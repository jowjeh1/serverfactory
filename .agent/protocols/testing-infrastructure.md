# Protocol: Testing Infrastructure

Every project MUST have a working test setup before agents start building features.

## Requirements by Stack

### Python (fastapi-*, python-cli)
- `pytest.ini` with testpaths, markers, asyncio_mode
- `tests/` directory with `__init__.py` and `conftest.py`
- Dependencies: pytest, pytest-cov, pytest-asyncio

### Node.js (nextjs, vite-react, astro)
- Test runner configured in package.json (vitest or jest)
- `__tests__/` or `tests/` directory
- Dependencies: vitest or jest, @testing-library/*

### Mobile (react-native, react-native-game)
- Jest configured via package.json or jest.config.js
- @testing-library/react-native for component tests

### Game Engines (ue5-game, unity-game)
- Python integration tests in `Scripts/tests/`
- Engine-native test frameworks for module tests

## How to Set Up

Use the `pytest` toolkit (Python) or equivalent:
```powershell
.\apply-toolkit.ps1 -ToolkitId pytest -Stack <stack-id> -ProjectRoot <path>
```

## Rule

If `tests/` doesn't exist or the test command fails with "no tests collected", fix the infrastructure BEFORE writing test code. Never skip test setup assuming it exists.
