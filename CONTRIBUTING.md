# Contributing

Created and maintained by A Haque (zaid).

Use Python 3.11 or later and install the test dependencies with `python -m pip install -e '.[test]'`. Run `python -m pytest -q` before opening a pull request. The tests use generated keys, local servers and simulated money; no bank or model-provider account is required.

Changes to permission checks, money states, retries, review or cryptography need tests of the affected security or failure boundary. Preserve existing accepted requests during upgrades. Never introduce an automatic retry that can turn an uncertain bank response into a second transfer.

Keep model output advisory. Do not add arbitrary tool execution, customer-password collection, credential-bearing URLs or approval shortcuts. Treat bank and agent identifiers as private data in examples and screenshots.

To test the console, install Node.js 22 or later and run:

```sh
cd tests/ui
npm ci
npx playwright install --with-deps chromium
npm test
```

The Python package must be installed in the active environment. Set `PYTHON` to its interpreter if necessary. Browser checks create disposable private state and screenshots under `.ui-artifacts`; they exercise real API roles and controls.

Describe the concrete change, affected behaviour, validation and any integration assumptions in each pull request. Use the private reporting route described in [SECURITY.md](SECURITY.md) for vulnerabilities. Contributions are under the repository's Apache 2.0 licence; preserve third-party notices and author credit.
