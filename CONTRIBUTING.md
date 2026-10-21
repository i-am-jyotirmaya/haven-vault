# Contributing

Use Node 22, pnpm 12, and npm 10 for the backend lockfile. Install both dependency sets as described in the README. Develop visual changes using the fictional demo; use a dedicated staging project for real authentication testing.

Before proposing changes:

```sh
pnpm test
pnpm test:config
pnpm test:backend
pnpm test:rules
pnpm build
```

Explain the problem, resulting behavior, and validation in your pull request. Add meaningful tests for changes to authentication, encryption, sessions, and authorization. Never loosen production rules to make a test pass. Encryption-format, recovery, sharing, or ownership changes need a migration and threat-model review.

Do not submit real vault files, passphrases, credentials, CLI logs, environment files, service-account keys, or private screenshots. Use fictional fixtures. Commit both lockfiles, but not node_modules, dist, functions/lib, emulator state, or local project bindings.

Report vulnerabilities privately as described in [SECURITY.md](SECURITY.md#reporting-a-vulnerability). Do not publish exploit details or sensitive data in an issue.
