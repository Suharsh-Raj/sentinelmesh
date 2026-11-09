# SentinelMesh working rules

- Use `D:\PBL-3` as the working project and `D:\PBL3-BACKUP` for local snapshots.
- Before a new implementation phase, verify that a complete snapshot of the current state exists. Take a fresh snapshot if files have changed.
- After each completed and verified phase, create a new timestamped local snapshot with a verification manifest. Keep earlier snapshots. Include hidden files, local dependencies, datasets, model artifacts, Git metadata, and SQLite data with any required sidecars. Preserve link objects without traversing their targets.
- Run the relevant tests and start the app against an isolated database. Visually verify UI changes when browser tools are available.
- Review the diff and check tracked and staged files for secrets. Commit and push verified source and documentation changes to the existing `Suharsh-Raj/sentinelmesh` repository. Use a pull request when required.
- Keep credentials, personal mail, SQLite databases, environments, downloaded datasets, fitted artifacts, and backups out of GitHub. Never force-push.
- Gmail account selection and authorization require a separate step. Wait for the user to explicitly identify the intended account before connecting or authorizing Gmail. Never assume the currently signed-in account.
- AWS provisioning requires an explicit user request.
