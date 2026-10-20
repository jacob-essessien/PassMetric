# Security

PassMetric is a university portfolio project, not an audited production password manager.

- Do not commit `.env`, `.secret_key`, SQLite databases, datasets, generated models, or real credentials.
- Report a suspected vulnerability privately to the repository owner rather than opening a public issue.
- Rotate a credential immediately if it is ever committed, even if the commit is later deleted.
- Only load an ML model generated locally by this project. Python pickle files are not safe when obtained from an untrusted source.

The derived vault key is held in process memory for a single-process deployment and expires after 15 minutes of inactivity. Only an opaque handle is stored in the browser session cookie. Website, username, and notes metadata remain plaintext in SQLite; stored passwords are encrypted with AES-256-GCM.
