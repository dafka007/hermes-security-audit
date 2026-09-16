# Contributing

Bug reports and small focused pull requests are welcome.

Before opening a PR:

```bash
python -m unittest discover -s tests -v
python -m compileall -q .
```

A few guidelines:

- Keep the plugin dependency-free unless there is a strong reason not to.
- Do not turn scanner errors into `PASS` results.
- Do not expose secret values in normalized output or logs.
- Keep scanner execution shell-free.
- If a change affects scanner behavior, include a test that covers it.

For security-sensitive reports, please follow [SECURITY.md](SECURITY.md) instead of posting exploit details in a public issue.
