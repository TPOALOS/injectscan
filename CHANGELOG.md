# Changelog

## 1.0.0

First release.

- Finds invisible Unicode (tag block and zero-width encodings are decoded), HTML and Markdown comments, CSS-hidden text, padded text, base64 payloads and image exfiltration
- Grades instruction-like wording, one level worse when it is hidden
- `--project` scans AI instruction files, `--sanitize` removes invisible characters, `--json`
