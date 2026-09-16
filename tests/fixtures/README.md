# Test Fixtures

JSON feature blobs for unit testing. These allow tests to run without
real malware samples or API calls.

## Format

Each `.json` file is a features dict as produced by `feature_extractor.py`.
The `sample.path` field will point to non-existent paths — that's expected for fixtures.

## Creating new fixtures

```bash
macskillet /path/to/sample --features-only --pretty \
  -o tests/fixtures/sample_name.json
```

Then redact any sensitive paths before committing.

## Files

- `clean_notarized.json` — notarized App Store app, expected BENIGN
- `adhoc_signed.json` — ad-hoc signed binary, expected SUSPICIOUS
- `amos_variant.json` — AMOS stealer features, expected MALICIOUS (REDACTED)
- `upx_packed.json` — UPX-packed binary features, expected SUSPICIOUS/MALICIOUS
