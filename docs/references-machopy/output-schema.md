# Classification Report — Output Schema

## Full JSON Schema

```json
{
  "report_version": "1.0",
  "sample": {
    "name": "string — bundle name or binary filename",
    "path": "string — path analyzed",
    "type": "app_bundle | macho_binary | universal_binary | dylib",
    "sha256": "string",
    "md5": "string",
    "filesize_bytes": "integer",
    "analysis_timestamp": "ISO 8601"
  },

  "verdict": "MALICIOUS | SUSPICIOUS | BENIGN",
  "confidence": "HIGH | MEDIUM | LOW",
  "risk_score": "integer — total from risk signal scoring",
  "recommendation": "BLOCK | INVESTIGATE | ALLOW",

  "summary": "string — 2-4 sentence human-readable verdict summary",

  "key_indicators": [
    "string — top signals that drove the verdict, in order of weight"
  ],

  "reasoning_chain": [
    {
      "step": "integer",
      "observation": "string — what the agent observed",
      "inference": "string — what the agent inferred from it",
      "risk_delta": "integer — score change from this step"
    }
  ],

  "static_features": {
    "bundle": {
      "bundle_id": "string",
      "bundle_version": "string",
      "main_executable": "string",
      "lsui_element": "boolean",
      "ls_background_only": "boolean",
      "has_launch_agent": "boolean",
      "has_launch_daemon": "boolean",
      "embedded_scripts": ["string"],
      "info_plist_keys": {}
    },

    "signature": {
      "signed": "boolean",
      "signing_status": "apple_signed | developer_id | ad_hoc | unsigned | invalid",
      "verification": "cryptographic | invalid | unverified — see docs/references-machopy/code-signature-verification.md",
      "notarized": "boolean",
      "team_id": "string | null",
      "bundle_id_match": "boolean",
      "cert_chain": []
    },

    "entitlements": {
      "sandboxed": "boolean",
      "has_private_entitlements": "boolean",
      "has_debug_entitlement": "boolean",
      "keys": {}
    },

    "macho": {
      "architectures": ["x86_64 | arm64 | ..."],
      "filetype": "EXECUTE | DYLIB | BUNDLE | ...",
      "flags": [],
      "segments": [
        {
          "name": "string",
          "entropy": "float",
          "size": "integer"
        }
      ],
      "load_commands": [],
      "dylib_dependencies": [],
      "imports": {
        "by_library": {}
      },
      "exports": [],
      "similarity_hashes": {
        "dylib_hash": "string",
        "import_hash": "string",
        "export_hash": "string",
        "symhash": "string"
      },
      "uuid": "string"
    },

    "strings_of_interest": [
      {
        "value": "string",
        "category": "url | ip | path | command | encoding | other",
        "risk": "HIGH | MEDIUM | LOW"
      }
    ]
  },

  "risk_signals": [
    {
      "signal": "string — signal name",
      "category": "signature | bundle | macho | strings | entitlements | imports",
      "score": "integer",
      "detail": "string — specific value that triggered this signal"
    }
  ]
}
```

## Minimal Report (for quick triage)

When doing bulk analysis or fast triage, output at minimum:

```json
{
  "sha256": "string",
  "name": "string",
  "verdict": "MALICIOUS | SUSPICIOUS | BENIGN",
  "confidence": "HIGH | MEDIUM | LOW",
  "risk_score": "integer",
  "summary": "string",
  "key_indicators": []
}
```

## Verdict Guidelines

**MALICIOUS / HIGH confidence**: Multiple corroborating high-risk signals, clear attack
capability (injection triad, persistence + C2 URLs, credential theft pattern).

**MALICIOUS / MEDIUM confidence**: Strong individual signals but some ambiguity (e.g.,
injection APIs present but could be legitimate tool; no corroborating network indicators).

**SUSPICIOUS / HIGH confidence**: Several medium-risk signals that together suggest malicious
intent, but no single smoking gun. Requires further dynamic analysis.

**SUSPICIOUS / LOW confidence**: A few anomalies that could be benign (e.g., ad-hoc signed
developer tool, non-standard bundle structure for a legitimate app).

**BENIGN / HIGH confidence**: Valid signature, standard bundle structure, expected APIs,
no suspicious strings or entitlements.

**BENIGN / MEDIUM confidence**: Minor anomalies (e.g., unsigned but matches known-good hash,
or common developer tool with expected ad-hoc signing).
