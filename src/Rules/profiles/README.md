# Profile lifecycle metadata

Profiles are active by default, so existing profile JSON remains compatible. To retire a profile without breaking baselines that already reference it, keep its JSON file and add:

```json
{
  "status": "deprecated",
  "deprecated_at": "2026-08-13",
  "deprecation_note": "Explain why this profile should no longer be selected.",
  "replacement_profile": "replacement-profile-id"
}
```

`deprecated_at` is required when `status` is `deprecated`. The note and replacement profile are optional. Dashboard catalog imports hide deprecated profiles from new baseline creation while preserving existing baselines and displaying the retirement guidance.
