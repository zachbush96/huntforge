# Environment Profiles

Public profiles describe table and field contracts, timestamp meanings and execution target. Use Microsoft Defender advanced hunting for the Defender XDR profiles. Use Sentinel Logs for Entra, CEF and custom workspace tables.

The browser's Menlo-style and proxy examples use synthetic `CustomWeb_CL` schemas. Their action and disposition values preserve what the source reports. Adapt a profile locally to reflect permitted and blocked traffic correctly.

Copy a synthetic profile object from `profiles/catalog.json` to an ignored or external path. Adjust its timestamp, mapped host and URL fields, action field and any optional projection fields. The introductory campaign destination hunt supports a local web profile. The renderer validates its generated query with the Microsoft analyzer.

```text
python -m pipeline.render HF-2026-0003 --local-profile .private/proxy.json --days 7 --json
```

The JSON output produces a single summarized cell. Analyze large result sets in a narrower time window when memory or client display limits apply.
