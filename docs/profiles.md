# Environment Profiles

Each Hunt Card opens with a query for Microsoft Sentinel Logs and lists its required workspace table. Choose an alternate query profile when the Hunt Card offers one.

| Query profile | Workspace requirement |
| --- | --- |
| Sentinel Windows | Windows Security Events via AMA or Windows Event Forwarding, as specified on the hunt. Sysmon network hunting requires Sysmon Event ID 3. |
| Sentinel Endpoint and Email | Enable raw event streaming for the specific table through the Microsoft Defender XDR connector. Open these queries in Sentinel Logs. |
| Sentinel Entra | Stream the appropriate sign-in or directory audit category to the workspace. |
| Sentinel CEF | Collect network or proxy CEF logs and check the vendor's field mappings. |
| Sentinel Azure | Route Graph or Key Vault diagnostics into the workspace and check the named table. |
| Sentinel Alerts | Connect the product that emits the detection names the query looks for. |
| Defender XDR | Optional alternate query for Defender Advanced Hunting. It uses `Timestamp`. |

The optional proxy example uses a synthetic `CustomWeb_CL` schema. Adapt the mappings locally to reflect your provider's fields and how it represents allowed and blocked traffic.

Copy a synthetic profile object from `profiles/catalog.json` to an ignored or external path. Adjust its timestamp, mapped host and URL fields, action field and any optional projection fields. The introductory campaign destination hunt supports a local web profile. The renderer validates its generated query with the Microsoft analyzer.

```text
python -m pipeline.render HF-2026-0003 --local-profile .private/proxy.json --days 7 --json
```

The JSON output produces a single summarized cell. Analyze large result sets in a narrower time window when memory or client display limits apply.
