# Tenable Cloud Security → Splunk (Kubernetes Findings)

Pull open Kubernetes posture findings from Tenable Cloud Security and send them to Splunk via HEC. Reference integration for Splunk .conf demos and your own environment.

## Why correlate posture with runtime?

Tenable Cloud Security tells you **what should be a risk** — vulnerable images, misconfigurations, and policy violations across your clusters. Isovalent (Cisco) tells you **what is actually happening** — process execution, network connections, and security alerts on those same workloads.

Correlating both in Splunk lets you:

- **Prioritize findings with runtime context** — focus on vulnerable workloads that are actively running, not just present in a scan
- **Catch drift** — spot when runtime images diverge from what posture last assessed
- **Accelerate investigation** — jump from a Tenable finding to the pods, processes, and alerts on the same cluster/namespace/workload

Bundled sample Isovalent runtime events live in `events/` if you want correlation examples without a live Isovalent feed.

## Prerequisites

- Python 3.10+
- Tenable Cloud Security API token ([GraphQL docs](https://developer.tenable.com/docs/graphql-api))
- Splunk with HEC enabled
- HEC token allowed to write to your target index (default: `tenable`)

## Quick start

```bash
pip install requests
cp env.txt .env          # edit with your credentials
python3 tenable_to_splunk.py --probe-endpoints
python3 tenable_to_splunk.py --send-to-splunk
```

File-only run (no Splunk needed):

```bash
python3 tenable_to_splunk.py
# writes tenable_hec_output.txt
```

## Configuration

Copy `env.txt` to `.env`. Variables:

| Variable | Required | Description |
|----------|----------|-------------|
| `TENABLE_CUSTOMER_ID` | Yes | Tenable customer ID (used in finding links) |
| `TENABLE_API_TOKEN` | Yes | Cloud Security API token |
| `TENABLE_API_URL` | No | Default: `https://app.tenable.com/api/graph` (use `app.tenable.us` for Gov Cloud) |
| `SPLUNK_HEC_URL` | For `--send-to-splunk` | HEC endpoint |
| `SPLUNK_HEC_TOKEN` | For `--send-to-splunk` | HEC token |
| `SPLUNK_HEC_VERIFY_SSL` | No | Default: `false` |
| `SPLUNK_INDEX` | No | Default: `tenable` |
| `SPLUNK_SOURCE` | No | Default: `demo-tenable-correlation` |
| `SPLUNK_SOURCETYPE` | No | Default: `httpevent` |

## Dashboards

Install manually in Splunk (Dashboards → Create → paste XML source):

| File | Use |
|------|-----|
| `dashboards/isovalent_tenable_narrative.xml` | Story-driven demo |
| `dashboards/isovalent_tenable_dev.xml` | Dev/debug panels |

Dashboards expect findings with `source=demo-tenable-correlation` (this script) and/or `source=Ermetic` (native Tenable Splunk app). For Isovalent correlation, runtime events use `index=cisco_security_cloud` and `sourcetype=cisco:isovalent:*`.

## Verify in Splunk

```spl
index=tenable source=demo-tenable-correlation type=Finding status=Open
| stats count by severity, title
```

## License

Apache License 2.0 — see [LICENSE](LICENSE).
