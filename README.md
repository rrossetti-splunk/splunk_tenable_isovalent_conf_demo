# Isovalent ↔ Tenable Correlation Demo Events

Synthetic Isovalent runtime events aligned to open Tenable Cloud Security findings so correlation SPL can be demonstrated in Splunk.

## Files

| File | Purpose |
|------|---------|
| `events/isovalent_correlation_events.ndjson` | 13 HEC-ready events (one JSON object per line) |
| `send_to_splunk_hec.sh` | Posts the NDJSON file to Splunk HEC |
| `dashboards/isovalent_tenable_dev.xml` | Simple XML dev dashboard for both data sources |

## Tenable findings matched

| Cluster | Namespace | Workload | Tenable finding |
|---------|-----------|----------|-----------------|
| `TenableUse2Eks1` | `kube-system` | `eks-pod-identity-agent` (DaemonSet) | Container Image has vulnerabilities |
| `alex-aws-cluster` | `kube-system` | `kube-proxy` (DaemonSet) | Container Image has vulnerabilities |
| `alex-aws-cluster` | `kube-system` | `coredns` (Deployment) | Container Image has vulnerabilities (3 Critical) |
| `alex-aws-cluster` | `kube-system` | `aws-network-policy-agent` (DaemonSet) | Container Image EOL OS (Amazon Linux 2) |
| `delete-test-proxy-config` | `kube-system` | `eks-pod-identity-agent` (DaemonSet) | EKS Cluster contains nodes with public IPs |

Container images use the same ECR paths as Tenable finding descriptions, except where noted below for **image drift** demo cases.

### Image drift (posture vs runtime mismatch)

These workloads appear in the **Container Image Match** pie chart as `no match` — realistic cases where runtime diverged from what Tenable last scanned:

| Cluster | Workload | Tenable posture image | Runtime image (Isovalent) | Story |
|---------|----------|----------------------|----------------------------|-------|
| `alex-aws-cluster` | `aws-network-policy-agent` | `...amazon/aws-network-policy-agent` | `...eks/aws-network-policy-agent:v1.1.0-eksbuild.1` | EKS upgrade moved the image to a different ECR repo path |
| `delete-test-proxy-config` | `eks-pod-identity-agent` | `...eks/eks-pod-identity-agent` | `public.ecr.aws/eks-distro/eks-pod-identity-agent:v0.1.5` | Emergency hotfix pulled from Public ECR instead of account ECR |

## Send to Splunk

Edit `send_to_splunk_hec.sh` and set `SPLUNK_HEC_URL` and `SPLUNK_HEC_TOKEN` at the top of the file, then:

```bash
chmod +x demo/send_to_splunk_hec.sh
./demo/send_to_splunk_hec.sh
```

Ensure the HEC token is allowed to write to index `cisco_security_cloud`.

## Add the dev dashboard to Splunk

The Splunk MCP server cannot create dashboards (query-only). Install manually:

**Option A — UI paste**

1. Dashboards → Create New Dashboard → Dashboard
2. Source → paste contents of `dashboards/isovalent_tenable_dev.xml`
3. Save as `isovalent_tenable_dev`

**Option B — filesystem**

```bash
cp demo/dashboards/isovalent_tenable_dev.xml \
  $SPLUNK_HOME/etc/apps/search/local/data/ui/views/isovalent_tenable_dev.xml
# restart Splunk or bump /servicesNS/nobody/search/admin/_new
```

Default time range is **Last 5 years** so older seeded events still appear. Re-run `./send_to_splunk_hec.sh` to restamp events with the current time (recommended). Re-sending accumulates historical processExec rows in Splunk; the dashboard pie chart uses `sort - _time | dedup cluster workload` so only the **latest** runtime image per workload is compared to posture.

## Verify correlation in Splunk

Workload-level join:

```spl
index=tenable source=Ermetic type=Finding status=Open resources{}="*/*/*/*"
| rex field=resources{} "cluster/(?<cluster>[^/]+)/(?<namespace>[^/]+)/(?<workload_kind>[^/]+)/(?<workload_name>[^\"]+)"
| eval join_key=cluster."|".namespace."|".workload_kind."|".workload_name
| join join_key [
    search index=cisco_security_cloud source=demo-tenable-correlation
    | eval cluster=coalesce(cluster, cluster-name)
    | eval namespace=coalesce(pod_namespace, kubernetes_namespace, 'event.process.namespace', 'event.network_connect.source.namespace', 'event.process_exec.process.pod.namespace')
    | eval workload_kind=coalesce('process_exec.process.pod.workload_kind', kubernetes_workload_kind, 'event.process.workload_kind', 'event.process_exec.process.pod.workload_kind')
    | eval workload_name=coalesce('process_exec.process.pod.workload', kubernetes_workload_name, 'event.process.workload_name', 'event.process_exec.process.pod.workload')
    | eval join_key=cluster."|".namespace."|".workload_kind."|".workload_name
    | stats count as runtime_events, values(sourcetype) as isovalent_sourcetypes by join_key
]
| table _time, severity, title, cluster, namespace, workload_kind, workload_name, runtime_events, isovalent_sourcetypes, link
```

Cluster-level (broader):

```spl
index=cisco_security_cloud source=demo-tenable-correlation
| eval cluster=coalesce(cluster, cluster-name)
| join cluster [
    search index=tenable source=Ermetic type=Finding status=Open
    | rex field=resources{} "cluster/(?<cluster>[^/\"]+)"
    | stats count as open_findings, values(title) as finding_titles by cluster
]
| table _time, cluster, sourcetype, open_findings, finding_titles
```
