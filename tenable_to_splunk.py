#!/usr/bin/env python3
"""Pull Kubernetes entities and open findings from Tenable Cloud Security.

By default, writes Splunk HEC-ready events to a local text file (one JSON object per line).
Use --send-to-splunk to post those events to Splunk HEC.

Usage:
  cp env.txt .env   # then edit .env with your credentials
  python3 tenable_to_splunk.py
  python3 tenable_to_splunk.py --output tenable_hec_output.txt
  python3 tenable_to_splunk.py --send-to-splunk
  python3 tenable_to_splunk.py --probe-endpoints

Configuration is read from environment variables (see env.txt). A .env file
next to this script is loaded automatically if present.

GraphQL endpoint (per Tenable docs):
  Global: https://app.tenable.com/api/graph
  US Gov: https://app.tenable.us/api/graph
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
import urllib3
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import requests

SCRIPT_DIR = Path(__file__).resolve().parent
DEFAULT_OUTPUT_FILE = SCRIPT_DIR / "tenable_hec_output.txt"
ENV_FILE = SCRIPT_DIR / ".env"

TENABLE_API_ENDPOINTS = [
    "https://app.tenable.com/api/graph",
    "https://app.tenable.us/api/graph",
]

FINDINGS_RESOURCE_ID_BATCH_SIZE = 100
FINDINGS_PAGE_SIZE = 50
ENTITIES_PAGE_SIZE = 500


@dataclass(frozen=True)
class Config:
    tenable_api_url: str
    tenable_customer_id: str
    tenable_api_token: str
    splunk_hec_url: str
    splunk_hec_token: str
    splunk_hec_verify_ssl: bool
    splunk_index: str
    splunk_source: str
    splunk_sourcetype: str


def load_env_file(path: Path) -> None:
    if not path.is_file():
        return

    for line in path.read_text(encoding="utf-8").splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        key, separator, value = stripped.partition("=")
        if not separator:
            continue
        key = key.strip()
        value = value.strip().strip('"').strip("'")
        if key and key not in os.environ:
            os.environ[key] = value


def env_bool(name: str, default: bool = False) -> bool:
    value = os.environ.get(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def require_env(name: str) -> str:
    value = os.environ.get(name, "").strip()
    if not value:
        print(
            f"Missing required environment variable: {name}\n"
            f"Copy env.txt to .env in {SCRIPT_DIR} and set your values.",
            file=sys.stderr,
        )
        raise SystemExit(1)
    return value


def load_config(require_splunk: bool = False) -> Config:
    load_env_file(ENV_FILE)
    splunk_hec_url = os.environ.get("SPLUNK_HEC_URL", "").strip()
    splunk_hec_token = os.environ.get("SPLUNK_HEC_TOKEN", "").strip()
    if require_splunk:
        if not splunk_hec_url:
            print(
                "Missing required environment variable: SPLUNK_HEC_URL\n"
                f"Copy env.txt to .env in {SCRIPT_DIR} and set your values.",
                file=sys.stderr,
            )
            raise SystemExit(1)
        if not splunk_hec_token:
            print(
                "Missing required environment variable: SPLUNK_HEC_TOKEN\n"
                f"Copy env.txt to .env in {SCRIPT_DIR} and set your values.",
                file=sys.stderr,
            )
            raise SystemExit(1)
    return Config(
        tenable_api_url=os.environ.get(
            "TENABLE_API_URL", "https://app.tenable.com/api/graph"
        ),
        tenable_customer_id=require_env("TENABLE_CUSTOMER_ID"),
        tenable_api_token=require_env("TENABLE_API_TOKEN"),
        splunk_hec_url=splunk_hec_url,
        splunk_hec_token=splunk_hec_token,
        splunk_hec_verify_ssl=env_bool("SPLUNK_HEC_VERIFY_SSL", default=False),
        splunk_index=os.environ.get("SPLUNK_INDEX", "tenable"),
        splunk_source=os.environ.get("SPLUNK_SOURCE", "demo-tenable-correlation"),
        splunk_sourcetype=os.environ.get("SPLUNK_SOURCETYPE", "httpevent"),
    )

ENTITIES_QUERY = """
query EntitiesQuery($after: String) {
  Entities(
    filter: {
      Types: [
        AwsEksCluster
        AzureContainerServiceManagedCluster
        GcpGkeCluster
        OciOkeCluster
        UnmanagedKubernetesCluster
        KubernetesNamespace
        KubernetesDeployment
        KubernetesDaemonSet
        KubernetesStatefulSet
        KubernetesReplicaSet
        KubernetesCronJob
        KubernetesJob
      ]
    }
    first: %d
    after: $after
  ) {
    totalCount
    pageInfo {
      hasNextPage
      endCursor
    }
    nodes {
      Id
      Name
      Provider
      Region
      AccountId
      AccountName
      Type: __typename
    }
  }
}
""" % ENTITIES_PAGE_SIZE

FINDINGS_QUERY = """
query FindingsQuery($after: String, $resourceIds: [Id!]) {
  Findings(
    filter: {
      Statuses: [Open]
      ResourceIds: $resourceIds
    }
    first: %d
    after: $after
  ) {
    totalCount
    pageInfo {
      hasNextPage
      endCursor
    }
    nodes {
      Id
      Description
      Severity
      Status
      SubStatus
      Provider
      AccountId
      AccountName
      OpenTime
      StatusUpdateTime
      Policy {
        Id
        Name
      }
      Resources {
        Id
        Name
      }
    }
  }
}
""" % FINDINGS_PAGE_SIZE


class TenableCloudSecurityClient:
    def __init__(self, api_url: str, api_token: str) -> None:
        self.api_url = api_url
        self.session = requests.Session()
        self.session.headers.update(
            {
                "Authorization": f"Bearer {api_token}",
                "Content-Type": "application/json",
                "Accept": "application/json",
                "User-Agent": "isovalent-tenable-integration/1.0",
            }
        )

    def graphql(self, query: str, variables: dict[str, Any] | None = None) -> dict[str, Any]:
        payload = {"query": query, "variables": variables or {}}
        response = self.session.post(self.api_url, json=payload, timeout=120)
        response.raise_for_status()
        body = response.json()
        if body.get("errors"):
            raise RuntimeError(f"GraphQL error: {json.dumps(body['errors'], indent=2)}")
        if "data" not in body:
            raise RuntimeError(f"Unexpected GraphQL response: {json.dumps(body, indent=2)}")
        return body["data"]

    def fetch_entities(self) -> list[dict[str, Any]]:
        entities: list[dict[str, Any]] = []
        cursor: str | None = None

        while True:
            data = self.graphql(ENTITIES_QUERY, {"after": cursor})
            connection = data["Entities"]
            nodes = connection.get("nodes") or []
            entities.extend(nodes)

            page_info = connection.get("pageInfo") or {}
            if not page_info.get("hasNextPage"):
                break
            cursor = page_info.get("endCursor")
            if not cursor:
                break

        return entities

    def fetch_findings_for_resources(self, resource_ids: list[str]) -> list[dict[str, Any]]:
        findings: list[dict[str, Any]] = []
        cursor: str | None = None

        while True:
            data = self.graphql(
                FINDINGS_QUERY,
                {"after": cursor, "resourceIds": resource_ids},
            )
            connection = data["Findings"]
            nodes = connection.get("nodes") or []
            findings.extend(nodes)

            page_info = connection.get("pageInfo") or {}
            if not page_info.get("hasNextPage"):
                break
            cursor = page_info.get("endCursor")
            if not cursor:
                break

        return findings

    def fetch_all_open_findings(self, resource_ids: list[str]) -> list[dict[str, Any]]:
        if not resource_ids:
            return []

        all_findings: list[dict[str, Any]] = []
        seen_ids: set[str] = set()

        for start in range(0, len(resource_ids), FINDINGS_RESOURCE_ID_BATCH_SIZE):
            batch = resource_ids[start : start + FINDINGS_RESOURCE_ID_BATCH_SIZE]
            batch_findings = self.fetch_findings_for_resources(batch)
            for finding in batch_findings:
                finding_id = finding.get("Id")
                if finding_id and finding_id in seen_ids:
                    continue
                if finding_id:
                    seen_ids.add(finding_id)
                all_findings.append(finding)

        return all_findings


class SplunkHecClient:
    def __init__(self, hec_url: str, hec_token: str, verify_ssl: bool = True) -> None:
        self.hec_url = hec_url
        self.session = requests.Session()
        self.session.headers.update(
            {
                "Authorization": f"Splunk {hec_token}",
                "Content-Type": "application/json",
            }
        )
        self.verify_ssl = verify_ssl
        if not verify_ssl:
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    def send_events(self, events: list[dict[str, Any]]) -> dict[str, Any]:
        if not events:
            return {"text": "No events", "code": 0}

        payload = "\n".join(json.dumps(event, separators=(",", ":")) for event in events)
        response = self.session.post(
            self.hec_url,
            data=payload.encode("utf-8"),
            timeout=120,
            verify=self.verify_ssl,
        )
        response.raise_for_status()
        return response.json()


def chunk(items: list[Any], size: int) -> list[list[Any]]:
    return [items[i : i + size] for i in range(0, len(items), size)]


def entity_to_hec_event(
    entity: dict[str, Any], event_time: int, config: Config
) -> dict[str, Any]:
    return {
        "time": event_time,
        "index": config.splunk_index,
        "sourcetype": config.splunk_sourcetype,
        "source": config.splunk_source,
        "event": {
            "type": "Entity",
            "id": entity.get("Id"),
            "name": entity.get("Name"),
            "entityType": entity.get("Type"),
            "cloudProvider": entity.get("Provider"),
            "accountId": entity.get("AccountId"),
            "accountName": entity.get("AccountName"),
            "region": entity.get("Region"),
            "sentBy": "Tenable",
        },
    }


def finding_to_hec_event(
    finding: dict[str, Any], event_time: int, config: Config
) -> dict[str, Any]:
    policy = finding.get("Policy") or {}
    resources = finding.get("Resources") or []
    resource_ids = [item.get("Id") for item in resources if item.get("Id")]
    resource_names = [item.get("Name") for item in resources if item.get("Name")]
    finding_id = finding.get("Id", "")

    return {
        "time": event_time,
        "index": config.splunk_index,
        "sourcetype": config.splunk_sourcetype,
        "source": config.splunk_source,
        "event": {
            "type": "Finding",
            "id": finding_id,
            "title": policy.get("Name"),
            "policyName": policy.get("Name"),
            "findingType": policy.get("Id"),
            "severity": finding.get("Severity"),
            "status": finding.get("Status"),
            "subStatus": finding.get("SubStatus"),
            "description": finding.get("Description"),
            "accountId": finding.get("AccountId"),
            "accountName": finding.get("AccountName"),
            "cloudProvider": finding.get("Provider"),
            "openTime": finding.get("OpenTime"),
            "statusUpdateTime": finding.get("StatusUpdateTime"),
            "resources{}": resource_ids,
            "resourceNames{}": resource_names,
            "sentBy": "Tenable",
            "link": (
                f"https://app.tenable.com/customer/{config.tenable_customer_id}/Risks/Cloud/Open"
                f"#risk/{finding_id}"
            ),
        },
    }


def send_in_batches(hec: SplunkHecClient, events: list[dict[str, Any]], batch_size: int = 100) -> None:
    for batch_number, batch in enumerate(chunk(events, batch_size), start=1):
        result = hec.send_events(batch)
        print(f"  sent batch {batch_number}: {len(batch)} events -> {result}")


def write_hec_events(events: list[dict[str, Any]], output_path: Path) -> None:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w", encoding="utf-8") as handle:
        for event in events:
            handle.write(json.dumps(event, separators=(",", ":")))
            handle.write("\n")
    print(f"Wrote {len(events)} HEC events to {output_path}")


def probe_endpoints(api_token: str) -> int:
    probe_query = "{ Entities(first: 1) { totalCount nodes { Id Name } } }"
    headers = {
        "Authorization": f"Bearer {api_token}",
        "Content-Type": "application/json",
        "Accept": "application/json",
    }

    print("Probing Tenable Cloud Security GraphQL endpoints...")
    any_success = False
    for endpoint in TENABLE_API_ENDPOINTS:
        try:
            response = requests.post(
                endpoint,
                json={"query": probe_query},
                headers=headers,
                timeout=30,
            )
            if response.status_code == 200 and "data" in response.json():
                print(f"  OK  {endpoint}")
                any_success = True
            else:
                print(f"  FAIL {endpoint} -> {response.status_code} {response.text[:120]}")
        except requests.RequestException as exc:
            print(f"  ERR  {endpoint} -> {exc}")

    if not any_success:
        print(
            "\nNo endpoint accepted the API token. Use https://app.tenable.com/api/graph "
            "for global tenants or https://app.tenable.us/api/graph for US Gov Cloud.",
            file=sys.stderr,
        )
        return 1
    return 0


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--output",
        type=Path,
        default=DEFAULT_OUTPUT_FILE,
        help=f"Output file for HEC events (default: {DEFAULT_OUTPUT_FILE.name})",
    )
    parser.add_argument(
        "--send-to-splunk",
        action="store_true",
        help="Send events to Splunk HEC after writing the output file",
    )
    parser.add_argument(
        "--probe-endpoints",
        action="store_true",
        help="Test the API token against documented GraphQL endpoints and exit",
    )
    parser.add_argument(
        "--probe-regions",
        action="store_true",
        help=argparse.SUPPRESS,
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    config = load_config(require_splunk=args.send_to_splunk)

    if args.probe_endpoints or args.probe_regions:
        return probe_endpoints(config.tenable_api_token)

    print("Fetching Kubernetes entities from Tenable Cloud Security...")
    tcs = TenableCloudSecurityClient(config.tenable_api_url, config.tenable_api_token)

    try:
        entities = tcs.fetch_entities()
    except requests.HTTPError as exc:
        print(f"Failed to fetch entities: {exc}", file=sys.stderr)
        if exc.response is not None:
            print(exc.response.text, file=sys.stderr)
        print(
            "If authentication fails, confirm TENABLE_API_URL is "
            "https://app.tenable.com/api/graph (or app.tenable.us for Gov Cloud).",
            file=sys.stderr,
        )
        return 1
    except RuntimeError as exc:
        print(f"Failed to fetch entities: {exc}", file=sys.stderr)
        return 1

    entity_ids = [entity["Id"] for entity in entities if entity.get("Id")]
    print(f"Fetched {len(entities)} entities ({len(entity_ids)} IDs)")

    print("Fetching open findings for collected entity IDs...")
    try:
        findings = tcs.fetch_all_open_findings(entity_ids)
    except requests.HTTPError as exc:
        print(f"Failed to fetch findings: {exc}", file=sys.stderr)
        if exc.response is not None:
            print(exc.response.text, file=sys.stderr)
        return 1
    except RuntimeError as exc:
        print(f"Failed to fetch findings: {exc}", file=sys.stderr)
        return 1

    print(f"Fetched {len(findings)} unique open findings")

    base_time = int(time.time())
    entity_events = [
        entity_to_hec_event(entity, base_time + index, config)
        for index, entity in enumerate(entities)
    ]
    finding_events = [
        finding_to_hec_event(finding, base_time + len(entities) + index, config)
        for index, finding in enumerate(findings)
    ]
    all_events = entity_events + finding_events

    try:
        write_hec_events(all_events, args.output)
    except OSError as exc:
        print(f"Failed to write output file: {exc}", file=sys.stderr)
        return 1

    if not args.send_to_splunk:
        print("Skipped Splunk HEC upload (pass --send-to-splunk to send).")
        print("Done.")
        return 0

    hec = SplunkHecClient(
        config.splunk_hec_url,
        config.splunk_hec_token,
        verify_ssl=config.splunk_hec_verify_ssl,
    )

    print(f"Sending {len(entity_events)} entity events to Splunk HEC...")
    try:
        send_in_batches(hec, entity_events)
    except requests.HTTPError as exc:
        print(f"Failed to send entity events: {exc}", file=sys.stderr)
        if exc.response is not None:
            print(exc.response.text, file=sys.stderr)
        return 1

    print(f"Sending {len(finding_events)} finding events to Splunk HEC...")
    try:
        send_in_batches(hec, finding_events)
    except requests.HTTPError as exc:
        print(f"Failed to send finding events: {exc}", file=sys.stderr)
        if exc.response is not None:
            print(exc.response.text, file=sys.stderr)
        return 1

    print("Done.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
