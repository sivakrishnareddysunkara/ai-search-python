#!/usr/bin/env python3
# search_cmek_tool_ordered.py
# pip install azure-identity azure-keyvault-keys azure-search-documents requests

import argparse
import time
import json
import requests
from typing import List, Optional
from azure.identity import DefaultAzureCredential
from azure.keyvault.keys import KeyClient
from azure.search.documents.indexes import SearchIndexClient, SearchIndexerClient
from azure.search.documents.indexes.models import (
    SearchIndex,
    SimpleField,
    SearchableField,
    SearchResourceEncryptionKey,
    SearchIndexer
)

# ---------------- DEFAULT CONFIG (edit or override via CLI) ----------------
SEARCH_SERVICE_NAME = "testcmekenable"
ENDPOINT = f"https://{SEARCH_SERVICE_NAME}.search.windows.net"
# storage account resource id (no ResourceId=)
STORAGE_ACCOUNT_RESOURCE_ID = "/subscriptions/50cf0a46-a844-41a9-a708-8a9ac2f0eecc/resourceGroups/rg-aml-test-demo2/providers/Microsoft.Storage/storageAccounts/searchcmektest"
KEY_VAULT_URI = "https://testcmeksearch.vault.azure.net"
KEY_NAME = "searchcmek"
SEARCH_API_VERSION = "2021-04-30-Preview"
# --------------------------------------------------------------------------

cred = DefaultAzureCredential()
index_client = SearchIndexClient(endpoint=ENDPOINT, credential=cred)
indexer_client = SearchIndexerClient(endpoint=ENDPOINT, credential=cred)
key_client = KeyClient(vault_url=KEY_VAULT_URI, credential=cred)

# ---------------- helpers ----------------
def normalize_conn_string(raw: str) -> str:
    """Return connection string acceptable for Search data source (ResourceId=...; or existing cs)."""
    if not raw:
        raise ValueError("Empty storage input")
    s = raw.strip()
    lc = s.lower()
    if lc.startswith("defaultendpointsprotocol=") or lc.startswith("blobendpoint=") or lc.startswith("resourceid=") or "sharedaccess" in lc:
        if not s.endswith(";"):
            s = s + ";"
        return s
    if s.startswith("/subscriptions/"):
        if not s.startswith("/"):
            s = "/" + s
        if not s.endswith("/"):
            s = s + "/"
        return f"ResourceId={s};"
    if not s.endswith("/"):
        s = s + "/"
    return f"ResourceId={s};"

def resolve_key_version(vault_uri: str, key_name: str) -> str:
    k = key_client.get_key(key_name)
    return k.properties.version

def build_sdk_encryption_key(vault_uri: str, key_name: str, key_version: str) -> SearchResourceEncryptionKey:
    return SearchResourceEncryptionKey(vault_uri=vault_uri, key_name=key_name, key_version=key_version)

# ------------ creation functions ------------
def create_index(name: str, encryption_key: Optional[SearchResourceEncryptionKey] = None):
    print(f"[INDEX] ensure '{name}'")
    fields = [
        SimpleField(name="id", type="Edm.String", key=True, filterable=True),
        SearchableField(name="content", type="Edm.String", searchable=True)
    ]
    idx = SearchIndex(name=name, fields=fields, encryption_key=encryption_key)
    try:
        res = index_client.create_index(idx)
        print(f"[INDEX] created: {res.name}")
    except Exception as e:
        print(f"[INDEX] create error or exists: {e}")

def create_datasource(name: str, container: str, conn_string: str, kv_uri: str, key_name: str, key_version: str):
    print(f"[DS] ensure '{name}' (container={container})")
    payload = {
        "name": name,
        "description": "Blob datasource using managed identity and CMEK (automated)",
        "type": "azureblob",
        "credentials": {"connectionString": conn_string},
        "container": {"name": container}
    }
    # try SDK first
    candidates = [
        "create_datasource_connection",
        "create_data_source_connection",
        "create_data_source",
        "create_datasource",
        "create_or_update_datasource_connection",
        "create_or_update_data_source_connection",
        "create_or_update_datasource",
    ]
    for c in candidates:
        m = getattr(indexer_client, c, None)
        if callable(m):
            try:
                print(f"[DS] trying SDK method {c}")
                try:
                    r = m(payload)
                except TypeError:
                    r = m(**payload)
                print(f"[DS] created via SDK method {c}")
                return r
            except Exception as e:
                print(f"[DS] SDK method {c} failed: {e}")

    # REST fallback (must include CMK)
    body = dict(payload)
    body["encryptionKey"] = {
        "keyVaultUri": kv_uri,
        "keyVaultKeyName": key_name,
        "keyVaultKeyVersion": key_version
    }
    token = cred.get_token("https://search.azure.com/.default").token
    url = f"{ENDPOINT}/datasources/{name}?api-version={SEARCH_API_VERSION}"
    headers = {"Content-Type": "application/json", "Authorization": f"Bearer {token}"}
    resp = requests.put(url, headers=headers, data=json.dumps(body))
    if not (200 <= resp.status_code < 300):
        raise RuntimeError(f"[DS][REST] create failed: {resp.status_code} {resp.text}")
    print("[DS] created via REST (with CMK).")
    return resp.json()

def create_indexer(name: str, datasource_name: str, target_index: str, kv_uri: str, key_name: str, key_version: str, encryption_key_model: Optional[SearchResourceEncryptionKey]):
    print(f"[IXR] ensure '{name}' linking ds='{datasource_name}' -> ix='{target_index}'")
    idxr_model = SearchIndexer(
        name=name,
        data_source_name=datasource_name,
        target_index_name=target_index,
        encryption_key=encryption_key_model
    )
    # try SDK
    create_candidates = ["create_indexer", "create_or_update_indexer", "createIndexer"]
    for c in create_candidates:
        m = getattr(indexer_client, c, None)
        if callable(m):
            try:
                print(f"[IXR] trying SDK method {c}")
                r = m(idxr_model)
                print(f"[IXR] created via SDK method {c}")
                return r
            except Exception as e:
                print(f"[IXR] SDK method {c} failed: {e}")

    # REST fallback (include CMK, use keyVault* naming)
    token = cred.get_token("https://search.azure.com/.default").token
    url = f"{ENDPOINT}/indexers/{name}?api-version={SEARCH_API_VERSION}"
    headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
    body = {
        "name": name,
        "dataSourceName": datasource_name,
        "targetIndexName": target_index,
        "encryptionKey": {
            "keyVaultUri": kv_uri,
            "keyVaultKeyName": key_name,
            "keyVaultKeyVersion": key_version
        }
    }
    resp = requests.put(url, headers=headers, data=json.dumps(body))
    if not (200 <= resp.status_code < 300):
        raise RuntimeError(f"[IXR][REST] create failed: {resp.status_code} {resp.text}")
    print("[IXR] created via REST.")
    return resp.json()

def run_indexer(name: str, timeout_sec: int = 300):
    print(f"[IXR] run {name}")
    # try SDK run
    for r in ["run_indexer", "run_indexer_now", "run"]:
        m = getattr(indexer_client, r, None)
        if callable(m):
            try:
                m(name)
                print("[IXR] invoked run via SDK")
                break
            except Exception as e:
                print(f"[IXR] SDK run {r} failed: {e}")
    else:
        token = cred.get_token("https://search.azure.com/.default").token
        url = f"{ENDPOINT}/indexers/{name}/run?api-version={SEARCH_API_VERSION}"
        resp = requests.post(url, headers={"Authorization": f"Bearer {token}"})
        if not (200 <= resp.status_code < 300):
            raise RuntimeError(f"[IXR][REST] run failed: {resp.status_code} {resp.text}")
        print("[IXR] run invoked via REST")

    # poll status
    start = time.time()
    while time.time() - start < timeout_sec:
        status = None
        for get_name in ["get_indexer_status", "get_indexer_status_with_http_info", "get_status"]:
            gm = getattr(indexer_client, get_name, None)
            if callable(gm):
                try:
                    status = gm(name)
                    break
                except Exception:
                    status = None
        if not status:
            token = cred.get_token("https://search.azure.com/.default").token
            url = f"{ENDPOINT}/indexers/{name}/status?api-version={SEARCH_API_VERSION}"
            r = requests.get(url, headers={"Authorization": f"Bearer {token}"})
            if 200 <= r.status_code < 300:
                status = r.json()
        if status:
            if hasattr(status, "last_result") and status.last_result:
                lr = status.last_result
                print("[IXR] status:", getattr(lr, "status", None),
                      "| processed:", getattr(lr, "items_processed", None),
                      "| failed:", getattr(lr, "items_failed", None))
                return status
            if isinstance(status, dict):
                last = status.get("lastResult") or status.get("last_result")
                if last:
                    print("[IXR][REST] status:", last.get("status"), "processed:", last.get("itemsProcessed"), "failed:", last.get("itemsFailed"))
                    return status
        time.sleep(5)
    print("[IXR] polling timed out")
    return None

# ---------------- CLI handling ----------------
def parse_list_arg(s: Optional[str]) -> List[str]:
    if not s:
        return []
    parts = []
    for segment in s.split(","):
        seg = segment.strip()
        if seg:
            parts.append(seg)
    return parts

def align_or_expand(a: List[str], b: List[str], c: List[str]):
    # If only one of them provided, replicate that value to match others
    maxlen = max(len(a), len(b), len(c))
    def expand(lst):
        if len(lst) == 0:
            return [None] * maxlen
        if len(lst) == 1 and maxlen > 1:
            return lst * maxlen
        if len(lst) < maxlen:
            raise ValueError("When providing multiple resource types, provide equal number of names or a single name to repeat.")
        return lst
    return expand(a), expand(b), expand(c)

def main():
    parser = argparse.ArgumentParser(prog="search_cmek_tool_ordered", description="Create indexes/datasources/indexers with CMEK + MI support (ordered creation).")
    parser.add_argument("--op", choices=["index", "datasource", "indexer", "all"], required=True, help="Operation to perform")
    parser.add_argument("--names", help="Comma-separated list of index names")
    parser.add_argument("--datasource-names", help="Comma-separated list of datasource names")
    parser.add_argument("--indexer-names", help="Comma-separated list of indexer names")
    parser.add_argument("--container", help="Blob container name for datasources (required for datasource creation)")
    parser.add_argument("--storage-resource-id", default=STORAGE_ACCOUNT_RESOURCE_ID, help="Storage account resource id (no ResourceId= prefix), or full connection string")
    parser.add_argument("--kv-uri", default=KEY_VAULT_URI, help="Key Vault URI")
    parser.add_argument("--kv-key", default=KEY_NAME, help="Key name in Key Vault")
    parser.add_argument("--api-version", default=SEARCH_API_VERSION, help="Search Data Plane API version for REST fallback")
    parser.add_argument("--run-indexer", action="store_true", help="Run indexer after creating it (only for indexer/all ops)")
    parser.add_argument("--poll-timeout", type=int, default=300, help="Indexer run poll timeout (seconds)")
    args = parser.parse_args()

    op = args.op
    index_names = parse_list_arg(args.names)
    ds_names = parse_list_arg(args.datasource_names)
    ixr_names = parse_list_arg(args.indexer_names)
    container = args.container
    conn_input = args.storage_resource_id
    kv_uri = args.kv_uri
    kv_key = args.kv_key
    api_ver = args.api_version

    # normalize connection string
    conn_string = normalize_conn_string(conn_input)

    # resolve key version
    try:
        key_version = resolve_key_version(kv_uri, kv_key)
        print("Resolved key version:", key_version)
    except Exception as e:
        print("Failed to resolve key version:", e)
        return

    # build SDK encryption model (may be None if model construction fails)
    encryption_model = None
    try:
        encryption_model = build_sdk_encryption_key(kv_uri, kv_key, key_version)
    except Exception:
        encryption_model = None

    # ---------- operations ----------
    if op == "index":
        if not index_names:
            print("No index names provided.")
            return
        for name in index_names:
            create_index(name, encryption_model)
        return

    if op == "datasource":
        if not ds_names:
            print("No datasource names provided.")
            return
        if not container:
            print("Container name is required for datasource creation.")
            return
        for ds in ds_names:
            create_datasource(ds, container, conn_string, kv_uri, kv_key, key_version)
        return

    if op == "indexer":
        if not ixr_names:
            print("No indexer names provided.")
            return
        if not ds_names:
            print("No datasource names provided.")
            return
        if not index_names:
            print("No index names provided.")
            return
        # align lists and create indexers linking nth index <-> nth datasource
        idx_list, ds_list, ixr_list = align_or_expand(index_names, ds_names, ixr_names)
        for idx_name, ds_name, ixr_name in zip(idx_list, ds_list, ixr_list):
            create_indexer(ixr_name, ds_name, idx_name, kv_uri, kv_key, key_version, encryption_model)
            if args.run_indexer:
                run_indexer(ixr_name, timeout_sec=args.poll_timeout)
        return

    if op == "all":
        # Validate at least minimal names present
        if not (index_names or ds_names or ixr_names):
            print("No resource names provided. Use --names or --datasource-names/--indexer-names.")
            return
        if not container:
            print("Container name is required for creating datasources in 'all' mode.")
            return

        # If missing, auto-generate lists
        if index_names and not ds_names:
            ds_names = [f"{n}-ds" for n in index_names]
        if index_names and not ixr_names:
            ixr_names = [f"{n}-ixr" for n in index_names]
        if ds_names and not index_names:
            index_names = [f"{n}-idx" for n in ds_names]
        if ds_names and not ixr_names:
            ixr_names = [f"{n}-ixr" for n in ds_names]

        # align lists (allow single-name replication or equal-length lists)
        index_names, ds_names, ixr_names = align_or_expand(index_names, ds_names, ixr_names)

        # PHASE 1: create all indexes
        print("PHASE 1/3: Creating all indexes...")
        for name in index_names:
            create_index(name, encryption_model)

        # PHASE 2: create all datasources
        print("PHASE 2/3: Creating all datasources...")
        for ds in ds_names:
            create_datasource(ds, container, conn_string, kv_uri, kv_key, key_version)

        # PHASE 3: create indexers linking nth index <-> nth datasource
        print("PHASE 3/3: Creating all indexers (linking by position)...")
        for idx_name, ds_name, ixr_name in zip(index_names, ds_names, ixr_names):
            create_indexer(ixr_name, ds_name, idx_name, kv_uri, kv_key, key_version, encryption_model)
            if args.run_indexer:
                run_indexer(ixr_name, timeout_sec=args.poll_timeout)
        return

if __name__ == "__main__":
    main()
