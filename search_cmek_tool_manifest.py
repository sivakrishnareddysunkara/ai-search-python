# Sivakrisnhna Reddy Sunkara 
# Created on : 2025-11-27
# created by : sivakrishnareddy sunkara
# Modified on: 

 # Please install the required packages before running the script (listed below)
#!/usr/bin/env python3
# pip install azure-identity azure-keyvault-keys azure-search-documents pyyaml requests

import argparse, time, json, requests, os
from typing import List, Optional, Dict, Any
import yaml
from azure.identity import DefaultAzureCredential
from azure.keyvault.keys import KeyClient
from azure.search.documents.indexes import SearchIndexClient, SearchIndexerClient
from azure.search.documents.indexes.models import (
    SearchIndex, SimpleField, SearchableField,
    SearchResourceEncryptionKey, SearchIndexer
)

# ----------------- Defaults (can be omitted if manifest provides them) -----------------
SEARCH_SERVICE_NAME = "testcmekenable"
ENDPOINT = f"https://{SEARCH_SERVICE_NAME}.search.windows.net"
SEARCH_API_VERSION = "2021-04-30-Preview"     # please update to the required api version ..here i have used the stable version as of today 

cred = DefaultAzureCredential()
index_client = SearchIndexClient(endpoint=ENDPOINT, credential=cred)
indexer_client = SearchIndexerClient(endpoint=ENDPOINT, credential=cred)
# key_client will be created later once key vault uri known

# ---------------- utilities ----------------
def load_manifest(path: str) -> Dict[str, Any]:
    with open(path, "r", encoding="utf-8") as f:
        text = f.read()
    if path.lower().endswith(".yaml") or path.lower().endswith(".yml"):
        return yaml.safe_load(text)
    else:
        return json.loads(text)

def normalize_conn_string(raw: str) -> str:
    if not raw:
        raise ValueError("Empty storage connection input")
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

def resolve_key_version(kv_uri: str, key_name: str) -> str:
    kc = KeyClient(vault_url=kv_uri, credential=cred)
    k = kc.get_key(key_name)
    return k.properties.version

def build_sdk_encryption_key(kv_uri: str, key_name: str, key_version: str) -> SearchResourceEncryptionKey:
    return SearchResourceEncryptionKey(vault_uri=kv_uri, key_name=key_name, key_version=key_version)

# ---------------- creation/deletion primitives ----------------
def create_index(name: str, encryption_key: Optional[SearchResourceEncryptionKey]):
    print(f"[INDEX] ensuring {name}")
    fields = [
        SimpleField(name="id", type="Edm.String", key=True, filterable=True),
        SearchableField(name="content", type="Edm.String", searchable=True),
    ]
    idx = SearchIndex(name=name, fields=fields, encryption_key=encryption_key)
    try:
        index_client.create_index(idx)
        print(f"[INDEX] created: {name}")
    except Exception as e:
        print(f"[INDEX] create error (may already exist): {e}")

def delete_index(name: str):
    print(f"[INDEX] deleting {name}")
    # try SDK delete_index
    try:
        m = getattr(index_client, "delete_index", None)
        if callable(m):
            m(name)
            print(f"[INDEX] deleted via SDK: {name}")
            return
    except Exception as e:
        print(f"[INDEX] SDK delete_index failed: {e}")
    # REST fallback
    token = cred.get_token("https://search.azure.com/.default").token
    url = f"{ENDPOINT}/indexes/{name}?api-version={SEARCH_API_VERSION}"
    r = requests.delete(url, headers={"Authorization": f"Bearer {token}"})
    if r.status_code in (200,204,404):
        print(f"[INDEX] deleted or not found (REST): {name}")
    else:
        print(f"[INDEX] REST delete error: {r.status_code} {r.text}")
        r.raise_for_status()

def create_datasource(ds: Dict[str, Any], conn_string: str, kv_uri: str, key_name: str, key_version: str):
    name = ds["name"]
    container = ds.get("container")
    if not container:
        raise ValueError(f"Datasource {name} requires 'container' (or manifest.storage.container).")
    payload = {
        "name": name,
        "description": ds.get("description", "datasource created via manifest"),
        "type": "azureblob",
        "credentials": {"connectionString": conn_string},
        "container": {"name": container}
    }
    # SDK attempts to check if there is a suitable create method
    sdk_candidates = [
        "create_datasource_connection",
        "create_data_source_connection",
        "create_data_source",
        "create_datasource",
        "create_or_update_datasource_connection",
        "create_or_update_data_source_connection",
        "create_or_update_datasource",
    ]
    for c in sdk_candidates:
        fn = getattr(indexer_client, c, None)
        if callable(fn):
            try:
                try:
                    fn(payload)
                except TypeError:
                    fn(**payload)
                print(f"[DS] created via SDK method {c}: {name}")
                return
            except Exception as e:
                print(f"[DS] SDK method {c} failed: {e}")
    # REST fallback with CMK
    body = dict(payload)
    body["encryptionKey"] = {
        "keyVaultUri": kv_uri,
        "keyVaultKeyName": key_name,
        "keyVaultKeyVersion": key_version
    }
    token = cred.get_token("https://search.azure.com/.default").token
    url = f"{ENDPOINT}/datasources/{name}?api-version={SEARCH_API_VERSION}"
    r = requests.put(url, headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"}, data=json.dumps(body))
    if not (200 <= r.status_code < 300):
        raise RuntimeError(f"[DS] REST create failed: {r.status_code} {r.text}")
    print(f"[DS] created via REST: {name}")

def delete_datasource(name: str):
    print(f"[DS] deleting {name}")
    # SDK candidate deletes
    sdk_candidates = ["delete_datasource_connection", "delete_data_source_connection", "delete_data_source", "delete_datasource"]
    for c in sdk_candidates:
        fn = getattr(indexer_client, c, None)
        if callable(fn):
            try:
                fn(name)
                print(f"[DS] deleted via SDK {c}: {name}")
                return
            except Exception as e:
                print(f"[DS] SDK delete {c} failed: {e}")
    # REST fallback
    token = cred.get_token("https://search.azure.com/.default").token
    url = f"{ENDPOINT}/datasources/{name}?api-version={SEARCH_API_VERSION}"
    r = requests.delete(url, headers={"Authorization": f"Bearer {token}"})
    if r.status_code in (200,204,404):
        print(f"[DS] deleted or not found (REST): {name}")
    else:
        print(f"[DS] REST delete error: {r.status_code} {r.text}")
        r.raise_for_status()

def create_indexer(ixr: Dict[str, Any], kv_uri: str, key_name: str, key_version: str, encryption_model: Optional[SearchResourceEncryptionKey]):
    name = ixr["name"]
    ds_name = ixr.get("dataSourceName")
    tgt = ixr.get("targetIndexName")
    if not ds_name or not tgt:
        raise ValueError(f"Indexer {name} must include dataSourceName and targetIndexName")
    print(f"[IXR] creating {name} linking {ds_name} -> {tgt}")
    model = SearchIndexer(name=name, data_source_name=ds_name, target_index_name=tgt, encryption_key=encryption_model)
    # SDK attempt
    for c in ["create_indexer", "create_or_update_indexer", "createIndexer"]:
        fn = getattr(indexer_client, c, None)
        if callable(fn):
            try:
                fn(model)
                print(f"[IXR] created via SDK {c}: {name}")
                return
            except Exception as e:
                print(f"[IXR] SDK {c} failed: {e}")
    # REST fallback (include CMK with keyVault* naming)
    token = cred.get_token("https://search.azure.com/.default").token
    url = f"{ENDPOINT}/indexers/{name}?api-version={SEARCH_API_VERSION}"
    body = {"name": name, "dataSourceName": ds_name, "targetIndexName": tgt,
            "encryptionKey": {"keyVaultUri": kv_uri, "keyVaultKeyName": key_name, "keyVaultKeyVersion": key_version}}
    r = requests.put(url, headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"}, data=json.dumps(body))
    if not (200 <= r.status_code < 300):
        raise RuntimeError(f"[IXR] REST create failed: {r.status_code} {r.text}")
    print(f"[IXR] created via REST: {name}")

def delete_indexer(name: str):
    print(f"[IXR] deleting {name}")
    # SDK delete variants
    for c in ["delete_indexer", "delete"]:
        fn = getattr(indexer_client, c, None)
        if callable(fn):
            try:
                fn(name)
                print(f"[IXR] deleted via SDK {c}: {name}")
                return
            except Exception as e:
                print(f"[IXR] SDK delete {c} failed: {e}")
    # REST fallback
    token = cred.get_token("https://search.azure.com/.default").token
    url = f"{ENDPOINT}/indexers/{name}?api-version={SEARCH_API_VERSION}"
    r = requests.delete(url, headers={"Authorization": f"Bearer {token}"})
    if r.status_code in (200,204,404):
        print(f"[IXR] deleted or not found (REST): {name}")
    else:
        print(f"[IXR] REST delete error: {r.status_code} {r.text}")
        r.raise_for_status()

def run_indexer_and_poll(name: str, timeout_sec: int = 300):
    print(f"[IXR] run {name}")
    # attempt run via SDK
    run_attempted = False
    for rname in ["run_indexer", "run_indexer_now", "run"]:
        fn = getattr(indexer_client, rname, None)
        if callable(fn):
            try:
                fn(name)
                run_attempted = True
                print("[IXR] run invoked via SDK")
                break
            except Exception as e:
                print(f"[IXR] SDK run {rname} failed: {e}")
    if not run_attempted:
        token = cred.get_token("https://search.azure.com/.default").token
        url = f"{ENDPOINT}/indexers/{name}/run?api-version={SEARCH_API_VERSION}"
        r = requests.post(url, headers={"Authorization": f"Bearer {token}"})
        if not (200 <= r.status_code < 300):
            raise RuntimeError(f"[IXR] REST run failed: {r.status_code} {r.text}")
        print("[IXR] run invoked via REST")

    # poll
    start = time.time()
    while time.time() - start < 300:
        status = None
        for getname in ["get_indexer_status", "get_indexer_status_with_http_info", "get_status"]:
            fn = getattr(indexer_client, getname, None)
            if callable(fn):
                try:
                    status = fn(name)
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
                print("[IXR] status:", getattr(lr, "status", None), "| processed:", getattr(lr, "items_processed", None), "| failed:", getattr(lr, "items_failed", None))
                return status
            if isinstance(status, dict):
                last = status.get("lastResult") or status.get("last_result")
                if last:
                    print("[IXR][REST] status:", last.get("status"), "processed:", last.get("itemsProcessed"), "failed:", last.get("itemsFailed"))
                    return status
        time.sleep(5)
    print("[IXR] poll timed out")
    return None

# ---------------- main manifest-driven flow ----------------
def validate_manifest(m: Dict[str, Any]) -> None:
    if not isinstance(m, dict):
        raise ValueError("Manifest must be a mapping/object at top level.")
    # storage: required for datasources unless each datasource provides connectionString
    if "storage" not in m:
        raise ValueError("Manifest must include 'storage' with resourceId and/or container.")
    if "resourceId" not in m["storage"] and "connectionString" not in m["storage"]:
        raise ValueError("Manifest.storage must include resourceId or connectionString.")
    # keyVault: required
    if "keyVault" not in m or "uri" not in m["keyVault"] or "keyName" not in m["keyVault"]:
        raise ValueError("Manifest.keyVault must include 'uri' and 'keyName'.")

def main():
    parser = argparse.ArgumentParser(prog="search_cmek_tool_manifest", description="Create/delete indexes/datasources/indexers using manifest (YAML/JSON).")
    parser.add_argument("--manifest", required=True, help="Path to YAML or JSON manifest")
    parser.add_argument("--op", choices=["create", "delete"], default="create", help="Operation")
    parser.add_argument("--run-indexers", action="store_true", help="Run indexers after creating them")
    parser.add_argument("--poll-timeout", type=int, default=300, help="Indexer run poll timeout (seconds)")
    args = parser.parse_args()

    manifest = load_manifest(args.manifest)
    validate_manifest(manifest)

    storage = manifest["storage"]
    storage_conn_input = storage.get("connectionString") or storage.get("resourceId")
    storage_conn = normalize_conn_string(storage_conn_input)
    storage_container_default = storage.get("container")

    kv = manifest["keyVault"]
    kv_uri = kv["uri"]
    kv_key = kv["keyName"]

    # resolve key version
    try:
        key_version = resolve_key_version(kv_uri, kv_key)
        print("Resolved key version:", key_version)
    except Exception as e:
        raise RuntimeError(f"Failed to resolve key version: {e}")

    # build SDK encryption model if possible
    try:
        enc_model = build_sdk_encryption_key(kv_uri, kv_key, key_version)
    except Exception:
        enc_model = None

    indexes = manifest.get("indexes", [])
    datasources = manifest.get("datasources", [])
    indexers = manifest.get("indexers", [])

    if args.op == "create":
        # PHASE 1: create all indexes
        if indexes:
            print("PHASE 1: Creating indexes...")
            for idx in indexes:
                name = idx["name"]
                create_index(name, enc_model)

        # PHASE 2: create all datasources
        if datasources:
            print("PHASE 2: Creating datasources...")
            for ds in datasources:
                # ds may provide its own connectionString or container
                conn = ds.get("connectionString") or storage_conn
                container = ds.get("container") or storage_container_default
                if not container:
                    raise ValueError(f"Datasource {ds.get('name')} lacks container and no storage.container default provided.")
                create_datasource(ds, conn, kv_uri, kv_key, key_version)

        # PHASE 3: create indexers (linking by explicit names in manifest)
        if indexers:
            print("PHASE 3: Creating indexers...")
            for ix in indexers:
                create_indexer(ix, kv_uri, kv_key, key_version, enc_model)
                if args.run_indexers:
                    run_indexer_and_poll(ix["name"], timeout_sec=args.poll_timeout)

    else:  # delete flow: indexers -> datasources -> indexes
        # delete indexers first
        if indexers:
            print("DELETE PHASE 1: Deleting indexers...")
            for ix in indexers:
                delete_indexer(ix["name"])
        # delete datasources
        if datasources:
            print("DELETE PHASE 2: Deleting datasources...")
            for ds in datasources:
                delete_datasource(ds["name"])
        # delete indexes
        if indexes:
            print("DELETE PHASE 3: Deleting indexes...")
            for idx in indexes:
                delete_index(idx["name"])

    print("Manifest operation complete.")

if __name__ == "__main__":
    main()
