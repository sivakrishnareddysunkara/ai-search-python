# create_indexer_with_cmek_mi_sanitized.py
# pip install azure-identity azure-keyvault-keys azure-search-documents requests

import time
import json
import requests
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

# ------------------ CONFIG - EDIT THESE ------------------
SEARCH_SERVICE_NAME = "testcmekenable"
ENDPOINT = f"https://{SEARCH_SERVICE_NAME}.search.windows.net"

INDEX_NAME = "my-secure-index-final2"
DATASOURCE_NAME = "my-blob-datasource"
INDEXER_NAME = "my-indexer2"
CONTAINER_NAME = "test"

# Provide the storage account resource id (without ResourceId= prefix).
# Example: "/subscriptions/50cf0a46-a844-41a9-a708-8a9ac2f0eecc/resourceGroups/myrg/providers/Microsoft.Storage/storageAccounts/searchcmektest/"
# The script will normalize to "ResourceId=...;"
STORAGE_ACCOUNT_RESOURCE_ID = "/subscriptions/50cf0a46-a844-41a9-a708-8a9ac2f0eecc/resourceGroups/rg-aml-test-demo2/providers/Microsoft.Storage/storageAccounts/searchcmektest"

# Key Vault + key info
KEY_VAULT_URI = "https://testcmeksearch.vault.azure.net"
KEY_NAME = "searchcmek"

# REST API version for Search data-plane fallback
SEARCH_API_VERSION = "2021-04-30-Preview"
# -------------------------------------------------------

# clients & credential
cred = DefaultAzureCredential()
index_client = SearchIndexClient(endpoint=ENDPOINT, credential=cred)
indexer_client = SearchIndexerClient(endpoint=ENDPOINT, credential=cred)
key_client = KeyClient(vault_url=KEY_VAULT_URI, credential=cred)

# ---------------- helpers ----------------
def sanitize_connection_string_for_mi(raw):
    """Return connection string in one of accepted formats. If raw looks like a resource id, return 'ResourceId=<raw>;'"""
    if not raw:
        raise ValueError("Storage resource id is empty.")
    s = raw.strip()
    # If user passed a full connection string already (AccountKey/SAS/BlobEndpoint), return as-is
    lc = s.lower()
    if lc.startswith("defaultendpointsprotocol=") or lc.startswith("blobendpoint=") or lc.startswith("resourceid=") or "sharedaccesstoken" in lc or "sharedacces" in lc:
        # ensure trailing semicolon
        if not s.endswith(";"):
            s = s + ";"
        return s
    # if it looks like a resource id (starts with /subscriptions/)
    if s.startswith("/subscriptions/") or s.startswith("subscriptions/"):
        # normalize: ensure leading slash and trailing "/;"
        if not s.startswith("/"):
            s = "/" + s
        if not s.endswith("/"):
            s = s + "/"
        # Build ResourceId=...;
        conn = f"ResourceId={s};"
        return conn
    # otherwise just prefix ResourceId=
    if not s.endswith("/"):
        s = s + "/"
    return f"ResourceId={s};"

def get_latest_key_version(key_vault_uri, key_name):
    k = key_client.get_key(key_name)
    return k.properties.version

def build_encryption_key_model(kv_uri, key_name, key_version):
    # SDK model
    return SearchResourceEncryptionKey(vault_uri=kv_uri, key_name=key_name, key_version=key_version)

def try_sdk_create_datasource(payload):
    candidates = [
        "create_datasource_connection",
        "create_data_source_connection",
        "create_data_source",
        "create_datasource",
        "create_or_update_datasource_connection",
        "create_or_update_data_source_connection",
        "create_or_update_datasource",
    ]
    for name in candidates:
        method = getattr(indexer_client, name, None)
        if callable(method):
            try:
                try:
                    res = method(payload)
                except TypeError:
                    res = method(**payload)
                print(f"Datasource created via SDK method '{name}'.")
                return res
            except Exception as e:
                print(f"SDK method '{name}' attempted but failed: {e}")
    raise RuntimeError("No SDK method succeeded for creating datasource.")

def rest_create_datasource_with_cmek_compatible(payload, kv_uri, key_name, key_version):
    """
    Create datasource via REST and include encryptionKey using the 'keyVault*' property names expected by data-plane.
    """
    body = dict(payload)
    # Use keyVaultUri/keyVaultKeyName/keyVaultKeyVersion property names for this API version.
    body["encryptionKey"] = {
        "keyVaultUri": kv_uri,
        "keyVaultKeyName": key_name,
        "keyVaultKeyVersion": key_version
    }
    token = cred.get_token("https://search.azure.com/.default").token
    url = f"{ENDPOINT}/datasources/{body['name']}?api-version={SEARCH_API_VERSION}"
    headers = {"Content-Type": "application/json", "Authorization": f"Bearer {token}"}
    resp = requests.put(url, headers=headers, data=json.dumps(body))
    if not (200 <= resp.status_code < 300):
        raise RuntimeError(f"REST datasource create failed: {resp.status_code} {resp.text}")
    print("Datasource created via REST (with CMK).")
    return resp.json()

def ensure_datasource_exists(payload, kv_uri, key_name, key_version):
    # Check via SDK get variants
    get_candidates = [
        "get_datasource_connection",
        "get_data_source_connection",
        "get_data_source",
        "get_datasource",
        "get_data_source_connection"
    ]
    for g in get_candidates:
        gm = getattr(indexer_client, g, None)
        if callable(gm):
            try:
                gm(payload["name"])
                print("Datasource already exists (found via SDK).")
                return
            except Exception:
                pass

    # Try SDK create, else REST with encryptionKey
    try:
        created = try_sdk_create_datasource(payload)
        return created
    except Exception as sdk_ex:
        print("SDK create failed or unsupported, attempting REST fallback. Error:", sdk_ex)
        return rest_create_datasource_with_cmek_compatible(payload, kv_uri, key_name, key_version)

def create_index_with_cmek(encryption_key):
    fields = [
        SimpleField(name="id", type="Edm.String", key=True, filterable=True),
        SearchableField(name="content", type="Edm.String", searchable=True)
    ]
    idx = SearchIndex(name=INDEX_NAME, fields=fields, encryption_key=encryption_key)
    try:
        created = index_client.create_index(idx)
        print("Index created:", created.name)
        return created
    except Exception as e:
        print("Index create failed or already exists:", e)

def create_indexer_with_cmek(encryption_key_model):
    idxr = SearchIndexer(
        name=INDEXER_NAME,
        data_source_name=DATASOURCE_NAME,
        target_index_name=INDEX_NAME,
        encryption_key=encryption_key_model
    )
    create_candidates = ["create_indexer", "create_or_update_indexer", "createIndexer"]
    for c in create_candidates:
        cm = getattr(indexer_client, c, None)
        if callable(cm):
            try:
                res = cm(idxr)
                print("Indexer created via SDK method:", c)
                return res
            except Exception as e:
                print(f"Indexer create via {c} failed: {e}")

    # REST fallback for indexer (use same keyVault* naming)
    token = cred.get_token("https://search.azure.com/.default").token
    url = f"{ENDPOINT}/indexers/{INDEXER_NAME}?api-version={SEARCH_API_VERSION}"
    headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
    body = {
        "name": INDEXER_NAME,
        "dataSourceName": DATASOURCE_NAME,
        "targetIndexName": INDEX_NAME,
        "encryptionKey": {
            "keyVaultUri": encryption_key_model.vault_uri if hasattr(encryption_key_model, "vault_uri") else KEY_VAULT_URI,
            "keyVaultKeyName": encryption_key_model.key_name if hasattr(encryption_key_model, "key_name") else KEY_NAME,
            "keyVaultKeyVersion": encryption_key_model.key_version if hasattr(encryption_key_model, "key_version") else key_version
        }
    }
    resp = requests.put(url, headers=headers, data=json.dumps(body))
    if not (200 <= resp.status_code < 300):
        raise RuntimeError(f"REST indexer create failed: {resp.status_code} {resp.text}")
    print("Indexer created via REST.")
    return resp.json()

def run_indexer_and_wait(timeout_sec=300, poll_interval=5):
    # run via SDK if possible
    run_candidates = ["run_indexer", "run_indexer_now", "run"]
    run_method = None
    for r in run_candidates:
        rm = getattr(indexer_client, r, None)
        if callable(rm):
            run_method = rm
            break
    if run_method:
        try:
            run_method(INDEXER_NAME)
            print("Indexer run invoked via SDK.")
        except Exception as e:
            print("SDK run_indexer failed; fallback to REST:", e)
            run_method = None

    if not run_method:
        token = cred.get_token("https://search.azure.com/.default").token
        url = f"{ENDPOINT}/indexers/{INDEXER_NAME}/run?api-version={SEARCH_API_VERSION}"
        headers = {"Authorization": f"Bearer {token}"}
        resp = requests.post(url, headers=headers)
        if not (200 <= resp.status_code < 300):
            raise RuntimeError(f"REST indexer run failed: {resp.status_code} {resp.text}")
        print("Indexer run invoked via REST.")

    # poll status
    start = time.time()
    while True:
        status = None
        for name in ["get_indexer_status", "get_indexer_status_with_http_info", "get_status"]:
            m = getattr(indexer_client, name, None)
            if callable(m):
                try:
                    status = m(INDEXER_NAME)
                    break
                except Exception:
                    status = None
        if not status:
            token = cred.get_token("https://search.azure.com/.default").token
            url = f"{ENDPOINT}/indexers/{INDEXER_NAME}/status?api-version={SEARCH_API_VERSION}"
            headers = {"Authorization": f"Bearer {token}"}
            r = requests.get(url, headers=headers)
            if 200 <= r.status_code < 300:
                status = r.json()

        if status:
            try:
                if hasattr(status, "last_result") and status.last_result:
                    lr = status.last_result
                    print("Status:", getattr(lr, "status", None),
                          "| Processed:", getattr(lr, "items_processed", None),
                          "| Failed:", getattr(lr, "items_failed", None))
                    return status
                if isinstance(status, dict):
                    last = status.get("lastResult") or status.get("last_result")
                    if last:
                        print("Status (REST):", last.get("status"), "Processed:", last.get("itemsProcessed"), "Failed:", last.get("itemsFailed"))
                        return status
            except Exception:
                pass

        if time.time() - start > timeout_sec:
            print("Timed out waiting for indexer status.")
            return None
        time.sleep(poll_interval)

# ---------------- main ----------------
if __name__ == "__main__":
    # normalize storage connection
    conn_string = sanitize_connection_string_for_mi(STORAGE_ACCOUNT_RESOURCE_ID)

    # resolve key version
    try:
        key_version = get_latest_key_version(KEY_VAULT_URI, KEY_NAME)
        print("Resolved key version:", key_version)
    except Exception as e:
        print("Failed to resolve key version:", e)
        raise

    # build encryption model for SDK path
    encryption_key_model = None
    try:
        encryption_key_model = build_encryption_key_model(KEY_VAULT_URI, KEY_NAME, key_version)
    except Exception as e:
        print("Warning: failed to build SDK encryption model:", e)

    # create index (with CMK)
    create_index_with_cmek(encryption_key_model)

    # build datasource payload (REST-shaped). credentials.connectionString must be valid:
    ds_payload = {
        "name": DATASOURCE_NAME,
        "description": "Blob datasource using managed identity and CMEK",
        "type": "azureblob",
        "credentials": {"connectionString": conn_string},
        "container": {"name": CONTAINER_NAME}
    }

    # ensure datasource (SDK first, REST fallback with CMK)
    try:
        ensure_datasource_exists(ds_payload, KEY_VAULT_URI, KEY_NAME, key_version)
    except Exception as e:
        print("Failed to ensure datasource:", e)
        raise

    # create indexer (with CMK)
    try:
        create_indexer_with_cmek(encryption_key_model)
    except Exception as e:
        print("Failed creating indexer:", e)
        raise

    # run indexer and wait
    try:
        run_indexer_and_wait()
    except Exception as e:
        print("Indexer run/check failed:", e)
        raise

    print("Done.")
