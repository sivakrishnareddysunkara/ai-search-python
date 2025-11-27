# app.py
# streamlit run app.py
import streamlit as st
import time
import json
import requests
import yaml
from typing import List, Optional, Dict, Any
from azure.identity import DefaultAzureCredential
from azure.keyvault.keys import KeyClient
from azure.search.documents.indexes import SearchIndexClient, SearchIndexerClient
from azure.search.documents.indexes.models import (
    SearchIndex, SimpleField, SearchableField,
    SearchResourceEncryptionKey, SearchIndexer
)

st.set_page_config(page_title="CMEK Search Manager", layout="wide")

# ---------------- Sidebar: config ----------------
st.sidebar.header("Azure / Service Configuration")

SEARCH_SERVICE_NAME = st.sidebar.text_input("Search service name", value="testcmekenable")
ENDPOINT = f"https://{SEARCH_SERVICE_NAME}.search.windows.net"
STORAGE_ACCOUNT_RESOURCE_ID = st.sidebar.text_input("Storage account resource id (or full connection string)", value="")
DEFAULT_CONTAINER = st.sidebar.text_input("Default container name", value="test")
KEY_VAULT_URI = st.sidebar.text_input("Key Vault URI", value="https://testcmeksearch.vault.azure.net")
KEY_NAME = st.sidebar.text_input("Key name in Key Vault", value="searchcmek")
SEARCH_API_VERSION = st.sidebar.text_input("Search API version (REST fallback)", value="2021-04-30-Preview")

# credential initialization (use DefaultAzureCredential)
cred = DefaultAzureCredential()

# clients (constructed lazily to reflect runtime edits)
def make_clients():
    idx_client = SearchIndexClient(endpoint=ENDPOINT, credential=cred)
    idxr_client = SearchIndexerClient(endpoint=ENDPOINT, credential=cred)
    kv_client = KeyClient(vault_url=KEY_VAULT_URI, credential=cred)
    return idx_client, idxr_client, kv_client

index_client, indexer_client, key_client = make_clients()

# ---------------- helpers (same logic as CLI tool) ----------------
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

def resolve_key_version(kv_uri: str, key_name: str):
    kc = KeyClient(vault_url=kv_uri, credential=cred)
    k = kc.get_key(key_name)
    return k.properties.version

def build_sdk_encryption_key(kv_uri: str, key_name: str, key_version: str):
    return SearchResourceEncryptionKey(vault_uri=kv_uri, key_name=key_name, key_version=key_version)

def create_index(name: str, encryption_key: Optional[SearchResourceEncryptionKey], logger):
    logger(f"[INDEX] ensuring '{name}'")
    fields = [
        SimpleField(name="id", type="Edm.String", key=True, filterable=True),
        SearchableField(name="content", type="Edm.String", searchable=True)
    ]
    idx = SearchIndex(name=name, fields=fields, encryption_key=encryption_key)
    try:
        res = index_client.create_index(idx)
        logger(f"[INDEX] created: {res.name}")
        return True, res
    except Exception as e:
        logger(f"[INDEX] create error or exists: {e}")
        return False, str(e)

def create_datasource(name: str, container: str, conn_string: str, kv_uri: str, key_name: str, key_version: str, logger):
    logger(f"[DS] ensure '{name}' container='{container}'")
    payload = {
        "name": name,
        "description": "Blob datasource using managed identity and CMEK (Streamlit UI)",
        "type": "azureblob",
        "credentials": {"connectionString": conn_string},
        "container": {"name": container}
    }
    # try SDK create variants
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
                logger(f"[DS] trying SDK method {c}")
                try:
                    r = m(payload)
                except TypeError:
                    r = m(**payload)
                logger(f"[DS] created via SDK method {c}")
                return True, r
            except Exception as e:
                logger(f"[DS] SDK method {c} failed: {e}")
    # REST fallback with CMK shape
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
        logger(f"[DS][REST] create failed: {resp.status_code} {resp.text}")
        return False, resp.text
    logger(f"[DS] created via REST: {name}")
    return True, resp.json()

def create_indexer(name: str, datasource_name: str, target_index: str, kv_uri: str, key_name: str, key_version: str, encryption_key_model: Optional[SearchResourceEncryptionKey], logger):
    logger(f"[IXR] ensure '{name}' linking ds='{datasource_name}' -> idx='{target_index}'")
    idxr_model = SearchIndexer(name=name, data_source_name=datasource_name, target_index_name=target_index, encryption_key=encryption_key_model)
    create_candidates = ["create_indexer", "create_or_update_indexer", "createIndexer"]
    for c in create_candidates:
        m = getattr(indexer_client, c, None)
        if callable(m):
            try:
                logger(f"[IXR] trying SDK method {c}")
                r = m(idxr_model)
                logger(f"[IXR] created via SDK method {c}")
                return True, r
            except Exception as e:
                logger(f"[IXR] SDK method {c} failed: {e}")
    # REST fallback
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
        logger(f"[IXR][REST] create failed: {resp.status_code} {resp.text}")
        return False, resp.text
    logger(f"[IXR] created via REST: {name}")
    return True, resp.json()

def run_indexer(name: str, timeout_sec: int, logger):
    logger(f"[IXR] run {name}")
    # try SDK run
    for r in ["run_indexer", "run_indexer_now", "run"]:
        m = getattr(indexer_client, r, None)
        if callable(m):
            try:
                m(name)
                logger("[IXR] invoked run via SDK")
                break
            except Exception as e:
                logger(f"[IXR] SDK run {r} failed: {e}")
    else:
        token = cred.get_token("https://search.azure.com/.default").token
        url = f"{ENDPOINT}/indexers/{name}/run?api-version={SEARCH_API_VERSION}"
        resp = requests.post(url, headers={"Authorization": f"Bearer {token}"})
        if not (200 <= resp.status_code < 300):
            logger(f"[IXR][REST] run failed: {resp.status_code} {resp.text}")
            return False, resp.text
        logger("[IXR] run invoked via REST")
    # poll using REST for reliable fields
    token = cred.get_token("https://search.azure.com/.default").token
    url = f"{ENDPOINT}/indexers/{name}/status?api-version={SEARCH_API_VERSION}"
    start = time.time()
    while time.time() - start < timeout_sec:
        r = requests.get(url, headers={"Authorization": f"Bearer {token}"})
        if 200 <= r.status_code < 300:
            js = r.json()
            last = js.get("lastResult") or js.get("last_result")
            if last:
                logger(f"[IXR] status: {last.get('status')} | processed: {last.get('itemsProcessed')} | failed: {last.get('itemsFailed')}")
                return True, js
        time.sleep(3)
    logger("[IXR] run polling timed out")
    return False, "timeout"

# ---------------- UI layout ----------------
st.title("Azure Cognitive Search — Resource Manager with CMEK (Sivakrishna Reddy Sunkara)")
left, right = st.columns([2, 1])

with left:
    st.subheader("Manifest / Quick UI")
    manifest_file = st.file_uploader("Upload manifest (YAML or JSON)", type=["yaml", "yml", "json"])
    use_quick = st.checkbox("Use Quick UI (instead of manifest)", value=False)

    if use_quick:
        op = st.selectbox("Operation", ["create", "delete", "index", "datasource", "indexer"])
        names_raw = st.text_input("Index names (comma separated)", value="my-secure-index-a,my-secure-index-b")
        ds_raw = st.text_input("Datasource names (comma separated)", value="ds-a,ds-b")
        ixr_raw = st.text_input("Indexer names (comma separated)", value="ixr-a,ixr-b")
        container = st.text_input("Container (for datasources)", value=DEFAULT_CONTAINER)
        run_after = st.checkbox("Run indexers after create", value=True)
    else:
        op = st.selectbox("Operation (manifest mode)", ["create", "delete"])
        names_raw = ""
        ds_raw = ""
        ixr_raw = ""
        container = ""
        run_after = st.checkbox("Run indexers after create", value=True)

    timeout = st.number_input("Indexer poll timeout (s)", value=300, min_value=30, step=30)

    if st.button("Start"):
        log_lines = []
        def logger(msg):
            log_lines.append(msg)
            # stream to the right pane as well
            st.session_state["log_area"] = "\n".join(log_lines)
        st.session_state["log_area"] = ""

        # prepare manifest or quick inputs
        if use_quick:
            index_names = [n.strip() for n in names_raw.split(",") if n.strip()]
            ds_names = [n.strip() for n in ds_raw.split(",") if n.strip()]
            ixr_names = [n.strip() for n in ixr_raw.split(",") if n.strip()]
            manifest = {
                "storage": {"resourceId": STORAGE_ACCOUNT_RESOURCE_ID or STORAGE_ACCOUNT_RESOURCE_ID},
                "keyVault": {"uri": KEY_VAULT_URI, "keyName": KEY_NAME},
                "indexes": [{"name": n} for n in index_names],
                "datasources": [{"name": n, "container": container} for n in ds_names],
                "indexers": [{"name": n, "dataSourceName": (ds_names[i] if i < len(ds_names) else None), "targetIndexName": (index_names[i] if i < len(index_names) else None)} for i,n in enumerate(ixr_names)]
            }
        else:
            if not manifest_file:
                st.error("Upload a manifest file when not using Quick UI.")
                st.stop()
            raw = manifest_file.read().decode("utf-8")
            if manifest_file.name.endswith((".yaml", ".yml")):
                manifest = yaml.safe_load(raw)
            else:
                manifest = json.loads(raw)

        # normalize storage connection
        storage = manifest.get("storage", {})
        storage_input = storage.get("connectionString") or storage.get("resourceId") or STORAGE_ACCOUNT_RESOURCE_ID
        try:
            conn_string = normalize_conn_string(storage_input)
        except Exception as e:
            st.error(f"Invalid storage input: {e}")
            st.stop()

        # key vault resolution
        kv = manifest.get("keyVault", {})
        kv_uri = kv.get("uri") or KEY_VAULT_URI
        kv_key = kv.get("keyName") or KEY_NAME
        try:
            key_version = resolve_key_version(kv_uri, kv_key)
            logger(f"Resolved key version: {key_version}")
        except Exception as e:
            st.error(f"Failed to resolve key version: {e}")
            st.stop()

        # build sdk encryption model if possible
        try:
            enc_model = build_sdk_encryption_key(kv_uri, kv_key, key_version)
        except Exception:
            enc_model = None

        indexes = manifest.get("indexes", [])
        datasources = manifest.get("datasources", [])
        indexers = manifest.get("indexers", [])

        # create/delete flow
        if op == "create":
            # PHASE 1: create indexes
            if indexes:
                logger("PHASE 1: Creating indexes...")
                for idx in indexes:
                    nm = idx["name"]
                    create_index(nm, enc_model, logger)
            # PHASE 2: datasources
            if datasources:
                logger("PHASE 2: Creating datasources...")
                for ds in datasources:
                    ds_name = ds["name"]
                    ds_container = ds.get("container") or storage.get("container") or DEFAULT_CONTAINER
                    ds_conn = ds.get("connectionString") or conn_string
                    create_datasource(ds_name, ds_container, ds_conn, kv_uri, kv_key, key_version, logger)
            # PHASE 3: indexers
            if indexers:
                logger("PHASE 3: Creating indexers...")
                for ix in indexers:
                    create_indexer(ix["name"], ix["dataSourceName"], ix["targetIndexName"], kv_uri, kv_key, key_version, enc_model, logger)
                    if run_after:
                        ok, info = run_indexer(ix["name"], timeout, logger)
        else:
            # delete: indexers -> datasources -> indexes
            if indexers:
                logger("DELETE PHASE 1: Deleting indexers...")
                for ix in indexers:
                    name = ix["name"]
                    # delete via SDK or REST
                    try:
                        m = getattr(indexer_client, "delete_indexer", None)
                        if callable(m):
                            m(name)
                            logger(f"[IXR] deleted via SDK: {name}")
                        else:
                            token = cred.get_token("https://search.azure.com/.default").token
                            r = requests.delete(f"{ENDPOINT}/indexers/{name}?api-version={SEARCH_API_VERSION}", headers={"Authorization": f"Bearer {token}"})
                            logger(f"[IXR] delete REST: {r.status_code}")
                    except Exception as e:
                        logger(f"[IXR] delete error: {e}")
            if datasources:
                logger("DELETE PHASE 2: Deleting datasources...")
                for ds in datasources:
                    name = ds["name"]
                    try:
                        m = getattr(indexer_client, "delete_datasource_connection", None)
                        if callable(m):
                            m(name)
                            logger(f"[DS] deleted via SDK: {name}")
                        else:
                            token = cred.get_token("https://search.azure.com/.default").token
                            r = requests.delete(f"{ENDPOINT}/datasources/{name}?api-version={SEARCH_API_VERSION}", headers={"Authorization": f"Bearer {token}"})
                            logger(f"[DS] delete REST: {r.status_code}")
                    except Exception as e:
                        logger(f"[DS] delete error: {e}")
            if indexes:
                logger("DELETE PHASE 3: Deleting indexes...")
                for idx in indexes:
                    name = idx["name"]
                    try:
                        m = getattr(index_client, "delete_index", None)
                        if callable(m):
                            m(name)
                            logger(f"[INDEX] deleted via SDK: {name}")
                        else:
                            token = cred.get_token("https://search.azure.com/.default").token
                            r = requests.delete(f"{ENDPOINT}/indexes/{name}?api-version={SEARCH_API_VERSION}", headers={"Authorization": f"Bearer {token}"})
                            logger(f"[INDEX] delete REST: {r.status_code}")
                    except Exception as e:
                        logger(f"[INDEX] delete error: {e}")

        # show logs on right panel (session_state used to stream)
        st.session_state["log_area"] = "\n".join(log_lines) if "log_lines" in locals() else st.session_state.get("log_area","")

with right:
    st.subheader("Logs / REST responses")
    log_text = st.text_area("Log output", value=st.session_state.get("log_area",""), height=600)
    st.download_button("Download logs", data=log_text, file_name="search_cmek_logs.txt")
    st.markdown("---")
    st.subheader("Inspector")
    inspector_indexer = st.text_input("Inspect indexer status (name)", value="")
    if st.button("Get indexer status"):
        if not inspector_indexer:
            st.warning("Enter indexer name")
        else:
            try:
                token = cred.get_token("https://search.azure.com/.default").token
                url = f"{ENDPOINT}/indexers/{inspector_indexer}/status?api-version={SEARCH_API_VERSION}"
                r = requests.get(url, headers={"Authorization": f"Bearer {token}"})
                st.json(r.json())
            except Exception as e:
                st.error(f"Failed to fetch status: {e}")

st.caption("Streamlit UI for CMEK + Cognitive Search created by assistant. Use with caution and proper Azure permissions.")