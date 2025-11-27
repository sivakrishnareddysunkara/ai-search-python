# create_index_with_cmk.py
# !pip install azure-identity azure-keyvault-keys azure-search-documents

import os
from azure.identity import DefaultAzureCredential
from azure.keyvault.keys import KeyClient
from azure.search.documents.indexes import SearchIndexClient
from azure.search.documents.indexes.models import (
    SearchIndex,
    SimpleField,
    SearchableField,
    SearchableField,
    edm,
    SearchResourceEncryptionKey
)

# ------------------ CONFIG ------------------
SEARCH_SERVICE_NAME = "testcmekenable"   # e.g. "mysearchsvc"
ENDPOINT = f"https://testcmekenable.search.windows.net"
INDEX_NAME = "my-secure-index"  # choose your index name

# Key Vault info
KV_URI = "https://testcmeksearch.vault.azure.net"   # no trailing path
KEY_NAME = "searchcmek"
# KEY_VERSION = "<optional-key-version>"  # leave None to auto-resolve latest version
KEY_VERSION = None
# -------------------------------------------

cred = DefaultAzureCredential()

def get_latest_key_version(kv_uri, key_name):
    """Return the latest key version string (or None if cannot fetch)."""
    try:
        key_client = KeyClient(vault_url=kv_uri, credential=cred)
        # list_properties_of_key_versions returns iterator of KeyProperties, newest first-ish is not guaranteed,
        # so we fetch the current key (which has .key.kid including version)
        key = key_client.get_key(key_name)
        # key.id is like: https://{vault}.vault.azure.net/keys/{name}/{version}
        return key.properties.version
    except Exception as e:
        print("Warning: failed to read key version from Key Vault:", e)
        return None

def build_encryption_key_descriptor(kv_uri, key_name, key_version=None):
    if key_version is None:
        key_version = get_latest_key_version(kv_uri, key_name)
        if not key_version:
            raise RuntimeError("Could not determine key version. Provide KEY_VERSION explicitly or check Key Vault permissions.")
    # Build the SearchResourceEncryptionKey model
    return SearchResourceEncryptionKey(
        vault_uri=kv_uri,
        key_name=key_name,
        key_version=key_version
    )

def create_index_with_cmk(endpoint, credential, index_name, encryption_key):
    client = SearchIndexClient(endpoint=endpoint, credential=credential)

    # Define a minimal index schema — adjust fields for your data model
    fields = [
        SimpleField(name="id", type=edm.String, key=True, filterable=True),
        SearchableField(name="content", type=edm.String, searchable=True, analyzer_name="en.lucene")
    ]

    index = SearchIndex(name=index_name, fields=fields, encryption_key=encryption_key)

    print("Creating index (with encryption key) ...")
    created = client.create_index(index)
    print("Index created:", created.name)
    print("Encryption key on index:", created.encryption_key)
    return created

if __name__ == "__main__":
    # build encryption key descriptor (will fetch latest version if KEY_VERSION is None)
    encryption_key = build_encryption_key_descriptor(KV_URI, KEY_NAME, KEY_VERSION)

    # Create the index with encryptionKey present — required when service enforcement is Enabled
    try:
        created_index = create_index_with_cmk(ENDPOINT, cred, INDEX_NAME, encryption_key)
    except Exception as err:
        print("Failed to create index. Common reasons:")
        print(" - Caller (DefaultAzureCredential principal) lacks Search RBAC role to create/update indices.")
        print(" - Key Vault permissions for the Search service identity are missing or propagation delay.")
        print(" - Service enforcement is enabled but encryption key payload is invalid.")
        print("Error details:", err)
