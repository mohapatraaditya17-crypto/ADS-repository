# FalconPy Service Classes

The official CrowdStrike FalconPy SDK provides service classes representing each Falcon API collection.

## Prevention Policies
The `PreventionPolicies` service class provides access to the CrowdStrike Prevention Policies API.

### `query_prevention_policies`
Find Prevention Policies by providing an FQL filter and paging details. Returns a set of Prevention Policy IDs that match your criteria.

**Method Signature:**
```python
def query_prevention_policies(self, filter: str = None, offset: int = None, limit: int = None, sort: str = None) -> dict
```

**Required Scopes:** 
- Prevention Policies: Read

**Example:**
```python
from falconpy import PreventionPolicies
import os

falcon = PreventionPolicies(
    client_id=os.environ.get("FALCON_CLIENT_ID"),
    client_secret=os.environ.get("FALCON_CLIENT_SECRET")
)

response = falcon.query_prevention_policies(filter="platform_name:'Windows'")
if response["status_code"] == 200:
    for policy_id in response["body"]["resources"]:
        print(f"Policy ID: {policy_id}")
```

### `get_prevention_policies`
Get a set of Prevention Policies by specifying their IDs.

**Method Signature:**
```python
def get_prevention_policies(self, ids: list) -> dict
```

## Hosts
The `Hosts` service class allows you to manage hosts and retrieve host details.

### `query_devices_by_filter`
Search for hosts in your environment by platform, hostname, IP, and other criteria.

**Method Signature:**
```python
def query_devices_by_filter(self, filter: str = None, limit: int = None, offset: int = None) -> dict
```

**Required Scopes:**
- Hosts: Read
