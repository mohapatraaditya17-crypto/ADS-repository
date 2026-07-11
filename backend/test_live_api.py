"""
Live API connectivity test — verifies real Falcon API credentials work.
Tests: Detections, Incidents, Hosts, Intel, Policies, Sensor Coverage
"""
import sys
sys.path.insert(0, '.')

from app.tools.crowdstrike.client_factory import FalconAPIError

def test_module(name, fn, *args, **kwargs):
    try:
        result = fn(*args, **kwargs)
        if isinstance(result, list):
            print(f"  PASS  {name}: {len(result)} records returned")
        elif isinstance(result, dict):
            print(f"  PASS  {name}: keys={list(result.keys())[:5]}")
        else:
            print(f"  PASS  {name}: {type(result).__name__}")
        return True
    except FalconAPIError as e:
        print(f"  WARN  {name}: API Error {e.status_code} — {e.errors[:1]}")
        if e.scope_hint:
            print(f"        Required scope: {e.scope_hint}")
        return False
    except Exception as e:
        print(f"  FAIL  {name}: {type(e).__name__}: {e}")
        return False

print("=" * 60)
print("Falcon AI Copilot — Live API Connectivity Tests")
print("=" * 60)
print()

results = []

# Test detections
from app.tools.crowdstrike.detections import query_recent_detections, get_detection_count_by_severity
print("DETECTIONS:")
results.append(test_module("query_recent_detections(24h)", query_recent_detections, hours=24, max_results=5))
results.append(test_module("get_detection_count_by_severity", get_detection_count_by_severity, hours=24))

print()
# Test incidents
from app.tools.crowdstrike.incidents import query_incidents
print("INCIDENTS:")
results.append(test_module("query_incidents(24h)", query_incidents, hours=24, max_results=5))

print()
# Test hosts
from app.tools.crowdstrike.hosts import list_all_hosts
print("HOSTS:")
results.append(test_module("list_all_hosts(limit=5)", list_all_hosts, max_results=5))

print()
# Test sensor coverage
from app.tools.crowdstrike.sensor import get_sensor_coverage
print("SENSOR:")
results.append(test_module("get_sensor_coverage", get_sensor_coverage))

print()
# Test intel
from app.tools.crowdstrike.intel import get_threat_actors
print("INTEL:")
results.append(test_module("get_threat_actors(5)", get_threat_actors, max_results=5))

print()
# Test policies
from app.tools.crowdstrike.policies import list_prevention_policies
print("POLICIES:")
results.append(test_module("list_prevention_policies", list_prevention_policies))

print()
# Test spotlight
from app.tools.crowdstrike.spotlight import get_vuln_summary_by_severity
print("SPOTLIGHT:")
results.append(test_module("get_vuln_summary_by_severity", get_vuln_summary_by_severity))

print()
# Test metrics
from app.tools.crowdstrike.metrics import get_mttd
print("METRICS:")
results.append(test_module("get_mttd(24h)", get_mttd, hours=24))

print()
print("=" * 60)
passed = sum(1 for r in results if r)
print(f"RESULT: {passed}/{len(results)} tests passed")
print("=" * 60)
