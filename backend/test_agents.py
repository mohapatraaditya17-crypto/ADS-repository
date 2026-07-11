"""
Agent integration test.
"""
import sys
import logging
sys.path.insert(0, '.')

from app.agents.soc_analyst import run_soc_analyst
from app.agents.report_generator import run_report_generator

logging.basicConfig(level=logging.INFO)

print("Testing SOC Analyst...")
stream = run_soc_analyst("Investigate recent detections from the last 24 hours.", [])
for event in stream:
    if event["event"] == "tool_complete":
        print(f"Tool Complete: {event['data']['name']} - Status: {event['data']['status']}")

print("\nTesting Report Generator...")
stream2 = run_report_generator("Generate a daily SOC report for the last 24 hours.", [])
for event in stream2:
    if event["event"] == "tool_complete":
        print(f"Tool Complete: {event['data']['name']} - Status: {event['data']['status']}")

print("\nIntegration test finished.")
