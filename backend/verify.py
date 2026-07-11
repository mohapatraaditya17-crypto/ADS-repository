import sys
from app.agents.falcon_engineer import run_falcon_engineer

def main():
    query = "Write a FalconPy script to query Windows prevention policies"
    print(f"Testing Falcon Engineer with query: {query}")
    
    stream = run_falcon_engineer(query)
    for event in stream:
        if event["event"] == "agent_state":
            print(f"[{event['data']['agent']}] {event['data']['message']}")
        elif event["event"] == "tool_start":
            print(f"[Tool Start] {event['data']['name']} with {event['data']['params']}")
        elif event["event"] == "tool_complete":
            print(f"[Tool Complete] {event['data']['name']}: {event['data']['result']}")
        elif event["event"] == "text_chunk":
            # Print text chunks without newlines to stream to console
            print(event["data"]["text"], end="", flush=True)
        elif event["event"] == "complete":
            print(f"\n[{event['data']['agent']}] Done!")
            
if __name__ == "__main__":
    main()
