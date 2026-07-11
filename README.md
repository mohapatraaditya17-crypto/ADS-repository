# Falcon AI Copilot

Falcon AI Copilot is an Enterprise AI Assistant specialized in CrowdStrike Falcon. It operates exclusively in **read-only** mode to ensure security while augmenting SOC analysts with natural-language access to logs, security configurations, MITRE ATT&CK, threat intelligence, and RAG-based CrowdStrike documentation.

## Project Structure

```
falcon-ai-copilot/
├── backend/                  # FastAPI app & LangGraph orchestrator
│   ├── app/
│   │   ├── agents/           # Specialized LangGraph agents
│   │   ├── tools/            # Read-only CrowdStrike API wrappers
│   │   ├── rag/              # Document loaders & pgvector similarity search
│   │   ├── middleware/       # Read-only guard & auditing
│   │   └── main.py           # API endpoints (SSE streaming)
│   └── pyproject.toml        # Backend python dependencies
├── frontend/                 # React & Next.js premium chat UI
└── docker-compose.yml        # Development environment configuration
```

## Running the App (Host-Run Mode without Docker)

Since Docker is not required, the application runs directly on the host using a local SQLite database fallback and an embedded premium Web Client:

1. Configure your `.env` variables in the `backend` directory.
2. Initialize the database and run the ingestion tool (from the `backend` directory):
   ```bash
   .venv/Scripts/python -m app.rag.ingest
   ```
3. Start the FastAPI assistant server (from the `backend` directory):
   ```bash
   .venv/Scripts/python -m uvicorn app.main:app --host 127.0.0.1 --port 8000 --reload
   ```
4. Access the premium Chat UI by opening `http://127.0.0.1:8000/` in your web browser.

