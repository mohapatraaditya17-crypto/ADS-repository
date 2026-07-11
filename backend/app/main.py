import asyncio
import time
import json
import logging
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse, HTMLResponse
from sse_starlette.sse import EventSourceResponse
from app.config import settings
from app.models.schemas import ChatRequest
from app.middleware.readonly_guard import enforce_readonly_globally

from app.agents.orchestrator import route_and_run

# Setup Logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("falcon_copilot_main")

# Initialize Read-Only Guard on startup
enforce_readonly_globally()

from fastapi.staticfiles import StaticFiles
import os

app = FastAPI(
    title="Falcon AI Copilot API",
    description="Strictly read-only SOC assistant for CrowdStrike Falcon",
    version="1.0"
)

# CORS configuration
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Restrict in production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Mount Static Files folder for generated reports
static_path = os.path.join(os.path.dirname(__file__), "static")
os.makedirs(static_path, exist_ok=True)
app.mount("/static", StaticFiles(directory=static_path), name="static")

@app.get("/", response_class=HTMLResponse)
async def read_index():
    index_file = os.path.join(static_path, "index.html")
    if os.path.exists(index_file):
        with open(index_file, "r", encoding="utf-8") as f:
            return HTMLResponse(content=f.read())
    return HTMLResponse(content="<h1>Falcon AI Copilot Backend Running</h1><p>Static index.html not found.</p>")

@app.get("/api/health")
async def health_check():
    return {
        "status": "ok",
        "timestamp": time.time(),
        "read_only_guard": "active",
        "llm_provider": settings.LLM_PROVIDER
    }

async def generate_chat_events(request: ChatRequest):
    """
    SSE stream generating events by routing through the orchestrator.
    """
    session_id = request.session_id or "sess_mock_12345"
    prompt = request.message
    history = [{"role": h.role, "content": h.content} for h in request.history]
    
    # Execute the orchestrator router
    loop = asyncio.get_event_loop()
    generator = route_and_run(prompt, history)
    
    def get_next_item():
        try:
            return next(generator)
        except StopIteration:
            return None

    while True:
        event_item = await loop.run_in_executor(None, get_next_item)
        if event_item is None:
            break
            
        yield {
            "event": event_item["event"],
            "data": json.dumps(event_item["data"])
        }
        # Yield control back to event loop
        await asyncio.sleep(0)


@app.post("/api/chat")
async def chat_endpoint(request: ChatRequest):
    """
    Main chat endpoint returning a Server-Sent Events stream.
    """
    logger.info(f"Received chat message: {request.message} (Session: {request.session_id})")
    return EventSourceResponse(generate_chat_events(request))

from pydantic import BaseModel

class SettingsUpdateRequest(BaseModel):
    client_id: str
    client_secret: str
    base_url: str

@app.get("/api/settings")
async def get_settings():
    return {
        "client_id": settings.FALCON_CLIENT_ID,
        "client_secret": settings.FALCON_CLIENT_SECRET,
        "base_url": settings.FALCON_BASE_URL
    }

@app.post("/api/settings")
async def update_settings(req: SettingsUpdateRequest):
    # Update in-memory settings immediately
    settings.FALCON_CLIENT_ID = req.client_id
    settings.FALCON_CLIENT_SECRET = req.client_secret
    settings.FALCON_BASE_URL = req.base_url

    # Write changes to the .env file
    env_file = settings.model_config.get("env_file")
    if env_file and os.path.exists(env_file):
        try:
            with open(env_file, "r", encoding="utf-8") as f:
                lines = f.readlines()
            
            new_lines = []
            replaced_id = False
            replaced_secret = False
            replaced_url = False
            
            for line in lines:
                strip_line = line.strip()
                if strip_line.startswith("FALCON_CLIENT_ID="):
                    new_lines.append(f"FALCON_CLIENT_ID={req.client_id}\n")
                    replaced_id = True
                elif strip_line.startswith("FALCON_CLIENT_SECRET="):
                    new_lines.append(f"FALCON_CLIENT_SECRET={req.client_secret}\n")
                    replaced_secret = True
                elif strip_line.startswith("FALCON_BASE_URL="):
                    new_lines.append(f"FALCON_BASE_URL={req.base_url}\n")
                    replaced_url = True
                else:
                    new_lines.append(line)
            
            # If any keys weren't present, append them
            if not replaced_id:
                new_lines.append(f"FALCON_CLIENT_ID={req.client_id}\n")
            if not replaced_secret:
                new_lines.append(f"FALCON_CLIENT_SECRET={req.client_secret}\n")
            if not replaced_url:
                new_lines.append(f"FALCON_BASE_URL={req.base_url}\n")
                
            with open(env_file, "w", encoding="utf-8") as f:
                f.writelines(new_lines)
        except Exception as e:
            logger.error(f"Failed to write to .env file: {e}")
            return {"status": "error", "message": f"Failed to save settings to .env file: {str(e)}"}
            
    return {"status": "success", "message": "Settings updated in memory and saved to .env"}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host=settings.HOST, port=settings.PORT)
