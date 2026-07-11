from pydantic import BaseModel, Field
from typing import List, Optional, Dict, Any

class ChatMessage(BaseModel):
    role: str = Field(..., description="Role of the sender: 'user' or 'assistant'")
    content: str = Field(..., description="Content of the message")
    timestamp: Optional[str] = Field(default=None, description="ISO timestamp")

class ChatRequest(BaseModel):
    message: str = Field(..., description="User prompt")
    history: List[ChatMessage] = Field(default=[], description="Previous conversation history")
    session_id: Optional[str] = Field(default=None, description="Unique session token")

class ToolCallLog(BaseModel):
    name: str
    params: Dict[str, Any]
    duration_ms: int
    status: str # 'success' or 'error'

class ChatResponse(BaseModel):
    session_id: str
    response: str
    agent_routed: str
    tools_called: List[ToolCallLog] = []
    duration_ms: int
