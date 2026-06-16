from typing import Optional

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

from database import get_fraud_logs, register_fraud_log, delete_log_query, delete_all_logs
from model import treat_message_llm
import uvicorn
from mangum import Mangum

app = FastAPI(
    title="Bless Guardian",
    description="Agente anti-fraude de deteccao de engenharia social."
)


class MessageRequest(BaseModel):
    device_id: Optional[str] = None
    user_id: Optional[str] = None
    message_content: str
    source: str


@app.post("/detect", status_code=201)
async def detect_fraud(request: MessageRequest):
    try:
        device_id = request.device_id or request.user_id
        if not device_id:
            raise HTTPException(status_code=422, detail="device_id is required")

        analise = await treat_message_llm(request.message_content)
        db_result = await register_fraud_log(
            device_id=device_id,
            content=request.message_content,
            score=analise.get("score"),
            is_fraud=analise.get("tentativa_fraude"),
            explanation=analise.get("veredito_curto"),
            source=request.source
        )

        return {
            "status_db": db_result.get("success", False),
            "user_id": db_result.get("user_id"),
            "analise": analise
        }
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/logs")
async def api_get_logs(
    device_id: Optional[str] = None,
    user_id: Optional[str] = None,
    limit: int = 50,
    offset: int = 0
):
    resultados = await get_fraud_logs(
        device_id=device_id,
        user_id=user_id,
        limit=limit,
        offset=offset
    )

    if isinstance(resultados, dict) and "error" in resultados:
        return {"status": "error", "message": resultados["error"]}

    return {
        "status": "success",
        "total_logs": len(resultados),
        "data": resultados
    }

@app.delete("/logs")
async def delete_log(user_id: str, detected_at: str):
    try:
        return await delete_log_query(user_id=user_id, detected_at=detected_at)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.delete("/logs/all")
async def delete_all_message_logs():
    try:
        return await delete_all_logs()
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/health")
async def health_check():
    return {"status": "healthy"}

handler = Mangum(app)

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8080)
