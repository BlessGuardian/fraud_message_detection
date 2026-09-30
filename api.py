from typing import Optional
import asyncio
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from fraud_detection import analyze_message
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

        # 1. Executa ambas as análises concorrentemente
        analise_llm_task = treat_message_llm(request.message_content)
        analise_onnx_task = analyze_message(request.message_content)
        analise_llm, analise_onnx = await asyncio.gather(analise_llm_task, analise_onnx_task)

        # 2. Extrai os resultados individuais
        is_fraud_llm = 1 if analise_llm.get("tentativa_fraude") else 0
        is_fraud_onnx = analise_onnx.get("is_fraud", 0)

        # 3. Matriz de Decisão Híbrida
        # [1,1] = fraude, [1,0] ou [0,1] = aviso, [0,0] = seguro
        soma_decisoes = is_fraud_llm + is_fraud_onnx
        
        if soma_decisoes >= 1:
            is_fraud_db = True
            status_final = "fraude"
            if soma_decisoes == 1:
                status_final = "aviso"
        else:
            status_final = "seguro"
            is_fraud_db = False

        explicacao = (
            f"Veredito Híbrido: {status_final.upper()}. "
            f"LLM: {'Fraude' if is_fraud_llm else 'Seguro'} | "
            f"Modelo Local: {'Fraude' if is_fraud_onnx else 'Seguro'}. "
            f"Justificativa LLM: {analise_llm.get('veredito_curto', '')}"
        )

        db_result = await register_fraud_log(
            device_id=device_id,
            content=request.message_content,
            score=0, 
            is_fraud=is_fraud_db,
            explanation=explicacao,
            source=request.source
        )

        #Formatação para se adequar a versão antiga da api e não quebrar os apps
        analise_resposta = analise_llm.copy() 
        analise_resposta["tentativa_fraude"] = is_fraud_db
        analise_resposta["veredito_curto"] = explicacao
        analise_resposta["score"] = 0

        return {
            "status_db": db_result.get("success", False),
            "user_id": db_result.get("user_id"),
            "analise": analise_resposta, 
            "detalhes_hibridos": {
                "status_final": status_final,
                "decisao_llm": is_fraud_llm,
                "decisao_onnx": is_fraud_onnx
            }
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
