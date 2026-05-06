from fastapi import FastAPI, HTTPException, BackgroundTasks
from pydantic import BaseModel
# from fraud_detection import check_text_for_fraud
from database import register_fraud_log, get_fraud_logs
from model import treat_message_llm
import uvicorn

app = FastAPI(title="Bless Guardian", description="Agente anti-fraude de detecção de engenharia social .")

# Modelo de dados para validação da requisição
class MessageRequest(BaseModel):
    user_id: str
    message_content: str
    source: str
    
@app.post("/detect", status_code=201)
def detect_fraud(request: MessageRequest):
    try:
    
        analise = treat_message_llm(request.message_content)

        db_success = register_fraud_log(
        user_id=request.user_id, # Exemplo de UUID
        content=request.message_content,
        score=analise.get("score"), # float8
        is_fraud=analise.get("tentativa_fraude"), # bool
        explanation=analise.get("veredito_curto"), # text
        source= request.source # varchar(50)
        )
        return {
            "status_db": db_success,
            "analise": analise
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

# @app.post("/detectbert", status_code=201)
# async def detect_fraud_mixed(request: MessageRequest):
#     try:
#         score, is_fraud, level = check_text_for_fraud(request.message_content)
        
#         return {
#             "score": score,
#             "is_fraud": is_fraud,
#             "risk_level": level,
#         }
#     except Exception as e:
#         raise HTTPException(status_code=500, detail=str(e))

@app.get("/logs")
def api_get_logs(user_id: str = None, limit: int = 50, offset: int = 0):
    
    resultados = get_fraud_logs(user_id=user_id, limit=limit, offset=offset)
    
    # Se retornou um erro estruturado
    if isinstance(resultados, dict) and "error" in resultados:
        return {"status": "error", "message": resultados["error"]}
        
    return {
        "status": "success",
        "total_logs": len(resultados),
        "data": resultados
    }

@app.get("/health")
def health_check():
    return {"status": "healthy"}

if __name__ == "__main__":
    # Porta 8080 é o padrão comum para o App Runner
    uvicorn.run(app, host="0.0.0.0", port=8080)