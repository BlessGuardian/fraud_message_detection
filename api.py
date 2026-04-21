from fastapi import FastAPI, HTTPException, BackgroundTasks
from pydantic import BaseModel
from fraud_detection import check_text_for_fraud
from database import register_scam_attempt, create_table_if_not_exists
from model import treat_message_llm
import uvicorn

app = FastAPI(title="Bless Guardian", description="Agente anti-fraude de detecção de engenharia social .")

# Modelo de dados para validação da requisição
class MessageRequest(BaseModel):
    user_id: str
    message_content: str

# Inicialização do banco (Executado ao subir a API)
@app.on_event("startup")
def startup_event():
    create_table_if_not_exists()

@app.post("/detect", status_code=201)
async def detect_fraud(request: MessageRequest):
    try:
        # 1. Tratamento Inicial com Bert
        score, is_fraud, level = check_text_for_fraud(request.message_content)
        db_success = register_scam_attempt(
            request.user_id, 
            request.message_content, 
            score, 
            level, 
            is_fraud
        )
        if is_fraud:
            return treat_message_llm(request.message_content)
        # 2. Persistência no Aiven
        else:
            return {
            "score": score,
            "is_fraud": is_fraud,
            "risk_level": level,
            "db_status": "synced" if db_success else "local_only"
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/health")
def health_check():
    return {"status": "healthy"}

if __name__ == "__main__":
    # Porta 8080 é o padrão comum para o App Runner
    uvicorn.run(app, host="127.0.0.1", port=8080)