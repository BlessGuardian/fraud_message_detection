from typing import Optional
import asyncio
import traceback
from fastapi import FastAPI, HTTPException,Depends
from fastapi.security import OAuth2PasswordBearer
from pydantic import BaseModel, EmailStr
from fraud_detection import analyze_message
from database import get_fraud_logs, register_fraud_log, delete_log_query, delete_all_logs, register_user_db, get_user,get_fraud_stats, calculate_scores, get_user_score
from model import treat_message_llm
import uvicorn
from mangum import Mangum
from auth import create_access_token, get_password_hash, verify_password, decode_access_token

app = FastAPI(
    title="Bless Guardian",
    description="Agente anti-fraude de deteccao de engenharia social."
)

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")
oauth2_scheme_optional = OAuth2PasswordBearer(tokenUrl="login", auto_error=False)

class MessageRequest(BaseModel):
    device_id: Optional[str] = None
    user_id: Optional[str] = None
    message_content: str
    source: str

class RegisterRequest(BaseModel):
    device_id: Optional[str] = None
    email: EmailStr
    password: str

class LoginRequest(BaseModel):
    email: EmailStr
    password: str

@app.post("/register", status_code=201, tags=["Auth"])
async def register_user(request: RegisterRequest):
    hashed_password = get_password_hash(request.password)

    db_result = await register_user_db(
        device_id=request.device_id,
        email=request.email, 
        password_hash=hashed_password
    )

    if not db_result.get("success"):
        raise HTTPException(status_code=400, detail=db_result.get("error"))

    return {
        "status": "success",
        "message": "Usuário registrado com sucesso.",
        "user_id": db_result.get("user_id")
    }

@app.post("/login", tags=["Auth"])
async def login_user(request: LoginRequest):
    user = await get_user(request.email)
    
    if not user or not verify_password(request.password, user['password_hash']):
        raise HTTPException(status_code=401, detail="E-mail ou senha incorretos")
    
    # 3. Gera o token importando do seu novo arquivo auth.py
    access_token = create_access_token(
        data={
            "sub": user['email'], 
            "user_id": user['user_id'], 
            "role": user.get('role', 'default')
        }
    )
    
    return {
        "access_token": access_token,
        "token_type": "bearer",
        "user_id": user['user_id'],
        "role": user.get('role', 'default')
    }

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
            category= analise_llm.get("categoria"),
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
        print(traceback.format_exc())
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/logs")
async def api_get_logs(
    device_id: Optional[str] = None,
    user_id: Optional[str] = None,
    limit: Optional[int] = None,
    offset: int = 0,
    token: str = Depends(oauth2_scheme)
):

    payload = decode_access_token(token)
    if not payload:
        raise HTTPException(status_code=401, detail="Token inválido ou expirado")
    user_id = payload.get("user_id")
    device_id = None


    resultados = await get_fraud_logs(
        limit=limit,
        device_id=device_id,
        user_id=user_id,
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

@app.get("/stats", tags=["Dashboard"])
async def api_get_stats(token: Optional[str] = Depends(oauth2_scheme_optional)):
    """
    Retorna as estatísticas de golpes. 
    Se o token for enviado, retorna apenas os dados do usuário.
    Se nenhum token for enviado, retorna as estatísticas globais.
    """
    user_id_seguro = None

    # Se um token foi enviado, aplicamos a trava de segurança para pegar o usuário
    if token:
        payload = decode_access_token(token)
        if not payload:
            raise HTTPException(status_code=401, detail="Token inválido ou expirado")
        
        user_id_seguro = payload.get("user_id")

    # Chama o banco de dados (se user_id_seguro for None, ele faz o Scan global)
    resultados = await get_fraud_stats(user_id=user_id_seguro)
    
    if not resultados.get("success"):
        raise HTTPException(status_code=500, detail=resultados.get("error"))
        
    return {
        "status": "success",
        "escopo": "usuario" if user_id_seguro else "global",
        "total_categorias": len(resultados.get("data", [])),
        "stats": resultados.get("data")
    }

@app.post("/admin/calculate-scores", tags=["Admin Dashboard"])
async def api_calculate_scores():
    """
    Endpoint manual para MVP. 
    Aciona o recálculo matemático de Vulnerability Score para TODOS os utilizadores.
    """
    # OPCIONAL: Se quiser proteger este endpoint apenas para administradores:
    # if current_user.get("role") != "admin":
    #     raise HTTPException(status_code=403, detail="Acesso negado. Apenas administradores.")
    
    resultado = await calculate_scores()
    
    if resultado.get("status") == "error":
        raise HTTPException(status_code=500, detail=resultado.get("error"))
        
    return resultado

@app.get("/score", tags=["Dashboard"])
async def api_get_score(token: str = Depends(oauth2_scheme)):
    """
    Devolve o score de vulnerabilidade (de 0.0 a 1.0) do usuário autenticado.
    Baseado no cálculo estatístico de 3 desvios padrões (atualizado via POST /admin/calculate-scores).
    """
    payload = decode_access_token(token)
    if not payload:
        raise HTTPException(status_code=401, detail="Token inválido ou expirado")
    user_id = payload.get("user_id")
    
    # Consulta rápida no banco de dados
    resultado = await get_user_score(user_id)
    
    if not resultado.get("success"):
        raise HTTPException(status_code=404, detail=resultado.get("error"))
        
    score = resultado.get("score")
    
    return {
        "status": "success",
        "user_id": user_id,
        "vulnerability_score": score,
    }

@app.get("/health")
async def health_check():
    return {"status": "healthy"}

handler = Mangum(app)

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8080)
