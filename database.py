import os
import uuid
from datetime import datetime, timezone,timedelta
from decimal import Decimal

import aioboto3
from boto3.dynamodb.conditions import Key
from dotenv import load_dotenv

load_dotenv()
DYNAMO_TABLE_NAME = os.getenv("DYNAMO_TABLE_NAME")
AWS_REGION = os.getenv("AWS_REGION")

# O aioboto3 trabalha com sessões que geram recursos de forma assíncrona
boto_session = aioboto3.Session(region_name=AWS_REGION)

def get_deterministic_user_id(device_id: str) -> str:
    """
    Gera um UUID consistente baseado no device_id. 
    Evita a necessidade de uma tabela separada apenas para mapear device -> user.
    """
    if not device_id:
        return str(uuid.uuid4())
    return str(uuid.uuid5(uuid.NAMESPACE_OID, device_id))


async def register_fraud_log(device_id, content, score, is_fraud, explanation=None, source=None):
    """Registra o log de análise de fraude exclusivamente no DynamoDB."""
    user_id = get_deterministic_user_id(device_id)
    fraud_log_id = str(uuid.uuid4())
    detected_at = datetime.now(timezone(timedelta(hours=-3))).isoformat()

    item = {
        "user_id": user_id,                  
        "detected_at": detected_at,          
        "id": fraud_log_id,
        "device_id": device_id,
        "content": content,
        "risk_score": Decimal(str(score)),   
        "is_fraud": is_fraud,
        "explanation": explanation,
        "source": source
    }

    # Context manager assíncrono do aioboto3
    async with boto_session.resource('dynamodb') as dynamodb:
        dynamo_table = await dynamodb.Table(DYNAMO_TABLE_NAME)
        await dynamo_table.put_item(Item=item)
        
    return {"success": True, "user_id": user_id, "database": "dynamodb"}


async def get_fraud_logs(device_id=None, user_id=None, limit=50, offset=0):
    """Busca o histórico de logs exclusivamente no DynamoDB."""
    query_user_id = user_id or (get_deterministic_user_id(device_id) if device_id else None)
    
    async with boto_session.resource('dynamodb') as dynamodb:
        dynamo_table = await dynamodb.Table(DYNAMO_TABLE_NAME)
        
        if query_user_id:
            # Se temos o user_id, usamos Query (Mais rápido e eficiente)
            response = await dynamo_table.query(
                KeyConditionExpression=Key('user_id').eq(query_user_id),
                ScanIndexForward=False 
            )
            items = response.get('Items', [])
        else:
            # Sem Partition Key, é necessário fazer um Scan
            response = await dynamo_table.scan()
            items = response.get('Items', [])
            items.sort(key=lambda x: x.get('detected_at', ''), reverse=True)

    # Convertendo tipos do DynamoDB de volta para o padrão da API e aplicando offset/limit
    sliced_items = items[offset : offset + limit]
    for item in sliced_items:
        if isinstance(item.get('risk_score'), Decimal):
            item['risk_score'] = float(item['risk_score'])
            
    return sliced_items


async def delete_log_query(user_id, detected_at):
    """Deleta um log específico do DynamoDB."""
    async with boto_session.resource('dynamodb') as dynamodb:
        dynamo_table = await dynamodb.Table(DYNAMO_TABLE_NAME)
        await dynamo_table.delete_item(Key={"user_id": user_id, "detected_at": detected_at})
    return {"status": "deleted", "log": {"user_id": user_id, "detected_at": detected_at}}


async def delete_all_logs():
    """Limpa todos os registros da tabela de logs do DynamoDB."""
    try:
        print(f"Iniciando a limpeza da tabela...")
        items = []
        
        async with boto_session.resource('dynamodb') as dynamodb:
            dynamo_table = await dynamodb.Table(DYNAMO_TABLE_NAME)
            
            # Escaneia a tabela buscando APENAS as chaves primárias
            scan = await dynamo_table.scan(ProjectionExpression="user_id, detected_at")
            items.extend(scan.get('Items', []))
            
            while 'LastEvaluatedKey' in scan:
                scan = await dynamo_table.scan(
                    ProjectionExpression="user_id, detected_at",
                    ExclusiveStartKey=scan['LastEvaluatedKey']
                )
                items.extend(scan.get('Items', []))
                
            if not items:
                print("A tabela já está totalmente vazia.")
                return {"success": True, "message": "A tabela já estava vazia.", "deleted_count": 0}
                
            # Deleção assíncrona item a item
            for item in items:
                await dynamo_table.delete_item(
                    Key={
                        'user_id': item['user_id'],
                        'detected_at': item['detected_at']
                    }
                )
                
        print(f"Limpeza concluída com sucesso! Total de itens removidos: {len(items)}")
        return {"success": True, "deleted_count": len(items)}
        
    except Exception as e:
        print(f"Erro ao tentar limpar a tabela do DynamoDB: {str(e)}")
        return {"success": False, "error": str(e)}
# =====================================================================
# LÓGICA DO POSTGRESQL AIVEN (FALLBACK)
# =====================================================================

# def get_connection():
#     """Estabelece conexao com o PostgreSQL do Aiven."""
#     try:
#         return psycopg2.connect(AIVEN_URI)
#     except Exception as e:
#         print(f"Erro ao conectar no Aiven: {e}")
#         return None

# def get_or_create_user(conn, device_id):
#     with conn.cursor() as cur:
#         cur.execute("SELECT id FROM users WHERE device_id = %s", (device_id,))
#         row = cur.fetchone()
#         if row: return row[0]
#         user_id = str(uuid.uuid4())
#         cur.execute(
#             "INSERT INTO users (id, device_id, vulnerability_score) VALUES (%s, %s, %s) RETURNING id",
#             (user_id, device_id, 0.0)
#         )
#         return cur.fetchone()[0]

# def update_user_vulnerability_score(conn, user_id):
#     with conn.cursor() as cur:
#         cur.execute(
#             """
#             UPDATE users SET vulnerability_score = COALESCE((
#                 SELECT AVG(risk_score) FROM fraud_logs WHERE user_id = %s
#             ), 0) WHERE id = %s
#             """, (user_id, user_id)
#         )

# def register_fraud_log_postgres(device_id, content, score, is_fraud, explanation=None, source=None):
#     conn = get_connection()
#     if not conn:
#         return {"success": False, "user_id": None, "error": "Aiven offline"}
#     try:
#         user_id = get_or_create_user(conn, device_id)
#         fraud_log_id = str(uuid.uuid4())
#         with conn.cursor() as cur:
#             cur.execute(
#                 """
#                 INSERT INTO fraud_logs (id, user_id, content, risk_score, is_fraud, explanation, source)
#                 VALUES (%s, %s, %s, %s, %s, %s, %s)
#                 """,
#                 (fraud_log_id, user_id, content, float(score), is_fraud, explanation, source)
#             )
#         update_user_vulnerability_score(conn, user_id)
#         conn.commit()
#         return {"success": True, "user_id": str(user_id), "database": "aiven"}
#     except Exception as e:
#         print(f"Erro Postgres: {e}")
#         conn.rollback()
#         return {"success": False, "user_id": None}
#     finally:
#         conn.close()

# def get_fraud_logs_postgres(device_id=None, user_id=None, limit=50, offset=0):
#     conn = get_connection()
#     if not conn:
#         return {"error": "Falha de conexao com Aiven", "data": []}
#     try:
#         cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
#         query = """
#             SELECT fl.id, fl.user_id, fl.content, fl.risk_score, fl.is_fraud, 
#                    fl.explanation, fl.source, fl.detected_at
#             FROM fraud_logs fl JOIN users u ON u.id = fl.user_id
#         """
#         params, filters = [], []
#         if device_id:
#             filters.append("u.device_id = %s")
#             params.append(device_id)
#         if user_id:
#             filters.append("fl.user_id = %s")
#             params.append(user_id)
#         if filters:
#             query += " WHERE " + " AND ".join(filters)
        
#         query += " ORDER BY fl.detected_at DESC LIMIT %s OFFSET %s"
#         params.extend([limit, offset])
#         cur.execute(query, tuple(params))
#         return [dict(row) for row in cur.fetchall()]
#     except Exception as e:
#         print(f"Erro Postgres consulta: {e}")
#         return {"error": "Erro interno ao buscar os dados do Aiven", "data": []}
#     finally:
#         if conn:
#             conn.close()


# # =====================================================================
# # ENTRYPOINTS EXPORTADOS (ROTEAMENTO HYBRID)
# # =====================================================================

# def register_fraud_log(device_id, content, score, is_fraud, explanation=None, source=None):
#     """Tenta salvar no DynamoDB primário. Se falhar, realiza fallback para o Aiven."""
#     try:
#         return register_fraud_log_dynamo(device_id, content, score, is_fraud, explanation, source)
#     except (BotoCoreError, ClientError, Exception) as dynamo_err:
#         print(f"[ALERTA] Falha ao escrever no DynamoDB: {dynamo_err}. Acionando Fallback Aiven...")
#         return register_fraud_log_postgres(device_id, content, score, is_fraud, explanation, source)


# def get_fraud_logs(device_id=None, user_id=None, limit=50, offset=0):
#     """Tenta ler do DynamoDB primário. Se falhar, realiza fallback para o Aiven."""
#     try:
#         return get_fraud_logs_dynamo(device_id, user_id, limit, offset)
#     except (BotoCoreError, ClientError, Exception) as dynamo_err:
#         print(f"[ALERTA] Falha ao ler do DynamoDB: {dynamo_err}. Acionando Fallback Aiven...")
#         return get_fraud_logs_postgres(device_id, user_id, limit, offset)