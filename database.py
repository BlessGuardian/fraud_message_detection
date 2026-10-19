import os
import uuid
from datetime import datetime, timezone,timedelta
from decimal import Decimal
from collections import Counter
import boto3
from boto3.dynamodb.conditions import Key
from dotenv import load_dotenv
import math
from collections import defaultdict

load_dotenv()
DYNAMO_TABLE_NAME = os.getenv("DYNAMO_TABLE_NAME")
AWS_REGION = os.getenv("AWS_REGION","us-east-1")
USERS_TABLE_NAME = os.getenv("USERS_TABLE_NAME")

boto_session = boto3.Session(region_name=AWS_REGION)
dynamodb = boto_session.resource('dynamodb',region_name="us-east-1")
message_logs_table = dynamodb.Table(DYNAMO_TABLE_NAME)
users_table = dynamodb.Table(USERS_TABLE_NAME)

async def calculate_scores():
    """
    Varre os logs de fraude, calcula as estatísticas globais (3 desvios padrões) 
    e atualiza a tabela de utilizadores com o novo score.
    """
    try:
        frauds_per_user = defaultdict(int)
        
        # 1. Varredura de fraudes confirmadas
        response = message_logs_table.scan(
            FilterExpression="is_fraud = :true_val",
            ExpressionAttributeValues={":true_val": True},
            ProjectionExpression="user_id"
        )
        items = response.get('Items', [])
        
        # Paginação caso a tabela de logs já tenha passado de 1MB de dados
        while 'LastEvaluatedKey' in response:
            response = message_logs_table.scan(
                FilterExpression="is_fraud = :true_val",
                ExpressionAttributeValues={":true_val": True},
                ProjectionExpression="user_id",
                ExclusiveStartKey=response['LastEvaluatedKey']
            )
            items.extend(response.get('Items', []))
            
        # 2. Conta fraudes por user_id
        for item in items:
            user_id = item.get('user_id')
            if user_id:
                frauds_per_user[user_id] += 1
                
        if not frauds_per_user:
            return {"status": "success", "message": "Nenhuma fraude registrada. Scores não alterados."}

        # 3. Matemática: Média (μ) e Desvio Padrão (σ)
        valores = list(frauds_per_user.values())
        n = len(valores)
        media = sum(valores) / n
        
        variancia = sum((x - media) ** 2 for x in valores) / n
        desvio_padrao = math.sqrt(variancia)
        
        limite_inferior = media - (3 * desvio_padrao)
        limite_superior = media + (3 * desvio_padrao)
        
        amplitude = limite_superior - limite_inferior
        if amplitude == 0:
            amplitude = 1 

        # 4. Calcula e atualiza o score para cada utilizador
        for user_id, count in frauds_per_user.items():
            
            raw_score = (count - limite_inferior) / amplitude
            final_score = max(0.0, min(raw_score, 1.0))
            
            # Formata para float com 4 casas e depois converte para Decimal exigido pela AWS
            score_aws = Decimal(str(round(final_score, 4)))
            
            # Atualiza o utilizador no DynamoDB
            users_table.update_item(
                Key={'user_id': user_id}, 
                UpdateExpression="SET vulnerability_score = :score",
                ExpressionAttributeValues={":score": score_aws} # <--- CORRIGIDO AQUI
            )

        return {
            "status": "success", 
            "updated_users": len(frauds_per_user),
            "estatisticas": {
                "media": round(media, 2),
                "desvio_padrao": round(desvio_padrao, 2),
                "limites": [round(limite_inferior, 2), round(limite_superior, 2)]
            }
        }

    except Exception as e:
        print(f"Erro ao calcular scores: {e}")
        return {"status": "error", "error": str(e)}

async def get_user_score(user_id: str):
    """
    Busca o score de vulnerabilidade (já pré-calculado) do usuário.
    """
    try:
        # Busca direta e veloz pela Primary Key (user_id)
        response = users_table.get_item(Key={'user_id': user_id}) 
        user = response.get('Item')
        
        if not user:
            return {"success": False, "error": "Usuário não encontrado"}
            
        # Pega o score. Se o cálculo nunca rodou para ele, o padrão de segurança é 0.0
        score_decimal = user.get('vulnerability_score', 0.0)
        
        # Converte do formato Decimal do AWS boto3 para o float nativo do Python 
        # (Isso evita o erro "Object of type Decimal is not JSON serializable" no FastAPI)
        score_float = float(score_decimal)
        
        return {"success": True, "score": score_float}
        
    except Exception as e:
        print(f"Erro ao buscar score: {e}")
        return {"success": False, "error": str(e)}
async def get_fraud_stats(user_id = None):
    """
    Busca os logs e retorna a contagem de golpes agrupada por categoria.
    Se user_id for fornecido, filtra por usuário (Query). 
    Se for None, varre todo o banco (Scan).
    """
    try:
        items = []
        
        if user_id:
            # Busca otimizada apenas para o usuário autenticado
            response = message_logs_table.query(
                KeyConditionExpression=Key('user_id').eq(user_id),
                ProjectionExpression="category"
            )
            items.extend(response.get('Items', []))
        else:
            # Varredura global para a interface web
            response = message_logs_table.scan(
                ProjectionExpression="category"
            )
            items.extend(response.get('Items', []))
            
            # Garante que vai ler todo o banco caso a tabela tenha mais de 1MB de dados
            while 'LastEvaluatedKey' in response:
                response = message_logs_table.scan(
                    ProjectionExpression="category",
                    ExclusiveStartKey=response['LastEvaluatedKey']
                )
                items.extend(response.get('Items', []))

        # Extrai as categorias, tratando valores vazios ou ausentes
        categorias = [
            item.get('category') if item.get('category') else 'Desconhecido' 
            for item in items
        ]
        
        # O Counter agrupa e soma tudo automaticamente
        contagem = dict(Counter(categorias))
        
        # Formata para JSON (lista de dicionários)
        resultado = [
            {"categoria": cat, "quantidade": qtd} 
            for cat, qtd in contagem.items()
        ]
        
        # Ordena da maior quantidade para a menor
        resultado.sort(key=lambda x: x['quantidade'], reverse=True)
        
        return {"success": True, "data": resultado}
        
    except Exception as e:
        print(f"Erro ao buscar estatísticas: {e}")
        return {"success": False, "error": str(e)}

async def register_user_db(device_id: str, email: str, password_hash: str):
    """
    Registra um novo usuário Guardião no banco de dados.
    Retorna o user_id gerado ou um erro se o e-mail já existir.
    """
    id = get_deterministic_user_id(device_id)
    try:
        # Usamos condition expression para evitar sobrescrever um email existente
        response = users_table.put_item(
            Item={
                'email': email,
                'user_id': id,
                'password_hash': password_hash,
                'role': 'default',
                'linked_numbers': [], 
                'created_at': datetime.now(timezone(timedelta(hours=-3))).isoformat(),
                'vulnerability_score': 0.0
            },
            ConditionExpression='attribute_not_exists(id)'
        )
        return {"success": True, "user_id": id}
    except dynamodb.meta.client.exceptions.ConditionalCheckFailedException:
        return {"success": False, "error": "Este celular ja foi cadastrado"}
    except Exception as e:
        return {"success": False, "error": str(e)}

async def get_user(email: str):
    try:
        response = users_table.query(
            IndexName='EmailIndex',
            KeyConditionExpression=Key('email').eq(email)
        )
        items = response.get('Items', [])
        
        return items[0] if items else None
    except Exception as e:
        print(f"Erro ao buscar usuário por email: {e}")
        return None

def get_deterministic_user_id(device_id: str) -> str:
    """
    Gera um UUID consistente baseado no device_id. 
    Evita a necessidade de uma tabela separada apenas para mapear device -> user.
    """
    if not device_id:
        return str(uuid.uuid4())
    return str(uuid.uuid5(uuid.NAMESPACE_OID, device_id))


async def register_fraud_log(device_id, content, score, is_fraud, category, explanation=None, source=None):
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
        "source": source,
        "category": category
    }

    message_logs_table.put_item(Item=item)
        
    return {"success": True, "user_id": user_id, "database": "dynamodb"}


async def get_fraud_logs(limit=None, device_id=None, user_id=None, offset=0):
    """Busca o histórico de logs exclusivamente no DynamoDB."""
    query_user_id = user_id or (get_deterministic_user_id(device_id) if device_id else None)
    
    if query_user_id:
        # Se temos o user_id, usamos Query (Mais rápido e eficiente)
        response = message_logs_table.query(
            KeyConditionExpression=Key('user_id').eq(query_user_id),
            ScanIndexForward=False 
        )
        items = response.get('Items', [])
    else:
        # Sem Partition Key, é necessário fazer um Scan
        response = message_logs_table.scan()
        items = response.get('Items', [])
        items.sort(key=lambda x: x.get('detected_at', ''), reverse=True)
    if limit is None or limit <= 0:
        sliced_items = items[offset:]
    else:
        sliced_items = items[offset : offset + limit]

    for item in sliced_items:
        if isinstance(item.get('risk_score'), Decimal):
            item['risk_score'] = float(item['risk_score'])
            
    return sliced_items


async def delete_log_query(user_id, detected_at):
    """Deleta um log específico do DynamoDB."""
    message_logs_table.delete_item(Key={"user_id": user_id, "detected_at": detected_at})
    return {"status": "deleted", "log": {"user_id": user_id, "detected_at": detected_at}}


async def delete_all_logs():
    """Limpa todos os registros da tabela de logs do DynamoDB."""
    try:
        print(f"Iniciando a limpeza da tabela...")
        items = []
        

        # Escaneia a tabela buscando APENAS as chaves primárias
        scan = message_logs_table.scan(ProjectionExpression="user_id, detected_at")
        items.extend(scan.get('Items', []))
        
        while 'LastEvaluatedKey' in scan:
            scan = message_logs_table.scan(
                ProjectionExpression="user_id, detected_at",
                ExclusiveStartKey=scan['LastEvaluatedKey']
            )
            items.extend(scan.get('Items', []))
            
        if not items:
            print("A tabela já está totalmente vazia.")
            return {"success": True, "message": "A tabela já estava vazia.", "deleted_count": 0}
            
        # Deleção assíncrona item a item
        for item in items:
            message_logs_table.delete_item(
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