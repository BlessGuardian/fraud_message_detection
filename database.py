import os
import psycopg2
import psycopg2.extras
from dotenv import load_dotenv

# Carrega a URI do .env
load_dotenv()
AIVEN_URI = os.getenv('AIVEN_URI')

def get_connection():
    """Estabelece conexão com o PostgreSQL do Aiven."""
    try:
        return psycopg2.connect(AIVEN_URI)
    except Exception as e:
        print(f"Erro ao conectar no Aiven: {e}")
        return None

def register_fraud_log(user_id, content, score, is_fraud, explanation=None, source=None):
    """
    Insere o resultado da análise na tabela fraud_logs, respeitando o esquema.
    
    Parâmetros:
    - user_id: O UUID do usuário (em formato de string). Deve ser um UUID válido.
    - content: O conteúdo da mensagem (texto).
    - score: A pontuação de risco (número de precisão dupla / FLOAT8).
    - is_fraud: Se foi detectado como fraude (booleano).
    - explanation: Explicação do risco (texto, opcional).
    - source: Fonte da análise (VARCHAR(50), opcional).
    """
    conn = get_connection()
    if not conn:
        return False
    
    try:
        cur = conn.cursor()
        risk_score_float = float(score)

        query = """
            INSERT INTO fraud_logs(user_id, content, risk_score, is_fraud, explanation, source)
            VALUES (%s, %s, %s, %s, %s, %s)
        """
        
        cur.execute(query, (user_id, content, risk_score_float, is_fraud, explanation, source))
        conn.commit()
        cur.close()
        return True
    except psycopg2.Error as e:
        # Captura erros do banco de dados, como falhas de chave estrangeira (se o user_id não existir)
        # ou problemas de tipo de dados.
        print(f"Erro na inserção: {e}")
        conn.rollback() # Reverte a transação em caso de erro
        return False
    except ValueError as e:
        print(f"Erro de tipo de dado: O score deve ser um número válido. {e}")
        return False
    except Exception as e:
        print(f"Erro inesperado: {e}")
        return False
    finally:
        conn.close()

def get_fraud_logs(user_id=None, limit=50, offset=0):
    """
    Consulta a tabela fraud_logs. Ideal para rotas GET da API.
    
    Parâmetros:
    - user_id (str, opcional): O UUID do usuário para filtrar os logs.
    - limit (int): Quantidade máxima de registros a retornar (paginação).
    - offset (int): Quantos registros pular (paginação).
    
    Retorna:
    - Uma lista de dicionários com os dados, prontos para serem transformados em JSON.
    """
    conn = get_connection()
    if not conn:
        # Retornamos uma lista vazia ou podemos levantar uma exceção dependendo do padrão da sua API
        return {"error": "Falha de conexão com o banco de dados", "data": []}
    
    try:
        # Usamos o RealDictCursor para que cada linha retorne como um dicionário
        # Ex: {"id": "...", "content": "...", "risk_score": 0.9}
        cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        
        # Base da consulta
        query = """
            SELECT 
                id, user_id, content, risk_score, is_fraud, 
                explanation, source, detected_at
            FROM fraud_logs
        """
        params = []
        
        # Adiciona filtro por usuário, se fornecido na requisição GET
        if user_id:
            query += " WHERE user_id = %s"
            params.append(user_id)
            
        # Adiciona ordenação (mais recentes primeiro) e paginação
        query += " ORDER BY detected_at DESC LIMIT %s OFFSET %s"
        params.extend([limit, offset])
        
        # Executa a query
        cur.execute(query, tuple(params))
        
        # Busca todos os resultados correspondentes
        records = cur.fetchall()
        
        # Converter os RealDictRows para dicionários Python padrão
        results = [dict(row) for row in records]
        
        return results

    except psycopg2.Error as e:
        print(f"Erro na consulta de logs: {e}")
        return {"error": "Erro interno ao buscar os dados", "data": []}
    except Exception as e:
        print(f"Erro inesperado: {e}")
        return {"error": "Erro inesperado", "data": []}
    finally:
        if conn:
            cur.close()
            conn.close()