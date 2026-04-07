import os
import psycopg2
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

def register_scam_attempt(user_id, content, score, level, is_fraud):
    """Insere o resultado da análise na tabela scam_attempts."""
    conn = get_connection()
    if not conn:
        return False
    
    try:
        cur = conn.cursor()
        query = """
            INSERT INTO scam_attempts (user_id, message_content, risk_score, risk_level, is_fraud)
            VALUES (%s, %s, %s, %s, %s)
        """
        cur.execute(query, (user_id, content, score, level, is_fraud))
        conn.commit()
        cur.close()
        return True
    except Exception as e:
        print(f"Erro na inserção: {e}")
        return False
    finally:
        conn.close()

def create_table_if_not_exists():
    """Garante que a estrutura do banco existe no Aiven."""
    conn = get_connection()
    if not conn: return
    
    try:
        cur = conn.cursor()
        cur.execute("""
            CREATE TABLE IF NOT EXISTS scam_attempts (
                id SERIAL PRIMARY KEY,
                user_id VARCHAR(100),
                message_content TEXT,
                risk_score INT,
                risk_level VARCHAR(20),
                is_fraud BOOLEAN,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
        """)
        conn.commit()
        cur.close()
    finally:
        conn.close()