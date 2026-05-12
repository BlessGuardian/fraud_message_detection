import os
import uuid

import psycopg2
import psycopg2.extras
from dotenv import load_dotenv

load_dotenv()
AIVEN_URI = os.getenv("AIVEN_URI")


def get_connection():
    """Estabelece conexao com o PostgreSQL do Aiven."""
    try:
        return psycopg2.connect(AIVEN_URI)
    except Exception as e:
        print(f"Erro ao conectar no Aiven: {e}")
        return None


def get_or_create_user(conn, device_id):
    """Resolve o device_id anonimo do Android para o UUID interno de users."""
    with conn.cursor() as cur:
        cur.execute("SELECT id FROM users WHERE device_id = %s", (device_id,))
        row = cur.fetchone()
        if row:
            return row[0]

        user_id = str(uuid.uuid4())
        cur.execute(
            """
                INSERT INTO users (id, device_id, vulnerability_score)
                VALUES (%s, %s, %s)
                RETURNING id
            """,
            (user_id, device_id, 0.0)
        )
        return cur.fetchone()[0]


def update_user_vulnerability_score(conn, user_id):
    """Atualiza o score de vulnerabilidade pela media historica do usuario."""
    with conn.cursor() as cur:
        cur.execute(
            """
                UPDATE users
                SET vulnerability_score = COALESCE((
                    SELECT AVG(risk_score)
                    FROM fraud_logs
                    WHERE user_id = %s
                ), 0)
                WHERE id = %s
            """,
            (user_id, user_id)
        )


def register_fraud_log(device_id, content, score, is_fraud, explanation=None, source=None):
    """
    Insere o resultado da analise em fraud_logs.

    O Android envia device_id. O backend encontra/cria users.id e grava
    fraud_logs.user_id apontando para esse UUID interno.
    """
    conn = get_connection()
    if not conn:
        return {"success": False, "user_id": None}

    try:
        user_id = get_or_create_user(conn, device_id)
        risk_score_float = float(score)
        fraud_log_id = str(uuid.uuid4())

        with conn.cursor() as cur:
            cur.execute(
                """
                    INSERT INTO fraud_logs (
                        id, user_id, content, risk_score, is_fraud, explanation, source
                    )
                    VALUES (%s, %s, %s, %s, %s, %s, %s)
                """,
                (
                    fraud_log_id,
                    user_id,
                    content,
                    risk_score_float,
                    is_fraud,
                    explanation,
                    source
                )
            )

        update_user_vulnerability_score(conn, user_id)
        conn.commit()
        return {"success": True, "user_id": str(user_id)}
    except psycopg2.Error as e:
        print(f"Erro na insercao: {e}")
        conn.rollback()
        return {"success": False, "user_id": None}
    except ValueError as e:
        print(f"Erro de tipo de dado: O score deve ser um numero valido. {e}")
        conn.rollback()
        return {"success": False, "user_id": None}
    except Exception as e:
        print(f"Erro inesperado: {e}")
        conn.rollback()
        return {"success": False, "user_id": None}
    finally:
        conn.close()


def get_fraud_logs(device_id=None, user_id=None, limit=50, offset=0):
    """
    Consulta fraud_logs.

    device_id filtra pelo identificador anonimo do Android.
    user_id filtra pelo UUID interno de users.
    """
    conn = get_connection()
    if not conn:
        return {"error": "Falha de conexao com o banco de dados", "data": []}

    try:
        cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        query = """
            SELECT
                fl.id,
                fl.user_id,
                fl.content,
                fl.risk_score,
                fl.is_fraud,
                fl.explanation,
                fl.source,
                fl.detected_at
            FROM fraud_logs fl
            JOIN users u ON u.id = fl.user_id
        """
        params = []
        filters = []

        if device_id:
            filters.append("u.device_id = %s")
            params.append(device_id)

        if user_id:
            filters.append("fl.user_id = %s")
            params.append(user_id)

        if filters:
            query += " WHERE " + " AND ".join(filters)

        query += " ORDER BY fl.detected_at DESC LIMIT %s OFFSET %s"
        params.extend([limit, offset])

        cur.execute(query, tuple(params))
        records = cur.fetchall()
        return [dict(row) for row in records]
    except psycopg2.Error as e:
        print(f"Erro na consulta de logs: {e}")
        return {"error": "Erro interno ao buscar os dados", "data": []}
    except Exception as e:
        print(f"Erro inesperado: {e}")
        return {"error": "Erro inesperado", "data": []}
    finally:
        if conn:
            if "cur" in locals():
                cur.close()
            conn.close()
