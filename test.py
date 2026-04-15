import json
import os
from fraud_detection import check_text_for_fraud 
def main():
    # 1. Garante que a tabela existe (bom para a primeira execução)
    if not os.path.exists('log.json'):
        print("Arquivo log.json não encontrado.")
        return

    with open('log.json', 'r', encoding='utf-8') as f:
        data = json.load(f)
        messages = data if isinstance(data, list) else [data]

    print("--- Processando Mensagens e Salvando no Aiven ---")
    for entry in messages:
        content = entry.get('message_content', '')
        user = entry.get('user_id', 'local_test')
        
        # Chama sua função de análise (Exemplo da Opção 2 ou 3)
        score, is_fraud, level = check_text_for_fraud(content)
        

        # # REGISTRO VIA MÓDULO SEPARADO
        # success = True # register_scam_attempt(user, content, score, level, is_fraud)
        
        color = "\033[91m" if is_fraud else "\033[92m"
        print(f"{color}[{level}] | Score: {score}\033[0m | Msg: {content[:70]}...")

if __name__ == "__main__":
    main()