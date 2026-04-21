import json
import os
from fraud_detection import check_text_for_fraud 
from database import register_scam_attempt
from model import treat_message_llm
def teste_json():
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
        success = register_scam_attempt(user, content, score, level, is_fraud)
        
        color = "\033[91m" if is_fraud else "\033[92m"
        print(f"{color}[{level}] | Score: {score}\033[0m | Msg: {content[:70]}...")

def teste_llm():
    mensagem = "Sua chave Pix foi agendada para uma transferencia de R$890. Caso nao reconheca, ligue agora para a central de seguranca:(11)XXXX-XXXXX."
    print(treat_message_llm(mensagem))

def main():
    teste_llm()
if __name__ == "__main__":
    main()