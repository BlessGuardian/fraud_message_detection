import re
from transformers import pipeline
from unicodedata import normalize

classifier = pipeline("sentiment-analysis", model="nlptown/bert-base-multilingual-uncased-sentiment")
# 1. Institucional e Autoridade (Simula confiança e medo)
KEYWORDS_BANCARIO = {
    # Instituições e Termos Genéricos
    "pix": 15, "p1x": 15, "banco": 5, "central": 8, "gerente": 5, 
    "conta": 5, "agência": 5, "nubank": 8, "itau": 8, "bradesco": 8, 
    "caixa": 8, "santander": 8, "inter": 8, "pan": 8, "safra": 8,
    
    # Segurança e Autenticação (Vetor de Fraude)
    "token": 12, "dispositivo": 10, "biometria": 10, "valide": 12, 
    "cadastre": 12, "exige": 10, "verificação": 10, "sincronização": 12,
    "chave": 5, "senha": 10, "assinatura digital": 12,
    
    # Jurídico e Órgãos (Ataque de Autoridade)
    "procuradoria": 18, "receita": 18, "serasa": 15, "spc": 15, 
    "cartorio": 15, "protesto": 18, "cpf": 8, "penhora": 22, 
    "judicial": 20, "extrajudicial": 20, "intimacao": 18, "policia": 15,
    "investigado": 15, "divida": 10, "acordo": 10, "limpar nome": 12
}

# 2. Gatilhos de Urgência e Coação (Ataque Psicológico)
KEYWORDS_URGENCIA = {
    "urgente": 18, "bloqueio": 20, "bloqueada": 20, "cancelamento": 15,
    "imediatamente": 12, "agora": 10, "suspensa": 15, "irregularidade": 15,
    "tentativa": 10, "acesso suspeito": 18, "evitar": 12, "multa": 12, 
    "expira": 15, "prazo": 12, "logo": 15, "hoje": 5, "recadastramento": 18,
    "obrigatório": 18, "notificacao": 10, "alerta": 10, "atencao": 10,
    "concluir": 8, "atualizacao": 10, "pendencia": 15, "vencimento": 10,
    "nas proximas": 12, "instantes": 10, "agendada": 10
}

# 3. Engenharia Social de Interação (Mão Fantasma / Falso Filho)
KEYWORDS_REMOTO = {
    # Acesso Remoto
    "anydesk": 35, "teamviewer": 35, "rustdesk": 35, "suporte": 15, 
    "instale": 20, "acesso remoto": 30, "modulo": 20, "instalação": 15,
    "espelhamento": 25, "compartilhar tela": 25, "ajuda técnica": 12,
    
    # Golpe Familiar (Falso Filho)
    "mae": 7, "pai": 7, "vovo": 15, "vovó": 15, "vovô": 15, 
    "celular quebrou": 25, "numero novo": 20, "conserto": 10, 
    "me adiciona": 10, "salva meu numero": 15, "consegue pagar": 15,
    
    # Falso Motoboy / Cartão
    "motoboy": 25, "recolher": 20, "entregar": 15, "chip": 15, 
    "cortar": 15, "devolver": 10, "clonado": 20, "compra suspeita": 18
}
KEYWORDS_PROMESSA = {
    "ganhe": 12, "vaga de emprego": 18, "trabalhando em casa": 18,
    "renda extra": 18, "comissão": 12, "investimento": 12, "lucro": 12,
    "milhas": 12, "cupom": 10, "inss": 18, "benefício": 15, "auxilio": 15,
    "liberado": 12, "sacar": 12, "herança": 25, "premio": 15, "sorteio": 15,
    "promocao": 10, "desconto": 10, "vagas": 10, "curtir videos": 20,
    "avaliar": 15, "dinheiro facil": 20, "dobrar": 15
}
KEYWORDS_ACAO = {
    "faça": 10, "realize": 10, "transfira": 15, "envie": 10, 
    "digite": 8, "informe": 10, "clique": 15, "acesse": 15, 
    "confirme": 10, "autorize": 15, "copie": 12, "cole": 12, "ligue":12
}

# 4. Regex para detecção de Links
URL_PATTERN = r"(https?://[^\s]+|bit\.ly/[^\s]+|t\.me/[^\s]+|tinyurl\.com/[^\s]+)"


def deep_normalize(text):
    # 1. Converte para minúsculo
    text = text.lower()
    text = text.replace('p1x', 'pix').replace('p|x', 'pix')
    # 2. Remove acentos (Ex: "cartão" -> "cartao")
    text = normalize('NFKD', text).encode('ASCII', 'ignore').decode('ASCII')
    clean_pattern = re.compile(r'[^a-z0-9\s]')
    text = clean_pattern.sub('', text)
    return text

def check_text_for_fraud(text):
    score = 0
    is_fraud = False
    has_link = bool(re.search(URL_PATTERN, text.lower()))
    # --- PASSO A: Análise de Intenção via IA ---
    # 1 ou 2 estrelas indicam teor negativo/urgente/agressivo
    result = classifier(text[:512])[0]
    if result['label'] == '1 star': 
        score += 45
    elif result['label'] == '2 stars': 
        score += 25
    clean_text = deep_normalize(text)
    # --- PASSO B: Soma de Keywords ---
    # Unificando as listas para somar ao score 0 inicial
    all_keywords = {**KEYWORDS_BANCARIO, **KEYWORDS_URGENCIA, **KEYWORDS_REMOTO, **KEYWORDS_PROMESSA,**KEYWORDS_ACAO}
    for word, weight in all_keywords.items():
        if word in clean_text:
            score += weight
    
    has_urgency = any(w in clean_text for w in KEYWORDS_URGENCIA)
    has_bank = any(w in clean_text for w in KEYWORDS_BANCARIO)
    has_action = any(w in clean_text for w in KEYWORDS_ACAO) 
    

    # --- PASSO C: Verificação de Links ---
    if has_link:
        score += 25
        if has_urgency or has_bank:
            score += 20
    elif has_action and (has_bank or has_urgency):
        score += 20
    elif result['label'] == '5 stars'and not has_bank:
        score = score * 0.6

    # --- PASSO D: Classificação Final ---
    final_score = min(score, 100) # Garante que não passe de 100 para o DB
     
    
    # Define o risk_level baseado no score
    if final_score > 75:
        level = "CRÍTICO"
        is_fraud = True
    elif final_score >= 55:
        level = "ALTO"
        is_fraud = True
    elif final_score >= 35:
        level = "MÉDIO"
    else:
        level = "BAIXO"
    
    return final_score, is_fraud, level


