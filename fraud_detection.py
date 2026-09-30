import os
import asyncio
import numpy as np
import onnxruntime as ort
from transformers import AutoTokenizer

CAMINHO_MODELO = os.environ.get("ONNX_MODEL_PATH", "./model_onnx")

opcoes_sessao = ort.SessionOptions()
opcoes_sessao.graph_optimization_level = ort.GraphOptimizationLevel.ORT_ENABLE_ALL

opcoes_sessao.intra_op_num_threads = 1
opcoes_sessao.inter_op_num_threads = 1

try:
    print(f"Carregando Tokenizador de: {CAMINHO_MODELO}")
    tokenizer = AutoTokenizer.from_pretrained(CAMINHO_MODELO)
    
    print(f"Carregando Modelo ONNX de: {CAMINHO_MODELO}/model_base.onnx")
    sessao_onnx = ort.InferenceSession(
        f"{CAMINHO_MODELO}/model_quantized.onnx",
        sess=opcoes_sessao,
        providers=["CPUExecutionProvider"]
    )
    print("Modelos carregados com sucesso!")
except Exception as e:
    print(f"Erro fatal ao carregar modelos ONNX: {e}")
    tokenizer = None
    sessao_onnx = None

def _run_onnx_inference_sync(mensagem: str) -> dict:
    """
    Função síncrona que processa a entrada e executa a inferência matemática.
    """
    if sessao_onnx is None or tokenizer is None:
        return {"is_phishing": False, "label": 0, "confianca": 0.0, "erro": "Modelos ONNX não carregados."}

    if not mensagem or not str(mensagem).strip():
        return {"is_phishing": False, "label": 0, "confianca": 0.0, "erro": "Mensagem vazia"}

    try:
        inputs = tokenizer(
            str(mensagem),
            return_tensors="np",  
            padding="max_length",
            truncation=True,
            max_length=128
        )

        entradas_onnx = {
            "input_ids": inputs["input_ids"],
            "attention_mask": inputs["attention_mask"]
        }

        saidas = sessao_onnx.run(None, entradas_onnx)
        logits = saidas[0][0]

        label_previsto = int(np.argmax(logits))

        exp_logits = np.exp(logits - np.max(logits))
        probabilidades = exp_logits / exp_logits.sum()
        confianca = float(probabilidades[label_previsto])

        return {
            "is_phishing": bool(label_previsto == 1),
            "label": label_previsto,
            "confianca": round(confianca, 4)
        }

    except Exception as e:
        return {"is_phishing": False, "label": 0, "confianca": 0.0, "erro": str(e)}

async def analyze_message(mensagem: str) -> dict:
    """
    Wrapper assíncrono que joga a inferência pesada (CPU bound) 
    para uma Thread separada, mantendo o FastAPI (I/O bound) responsivo.
    """
    loop = asyncio.get_running_loop()
    resultado = await loop.run_in_executor(None, _run_onnx_inference_sync, mensagem)
    
    return {
        "is_fraud": resultado.get("label", 0),
        "score": resultado.get("confianca", 0.0),
        "erro": resultado.get("erro")
    }