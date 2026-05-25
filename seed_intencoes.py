"""
Massa de teste — popula todas as intenções no banco.
Uso: python seed_intencoes.py
     python seed_intencoes.py --url http://outro-servidor:5000
     python seed_intencoes.py --delay 1.5
"""

import argparse
import time
import requests

DEFAULT_URL = "http://localhost:5000"
DEFAULT_DELAY = 1.2  # segundos entre requests (respeita rate limit de 30/min)

MENSAGENS: dict[str, list[str]] = {

    "lead": [
        "Quero contratar um agente de IA para minha empresa. Como faço?",
        "Quanto custa criar uma automação de processos?",
        "Gostaria de solicitar uma proposta para automatizar o meu setor financeiro.",
        "Tenho interesse em agendar uma reunião com o time comercial de vocês.",
        "Preciso de um agente de IA para atendimento ao cliente. Quero começar logo.",
        "Qual o investimento para ter um projeto de RPA na minha empresa?",
        "Vocês fazem automação para e-commerce? Quero contratar.",
    ],

    "duvida": [
        "Como funciona o processo de criação de um agente de IA?",
        "Qual a diferença entre RPA e um agente de IA?",
        "Em quanto tempo um projeto de automação fica pronto?",
        "Vocês utilizam LangChain nos projetos de vocês?",
        "O que é RAG e por que é importante para agentes de IA?",
        "Quais tecnologias a Z-IT Connect usa nos projetos?",
        "Vocês atendem empresas de pequeno porte?",
        "A Z-IT Connect tem cases de automação na área de saúde?",
    ],

    "elogio": [
        "O Claudio me atendeu muito bem, parabéns pela iniciativa!",
        "Adorei a rapidez nas respostas, o agente é excelente.",
        "Muito bom o serviço de vocês, estou impressionado.",
        "Parabéns pela qualidade do atendimento automatizado!",
        "O agente de vocês é muito mais inteligente do que eu esperava.",
        "Ótimo trabalho, a Z-IT Connect é referência em IA.",
    ],

    "reclamacao": [
        "O agente não soube responder minha pergunta sobre preços.",
        "Não gostei, fiquei sem resposta sobre o prazo do projeto.",
        "O chatbot de vocês não me ajudou direito, decepcionante.",
        "Tive dificuldade em entender as informações que o agente passou.",
        "A resposta demorou muito e ainda ficou incompleta.",
    ],

    "saudacao": [
        "Oi, tudo bem?",
        "Olá! Bom dia.",
        "Boa tarde, pode me ajudar?",
        "Oi Claudio, como vai?",
        "Olá, estou aqui para tirar algumas dúvidas.",
        "Bom dia! Vim conhecer melhor a Z-IT Connect.",
    ],
}


def enviar(url: str, mensagem: str, intencao_esperada: str, delay: float) -> dict:
    time.sleep(delay)
    try:
        r = requests.post(
            f"{url}/api/perguntar",
            json={"pergunta": mensagem},
            timeout=45,
        )
        data = r.json() if r.content else {}
        intencao_real = data.get("intencao", "—")
        ok = "✅" if intencao_real == intencao_esperada else "⚠️"
        print(
            f"  {ok} [{intencao_esperada:10s} → {intencao_real:10s}] "
            f"HTTP {r.status_code} | {mensagem[:55]!r}"
        )
        return {"esperada": intencao_esperada, "real": intencao_real, "status": r.status_code}
    except Exception as exc:
        print(f"  ❌ ERRO [{intencao_esperada}] {mensagem[:40]!r} — {exc}")
        return {"esperada": intencao_esperada, "real": "erro", "status": 0}


def main():
    parser = argparse.ArgumentParser(description="Seed de intenções — Z-IT Connect")
    parser.add_argument("--url",   default=DEFAULT_URL)
    parser.add_argument("--delay", default=DEFAULT_DELAY, type=float)
    args = parser.parse_args()

    total = sum(len(v) for v in MENSAGENS.values())
    print(f"\nEnviando {total} mensagens para {args.url}/api/perguntar")
    print(f"Delay entre requests: {args.delay}s\n")

    resultados = []
    for intencao, msgs in MENSAGENS.items():
        print(f"── {intencao.upper()} ({len(msgs)} mensagens) ──")
        for msg in msgs:
            resultados.append(enviar(args.url, msg, intencao, args.delay))
        print()

    # Resumo
    acertos = sum(1 for r in resultados if r["real"] == r["esperada"])
    erros   = sum(1 for r in resultados if r["real"] == "erro")
    print("=" * 60)
    print(f"  Total enviado : {len(resultados)}")
    print(f"  Intenção correta : {acertos}/{len(resultados) - erros}")
    print(f"  Erros de conexão : {erros}")
    print("=" * 60)
    print("\nAtualize o analytics para ver o gráfico populado.\n")


if __name__ == "__main__":
    main()
