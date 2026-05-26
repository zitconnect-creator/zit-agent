import os
import hmac
import logging
import threading
import requests
from collections import defaultdict
from datetime import datetime, timedelta, timezone

from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS
from agent import AgenteLocacaoMotos
import security

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)

app = Flask(__name__)
CORS(app, resources={r"/api/*": {"origins": "*"}})
agente = AgenteLocacaoMotos()

_SOFT_BLOCK_MSG = (
    "Não consigo processar essa solicitação. "
    "Para dúvidas sobre os serviços da Z-IT Connect, acesse zitconnect.com 😊"
)


def _security_block(layer: str, reason: str):
    """Resposta padronizada para bloqueio de segurança."""
    logger.warning("SECURITY BLOCK [%s] motivo=%s ip=%s", layer, reason, request.remote_addr)
    return jsonify({
        "respondeu": False,
        "resposta": None,
        "score": 0.0,
        "score_status": "blocked",
        "documentos_usados": [],
        "session_id": "",
        "intencao": "blocked",
        "capturar_lead": False,
        "mensagem": _SOFT_BLOCK_MSG,
    }), 400


# ─── Chat ─────────────────────────────────────────────────────────────────────

@app.route("/")
def index():
    return send_from_directory(BASE_DIR, "index.html")


@app.route("/api/saudacao", methods=["GET"])
def saudacao():
    rate = security.check_ip(request.remote_addr)
    if not rate.is_allowed:
        return jsonify({"erro": "Muitas requisições. Tente novamente em instantes."}), 429
    return jsonify({"mensagem": agente.saudar()})


@app.route("/api/perguntar", methods=["POST"])
def perguntar():
    data = request.get_json(silent=True) or {}
    pergunta = (data.get("pergunta") or "").strip()
    telefone = (data.get("telefone") or "").strip() or None
    ip = request.remote_addr

    if not pergunta:
        return jsonify({"erro": "Pergunta não pode ser vazia."}), 400

    # ── Camada 5: Rate limit ──────────────────────────────────────────────────
    rate = security.check_ip(ip)
    if not rate.is_allowed:
        return jsonify({"erro": "Muitas requisições. Tente novamente em instantes."}), 429

    if telefone:
        rate_phone = security.check_phone(telefone)
        if not rate_phone.is_allowed:
            return jsonify({"erro": "Muitas requisições. Tente novamente em instantes."}), 429

    # ── Camada 1: Sanitizador ─────────────────────────────────────────────────
    san = security.sanitize(pergunta)
    if not san.is_safe:
        security.penalize_attacker(ip=ip, phone=telefone)
        return _security_block("sanitizer", san.reason)
    pergunta = san.cleaned_text

    # ── Camada 2: Guardrail LLM ───────────────────────────────────────────────
    guard = security.classify(pergunta)
    if not guard.is_safe:
        security.penalize_attacker(ip=ip, phone=telefone)
        return _security_block("guardrail", guard.category)

    # ── Camada 3: Agente ──────────────────────────────────────────────────────
    resultado = agente.responder(pergunta, telefone=telefone)

    # ── Camada 4: Validador de output ─────────────────────────────────────────
    if resultado.resposta:
        val = security.validate_output(resultado.resposta)
        if not val.is_valid:
            resultado.resposta = val.safe_output
            resultado.respondeu = False
            resultado.score_status = "blocked"

    return jsonify({
        "respondeu": resultado.respondeu,
        "resposta": resultado.resposta,
        "score": round(resultado.score, 4),
        "score_status": resultado.score_status,
        "documentos_usados": resultado.documentos_usados,
        "session_id": resultado.session_id,
        "intencao": resultado.intencao,
        "capturar_lead": resultado.capturar_lead,
    })


# ─── Error handlers ───────────────────────────────────────────────────────────

@app.errorhandler(404)
def not_found(e):
    return jsonify({"erro": "Rota não encontrada"}), 404

@app.errorhandler(500)
def server_error(e):
    return jsonify({"erro": str(e)}), 500


# ─── Analytics ────────────────────────────────────────────────────────────────

@app.route("/api/ping")
def ping():
    return jsonify({"ok": True})


@app.route("/api/lead", methods=["POST"])
def salvar_lead():
    rate = security.check_ip(request.remote_addr)
    if not rate.is_allowed:
        return jsonify({"erro": "Muitas requisições. Tente novamente em instantes."}), 429

    data = request.get_json(silent=True) or {}
    nome     = (data.get("nome") or "").strip()
    telefone = (data.get("telefone") or "").strip()
    plano    = (data.get("plano") or "").strip()
    session_id       = data.get("session_id", "")
    mensagem_original = data.get("mensagem_original", "")

    if not nome or not telefone:
        return jsonify({"erro": "Nome e telefone são obrigatórios."}), 400

    try:
        agente.supabase.table("leads").insert({
            "nome": nome,
            "telefone": telefone,
            "plano_interesse": plano or None,
            "session_id": session_id,
            "mensagem_original": mensagem_original,
            "status": "novo",
        }).execute()
    except Exception as exc:
        logging.error("Erro ao salvar lead: %s", exc)
        return jsonify({"erro": "Falha ao registrar lead."}), 500

    _notificar_vendas(nome, telefone, plano)

    return jsonify({"ok": True})


def _notificar_vendas(nome: str, telefone: str, plano: str) -> None:
    """Envia WhatsApp para o vendedor via Evolution API."""
    url     = os.getenv("EVOLUTION_URL")
    api_key = os.getenv("EVOLUTION_API_KEY")
    numero  = os.getenv("EVOLUTION_NUMERO_VENDAS")

    if not all([url, api_key, numero]):
        logging.info("Evolution API não configurada — notificação WhatsApp ignorada.")
        return

    plano_str = f"Serviço: {plano}" if plano else "Serviço: não informado"
    mensagem = (
        f"🤖 *Novo Lead Z-IT Connect!*\n\n"
        f"👤 Nome: {nome}\n"
        f"📱 WhatsApp: {telefone}\n"
        f"📋 {plano_str}\n\n"
        f"_Lead capturado pelo Claudio agora mesmo._"
    )

    instancia = os.getenv("EVOLUTION_INSTANCIA", "ZIT")
    try:
        requests.post(
            f"{url}/message/sendText/{instancia}",
            json={"number": numero, "text": mensagem},
            headers={"apikey": api_key},
            timeout=8,
        )
        logging.info("Notificação de lead enviada para %s", numero)
    except Exception as exc:
        logging.warning("Falha ao enviar notificação de lead: %s", exc)

@app.route("/analytics")
def analytics():
    return send_from_directory(BASE_DIR, "analytics.html")


@app.route("/api/analytics/resumo")
@security.require_admin_key
def analytics_resumo():
    """KPIs gerais: totais, taxa de resposta, score médio, distribuição por status."""
    try:
        sb = agente.supabase
        todos = sb.table("zit_interacoes").select("score_status, score_rag, criado_em").execute().data or []
    except Exception as exc:
        logging.error("Erro ao buscar zit_interacoes: %s", exc)
        return jsonify({"erro": str(exc)}), 500

    hoje = datetime.now(timezone.utc).date().isoformat()
    por_status = {"respondido": 0, "baixa_confianca": 0, "sem_resultado": 0}
    scores, total_hoje = [], 0

    for row in todos:
        status = row.get("score_status") or "sem_resultado"
        if status in por_status:
            por_status[status] += 1
        if row.get("score_rag") is not None:
            scores.append(row["score_rag"])
        if (row.get("criado_em") or "").startswith(hoje):
            total_hoje += 1

    total = len(todos)
    taxa = round(por_status["respondido"] / total * 100, 1) if total else 0
    score_medio = round(sum(scores) / len(scores), 4) if scores else 0

    return jsonify({
        "total": total,
        "hoje": total_hoje,
        "taxa_resposta": taxa,
        "score_medio": score_medio,
        "por_status": por_status,
    })


@app.route("/api/analytics/historico")
@security.require_admin_key
def analytics_historico():
    """Interações por dia nos últimos N dias (padrão 7, máx 30)."""
    dias = min(int(request.args.get("dias", 7)), 30)
    try:
        sb = agente.supabase
        desde = (datetime.now(timezone.utc) - timedelta(days=dias)).isoformat()
        rows = (
            sb.table("zit_interacoes")
            .select("score_status, score_rag, criado_em")
            .gte("criado_em", desde)
            .execute()
            .data
        ) or []
    except Exception as exc:
        logging.error("Erro ao buscar histórico: %s", exc)
        return jsonify({"erro": str(exc)}), 500

    agrupado = defaultdict(lambda: {"total": 0, "respondido": 0, "scores": []})
    for row in rows:
        dia = (row.get("criado_em") or "")[:10]
        if not dia:
            continue
        agrupado[dia]["total"] += 1
        if row.get("score_status") == "respondido":
            agrupado[dia]["respondido"] += 1
        if row.get("score_rag") is not None:
            agrupado[dia]["scores"].append(row["score_rag"])

    # Garante todos os dias no intervalo, mesmo sem dados
    resultado = []
    for i in range(dias):
        dia = (datetime.now(timezone.utc) - timedelta(days=dias - 1 - i)).date().isoformat()
        d = agrupado[dia]
        resultado.append({
            "dia": dia,
            "total": d["total"],
            "respondidas": d["respondido"],
            "score_medio": round(sum(d["scores"]) / len(d["scores"]), 3) if d["scores"] else 0,
        })

    return jsonify(resultado)


@app.route("/api/analytics/nao-respondidas")
@security.require_admin_key
def analytics_nao_respondidas():
    """Últimas 25 perguntas com score baixo ou sem resultado (gap da base de conhecimento)."""
    try:
        sb = agente.supabase
        rows = (
            sb.table("zit_interacoes")
            .select("pergunta, score_rag, score_status, criado_em")
            .in_("score_status", ["sem_resultado", "baixa_confianca"])
            .order("criado_em", desc=True)
            .limit(25)
            .execute()
            .data
        ) or []
    except Exception as exc:
        logging.error("Erro ao buscar não-respondidas: %s", exc)
        return jsonify({"erro": str(exc)}), 500
    return jsonify(rows)


@app.route("/api/leads")
@security.require_admin_key
def listar_leads():
    """Lista todos os leads ordenados por data, para gestão."""
    try:
        rows = (
            agente.supabase.table("leads")
            .select("id, nome, telefone, plano_interesse, mensagem_original, status, criado_em")
            .order("criado_em", desc=True)
            .execute()
            .data
        ) or []
    except Exception as exc:
        logging.error("Erro ao listar leads: %s", exc)
        return jsonify({"erro": str(exc)}), 500
    return jsonify(rows)


@app.route("/api/leads/<lead_id>/status", methods=["PATCH"])
@security.require_admin_key
def atualizar_status_lead(lead_id):
    """Atualiza o status de um lead (novo | contatado | convertido | perdido)."""
    data = request.get_json(silent=True) or {}
    novo_status = (data.get("status") or "").strip().lower()

    if novo_status not in {"novo", "contatado", "convertido", "perdido"}:
        return jsonify({"erro": "Status inválido."}), 400

    try:
        agente.supabase.table("leads").update({"status": novo_status}).eq("id", lead_id).execute()
    except Exception as exc:
        logging.error("Erro ao atualizar status do lead %s: %s", lead_id, exc)
        return jsonify({"erro": "Falha ao atualizar status."}), 500

    return jsonify({"ok": True})


@app.route("/api/analytics/intencoes")
@security.require_admin_key
def analytics_intencoes():
    """Distribuição percentual de intenções detectadas nas interações."""
    try:
        rows = agente.supabase.table("zit_interacoes").select("intencao").execute().data or []
    except Exception as exc:
        # Coluna 'intencao' ainda não existe na tabela — retorna vazio sem quebrar
        logging.warning("Coluna 'intencao' ausente em zit_interacoes (rode o ALTER TABLE): %s", exc)
        return jsonify({"total": 0, "por_intencao": {}, "aviso": "coluna_ausente"})

    por_intencao: dict[str, int] = {}
    for row in rows:
        intencao = (row.get("intencao") or "duvida").strip().lower()
        por_intencao[intencao] = por_intencao.get(intencao, 0) + 1

    total = len(rows)
    return jsonify({"total": total, "por_intencao": por_intencao})


@app.route("/api/analytics/canais")
@security.require_admin_key
def analytics_canais():
    """Contagem de interações por canal: web vs whatsapp."""
    try:
        rows = agente.supabase.table("zit_interacoes").select("canal").execute().data or []
    except Exception as exc:
        logging.error("Erro ao buscar canais: %s", exc)
        return jsonify({"erro": str(exc)}), 500
    contagem = {"web": 0, "whatsapp": 0}
    for row in rows:
        canal = (row.get("canal") or "web").lower()
        contagem[canal] = contagem.get(canal, 0) + 1
    return jsonify(contagem)


@app.route("/api/analytics/leads")
@security.require_admin_key
def analytics_leads():
    """Funil de leads: totais por status e por plano de interesse."""
    try:
        sb = agente.supabase
        rows = sb.table("leads").select("status, plano_interesse, criado_em").execute().data or []
    except Exception as exc:
        logging.error("Erro ao buscar leads: %s", exc)
        return jsonify({"erro": str(exc)}), 500

    hoje = datetime.now(timezone.utc).date().isoformat()
    por_status = {"novo": 0, "contatado": 0, "convertido": 0, "perdido": 0}
    por_plano: dict[str, int] = {}
    total_hoje = 0

    for row in rows:
        status = (row.get("status") or "novo").lower()
        if status in por_status:
            por_status[status] += 1
        plano = row.get("plano_interesse") or "Não informado"
        por_plano[plano] = por_plano.get(plano, 0) + 1
        if (row.get("criado_em") or "").startswith(hoje):
            total_hoje += 1

    total = len(rows)
    taxa = round(por_status["convertido"] / total * 100, 1) if total else 0

    return jsonify({
        "total": total,
        "hoje": total_hoje,
        "por_status": por_status,
        "por_plano": por_plano,
        "taxa_conversao": taxa,
    })


# ─── WhatsApp Webhook ─────────────────────────────────────────────────────────

def _enviar_whatsapp(numero: str, mensagem: str) -> None:
    """Envia uma mensagem de texto via Evolution API."""
    url      = os.getenv("EVOLUTION_URL")
    api_key  = os.getenv("EVOLUTION_API_KEY")
    instancia = os.getenv("EVOLUTION_INSTANCIA", "ZIT")

    if not all([url, api_key]):
        logging.warning("Evolution API não configurada — mensagem não enviada.")
        return

    try:
        requests.post(
            f"{url}/message/sendText/{instancia}",
            json={"number": numero, "text": mensagem},
            headers={"apikey": api_key},
            timeout=10,
        )
        logging.info("WhatsApp enviado para %s", numero)
    except Exception as exc:
        logging.warning("Falha ao enviar WhatsApp para %s: %s", numero, exc)


def _processar_mensagem_wa(telefone: str, texto: str, nome: str = "") -> None:
    """Processa a mensagem e responde via WhatsApp. Roda em thread separada."""
    try:
        # Camada 5: rate limit por telefone
        rate = security.check_phone(telefone)
        if not rate.is_allowed:
            logger.warning("WhatsApp rate limit para %s", telefone[-4:])
            return

        # Camada 1: sanitização
        san = security.sanitize(texto)
        if not san.is_safe:
            security.penalize_attacker(phone=telefone)
            logger.warning("WhatsApp bloqueado [sanitizer/%s] de %s", san.reason, telefone[-4:])
            _enviar_whatsapp(telefone, _SOFT_BLOCK_MSG)
            return
        texto = san.cleaned_text

        # Camada 2: guardrail
        guard = security.classify(texto)
        if not guard.is_safe:
            security.penalize_attacker(phone=telefone)
            logger.warning("WhatsApp bloqueado [guardrail/%s] de %s", guard.category, telefone[-4:])
            _enviar_whatsapp(telefone, _SOFT_BLOCK_MSG)
            return

        resultado = agente.responder(texto, telefone=telefone, canal="whatsapp")

        if resultado.capturar_lead:
            # No WhatsApp o telefone já é conhecido — só pede nome e serviço
            resposta = (
                "Que ótimo, fico feliz com seu interesse na Z-IT Connect! 🚀\n\n"
                "Me diz seu nome e em qual serviço você tem interesse:\n"
                "• Automação de Processos\n"
                "• Criação de Agente de IA\n"
                "• Consultoria em IA\n\n"
                "Nossa equipe entra em contato em breve!"
            )
            _enviar_whatsapp(telefone, resposta)

            # Salva lead com o nome real do contato WhatsApp
            try:
                agente.supabase.table("leads").insert({
                    "telefone": telefone,
                    "nome": nome or "Via WhatsApp",
                    "plano_interesse": None,
                    "mensagem_original": texto,
                    "session_id": telefone,
                    "status": "novo",
                }).execute()
            except Exception as exc:
                logging.warning("Falha ao salvar lead WhatsApp: %s", exc)

        elif resultado.respondeu and resultado.resposta:
            # Camada 4: validação de output
            val = security.validate_output(resultado.resposta)
            _enviar_whatsapp(telefone, val.safe_output)

        else:
            _enviar_whatsapp(
                telefone,
                "Não encontrei informações suficientes sobre isso. "
                "Para mais detalhes, acesse zitconnect.com ou fale com nossa equipe. 😊",
            )

    except Exception as exc:
        logging.error("Erro ao processar mensagem WhatsApp de %s: %s", telefone, exc)


@app.route("/webhook/whatsapp", methods=["POST"])
def webhook_whatsapp():
    """Recebe eventos do Evolution API e responde mensagens recebidas."""
    webhook_token = os.getenv("EVOLUTION_WEBHOOK_TOKEN", "")
    if webhook_token:
        provided = request.headers.get("apikey", "") or request.headers.get("Authorization", "")
        if not hmac.compare_digest(provided, webhook_token):
            logger.warning("Webhook rejeitado — token inválido de %s", request.remote_addr)
            return jsonify({"ok": False}), 401

    data  = request.get_json(silent=True) or {}
    event = data.get("event", "")

    # Só processa eventos de mensagem nova
    if event not in ("messages.upsert", "MESSAGES_UPSERT"):
        return jsonify({"ok": True})

    msg_data   = data.get("data", {})
    key        = msg_data.get("key", {})
    remote_jid = key.get("remoteJid", "")

    # Ignora mensagens enviadas pelo próprio bot e mensagens de grupo
    if key.get("fromMe") or "@g.us" in remote_jid:
        return jsonify({"ok": True})

    # Extrai telefone (remove sufixo @s.whatsapp.net ou @c.us)
    telefone = remote_jid.split("@")[0]

    # Nome do contato no WhatsApp — limitado e strip para evitar injection via pushName
    nome = (msg_data.get("pushName") or "").strip()[:80]

    # Extrai texto da mensagem (suporta conversation e extendedTextMessage)
    message = msg_data.get("message", {})
    texto = (
        message.get("conversation")
        or message.get("extendedTextMessage", {}).get("text")
        or ""
    ).strip()

    if not texto:
        return jsonify({"ok": True})  # ignora áudio, imagem, sticker, etc.

    logging.info("WhatsApp recebido de %s (%s): %s", telefone, nome or "—", texto[:60])

    # Processa em background — responde 200 imediatamente para o Evolution API
    threading.Thread(
        target=_processar_mensagem_wa,
        args=(telefone, texto, nome),
        daemon=True,
    ).start()

    return jsonify({"ok": True})


if __name__ == "__main__":
    app.run(host="0.0.0.0", debug=False, port=5000, threaded=True)
