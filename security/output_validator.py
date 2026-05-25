"""
Camada 4 — Validador de Output
Detecta vazamentos do system prompt, canary token, e dados sensíveis na resposta gerada.
Substitui a resposta por uma mensagem segura se algo suspeito for encontrado.
"""

import re
import logging
from dataclasses import dataclass

logger = logging.getLogger(__name__)

# Token canário — se aparecer no output, significa que o prompt foi extraído
CANARY_TOKEN = "ZIT-CANARY-9B4F"

_FALLBACK = (
    "Desculpe, não consigo ajudar com isso. "
    "Para dúvidas sobre os serviços da Z-IT Connect, acesse zitconnect.com 😊"
)

# Padrões que indicam vazamento ou dado sensível
_LEAK_PATTERNS: list[tuple[re.Pattern, str]] = [
    # Canary token
    (re.compile(r'ZIT-CANARY-9B4F', re.IGNORECASE), "canary_token"),
    # Marcadores estruturais do system prompt
    (re.compile(r'# IDENTIDADE|# REGRAS ABSOLUTAS|# OBJETIVO|# PERSONALIDADE|# PROTEÇÃO', re.IGNORECASE), "prompt_structure_leak"),
    (re.compile(r'SYSTEM_PROMPT\s*=|QUERY_EXPANSION_PROMPT|INTENT_PROMPT', re.IGNORECASE), "code_leak"),
    # Chaves de API
    (re.compile(r'sk-[a-zA-Z0-9]{20,}'), "openai_key"),
    (re.compile(r'sbp_[a-zA-Z0-9]{30,}'), "supabase_key"),
    # JWT / tokens
    (re.compile(r'eyJ[a-zA-Z0-9_-]{10,}\.eyJ'), "jwt_token"),
    # Variáveis de ambiente sensíveis
    (re.compile(r'\b(SUPABASE_URL|SUPABASE_SERVICE_KEY|OPENAI_API_KEY|GROQ_API_KEY|EVOLUTION_API_KEY)\b'), "env_var_leak"),
    # Token interno do prompt
    (re.compile(r'TOKEN-SEGURANÇA|INTERNAL-REF|INTERNAL:', re.IGNORECASE), "internal_marker_leak"),
]


@dataclass
class ValidationResult:
    is_valid: bool
    reason: str
    safe_output: str


def validate_output(text: str) -> ValidationResult:
    if not text:
        return ValidationResult(is_valid=True, reason="ok", safe_output=text)

    for pattern, label in _LEAK_PATTERNS:
        if pattern.search(text):
            logger.warning("Output validator bloqueou '%s' na resposta gerada", label)
            return ValidationResult(is_valid=False, reason=label, safe_output=_FALLBACK)

    return ValidationResult(is_valid=True, reason="ok", safe_output=text)
