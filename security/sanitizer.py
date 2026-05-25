"""
Camada 1 — Sanitizador de Input
Defesa de custo zero: sem chamadas LLM.
"""

import re
import unicodedata
import logging
from dataclasses import dataclass

logger = logging.getLogger(__name__)

MAX_INPUT_LENGTH = 1200

# Padrões de injeção conhecidos (PT-BR e EN)
_INJECTION_PATTERNS: list[tuple[str, str]] = [
    # Override de instruções
    (
        r'\b(ignore|ignora|ignorar|disregard|disregarda)\b.{0,40}'
        r'\b(all|todas?|previous|anteriores?|your|suas?|above|acima|prior|prévias?)\b.{0,40}'
        r'\b(instructions?|instruções?|rules?|regras?|prompts?|guidelines?|directives?)\b',
        "instruction_override",
    ),
    (
        r'\b(esqueça|esquecer|forget|desconsider|desconsidere)\b.{0,40}'
        r'\b(tudo|everything|instruções?|instructions?|regras?|rules?|treinamento|training)\b',
        "instruction_override",
    ),
    (
        r'\b(override|substituir|substituia|substituindo)\b.{0,30}'
        r'\b(instruções?|instructions?|rules?|regras?|filters?|filtros?|restrictions?|restrições?)\b',
        "instruction_override",
    ),
    # Tomada de persona
    (r'\byou\s+are\s+now\b', "persona_takeover"),
    (r'\bagora\s+você\s+(é|se\s+chama|deve\s+ser)\b', "persona_takeover"),
    (r'\bfrom\s+now\s+on\s+(you\s+are|act\s+as|pretend)\b', "persona_takeover"),
    (r'\ba\s+partir\s+de\s+agora\s+(você|vc)\s+(é|age|deve)\b', "persona_takeover"),
    (r'\bpretend\s+(you\s+are|to\s+be)\b', "persona_takeover"),
    (r'\bfinja\s+(ser|que\s+é|que\s+você\s+é)\b', "persona_takeover"),
    (r'\bact\s+as\b.{0,50}\b(without|no|unrestricted|free|sem)\b', "persona_takeover"),
    (r'\broleplay\s+as\b', "persona_takeover"),
    # Jailbreak clássico
    (r'\bDANmode\b|\bDAN\s+mode\b|\byou\s+are\s+DAN\b|\bDo\s+Anything\s+Now\b', "jailbreak"),
    (r'\bdeveloper\s+mode\b|\bmodo\s+desenvolvedor\b', "jailbreak"),
    (r'\bunrestricted\s+mode\b|\bmodo\s+sem\s+restrições?\b', "jailbreak"),
    (r'\bjailbreak\b', "jailbreak"),
    (r'\bsem\s+(filtros?|restrições?|limites?)\b.{0,30}\b(responda|aja|fale|seja)\b', "jailbreak"),
    # Exfiltração de dados
    (
        r'\b(print|repita|repeat|mostre?|show|reveal|revele?|display|output|escreva?|write|diga|tell\s+me)\b'
        r'.{0,50}'
        r'\b(system\s*prompt|your\s+prompt|suas?\s+instruções?|your\s+instructions?|everything\s+above|tudo\s+acima|previous\s+text|texto\s+anterior)\b',
        "data_exfiltration",
    ),
    (r'\bwhat\s+are\s+your\s+(instructions?|rules?|prompts?|guidelines?)\b', "data_exfiltration"),
    (r'\bquais\s+(são\s+)?(suas?\s+)?(instruções?|regras?|prompts?|diretrizes?)\b', "data_exfiltration"),
    (r'\b(repita?|repeat)\s+(tudo|everything|all)\s+(acima|above|anterior|previous)\b', "data_exfiltration"),
    # Confusão de papel via formatação
    (r'^(system|assistant)\s*:\s', "role_confusion"),
    (r'\n(system|assistant)\s*:\s', "role_confusion"),
    # Bypass explícito
    (
        r'\b(bypass|burlar|contornar|disable|desativ)\b.{0,30}'
        r'\b(filter|filtro|restriction|restrição|rule|regra|check|guard|safety|segurança)\b',
        "bypass_attempt",
    ),
]

# Caracteres invisíveis e de controle (incluindo zero-width, RTL override, BOM)
_CONTROL_RE = re.compile(
    r'[\x00-\x08\x0b\x0c\x0e-\x1f\x7f'
    r'​‌‍\u200E\u200F'
    r'\u202A-\u202E⁠-⁤﻿]'
)

_COMPILED: list[tuple[re.Pattern, str]] = [
    (re.compile(p, re.IGNORECASE | re.DOTALL), label)
    for p, label in _INJECTION_PATTERNS
]


@dataclass
class SanitizationResult:
    is_safe: bool
    reason: str
    cleaned_text: str


def sanitize(text: str) -> SanitizationResult:
    # 1. Normalização unicode — derrota ataques com homoglifos
    normalized = unicodedata.normalize("NFKC", text)

    # 2. Remove caracteres invisíveis e de controle
    cleaned = _CONTROL_RE.sub("", normalized).strip()

    # 3. Input vazio após limpeza
    if not cleaned:
        return SanitizationResult(is_safe=False, reason="empty_input", cleaned_text="")

    # 4. Limite de tamanho
    if len(cleaned) > MAX_INPUT_LENGTH:
        logger.warning("Input truncado: %d chars", len(cleaned))
        return SanitizationResult(
            is_safe=False,
            reason=f"input_too_long:{len(cleaned)}",
            cleaned_text=cleaned[:MAX_INPUT_LENGTH],
        )

    # 5. Denylist de padrões de injeção
    for pattern, label in _COMPILED:
        if pattern.search(cleaned):
            logger.warning("Sanitizer bloqueou padrão '%s': %.60s", label, cleaned)
            return SanitizationResult(is_safe=False, reason=label, cleaned_text=cleaned)

    return SanitizationResult(is_safe=True, reason="ok", cleaned_text=cleaned)
