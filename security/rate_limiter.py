"""
Camada 5 — Rate Limiter (sliding window, in-memory)
Sem dependência externa (sem Redis).
"""

import time
import threading
import logging
from collections import defaultdict, deque
from dataclasses import dataclass

logger = logging.getLogger(__name__)

# Limites por IP (requisições na janela de tempo)
IP_WINDOW_SEC = 60
IP_MAX_REQ = 30

# Limites por telefone (WhatsApp)
PHONE_WINDOW_SEC = 60
PHONE_MAX_REQ = 20

# Cooldown aplicado ao detectar ataque
ATTACKER_COOLDOWN_SEC = 300  # 5 minutos

_lock = threading.Lock()
_ip_buckets: dict[str, deque] = defaultdict(deque)
_phone_buckets: dict[str, deque] = defaultdict(deque)
_blocked_ips: dict[str, float] = {}    # ip -> unblock_at (timestamp)
_blocked_phones: dict[str, float] = {}  # phone -> unblock_at


@dataclass
class RateResult:
    is_allowed: bool
    reason: str


def _sliding_window(key: str, store: dict[str, deque], window: int, max_req: int) -> bool:
    now = time.time()
    bucket = store[key]
    while bucket and bucket[0] < now - window:
        bucket.popleft()
    if len(bucket) >= max_req:
        return False
    bucket.append(now)
    return True


def check_ip(ip: str) -> RateResult:
    with _lock:
        blocked_until = _blocked_ips.get(ip)
        if blocked_until:
            if time.time() < blocked_until:
                return RateResult(is_allowed=False, reason="ip_blocked_attacker")
            del _blocked_ips[ip]

        if not _sliding_window(ip, _ip_buckets, IP_WINDOW_SEC, IP_MAX_REQ):
            logger.warning("Rate limit IP excedido: %s", ip)
            return RateResult(is_allowed=False, reason="ip_rate_limit")

    return RateResult(is_allowed=True, reason="ok")


def check_phone(phone: str) -> RateResult:
    with _lock:
        blocked_until = _blocked_phones.get(phone)
        if blocked_until:
            if time.time() < blocked_until:
                return RateResult(is_allowed=False, reason="phone_blocked_attacker")
            del _blocked_phones[phone]

        if not _sliding_window(phone, _phone_buckets, PHONE_WINDOW_SEC, PHONE_MAX_REQ):
            logger.warning("Rate limit telefone excedido: ...%s", phone[-4:])
            return RateResult(is_allowed=False, reason="phone_rate_limit")

    return RateResult(is_allowed=True, reason="ok")


def penalize_attacker(ip: str | None = None, phone: str | None = None) -> None:
    """Bloqueia IP/telefone por ATTACKER_COOLDOWN_SEC após detecção de ataque."""
    unblock_at = time.time() + ATTACKER_COOLDOWN_SEC
    with _lock:
        if ip:
            _blocked_ips[ip] = unblock_at
            logger.warning("IP penalizado por ataque: %s (até %s)", ip, unblock_at)
        if phone:
            _blocked_phones[phone] = unblock_at
            logger.warning("Telefone penalizado por ataque: ...%s", phone[-4:] if len(phone) >= 4 else phone)
