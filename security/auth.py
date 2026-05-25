"""
Autenticação de endpoints admin via header X-Admin-Key.
Chave configurada pela variável de ambiente ADMIN_API_KEY.
"""

import os
import hmac
import functools
import logging
from flask import request, jsonify

logger = logging.getLogger(__name__)


def require_admin_key(f):
    @functools.wraps(f)
    def decorated(*args, **kwargs):
        expected = os.getenv("ADMIN_API_KEY", "")
        if not expected:
            logger.warning("ADMIN_API_KEY não configurada — endpoint admin desprotegido!")
            return f(*args, **kwargs)

        provided = request.headers.get("X-Admin-Key", "")
        if not provided or not hmac.compare_digest(provided, expected):
            logger.warning(
                "Acesso admin não autorizado de %s para %s",
                request.remote_addr, request.path,
            )
            return jsonify({"erro": "Não autorizado."}), 401

        return f(*args, **kwargs)
    return decorated
