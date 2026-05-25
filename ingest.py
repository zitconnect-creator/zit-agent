"""
ingest.py — Ingesta de documentos na base vetorial do Supabase
==============================================================
Suporta:
  - Texto direto (dicionários)
  - Arquivos .txt e .pdf (via PyMuPDF)
  - PDF de FAQ com detecção automática de pares Q&A
  - Chunking automático com RecursiveCharacterTextSplitter
"""

import os
import re
import json
import logging
from pathlib import Path
from typing import Optional

from dotenv import load_dotenv
from supabase import create_client
from langchain_community.embeddings import HuggingFaceEmbeddings
from langchain_community.vectorstores import SupabaseVectorStore
from langchain_text_splitters import RecursiveCharacterTextSplitter
from langchain_core.documents import Document

load_dotenv()
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)


# ─── Configurações de chunking ────────────────────────────────────────────────
# Chunks menores = maior precisão semântica por cláusula do contrato
CHUNK_SIZE = 450
CHUNK_OVERLAP = 80


class IngestorDocumentos:

    def __init__(self):
        self.supabase = create_client(
            os.environ["SUPABASE_URL"],
            os.environ["SUPABASE_SERVICE_KEY"],
        )
        self.embeddings = HuggingFaceEmbeddings(
            model_name="sentence-transformers/paraphrase-multilingual-mpnet-base-v2",
            model_kwargs={"device": "cpu"},
            encode_kwargs={"normalize_embeddings": True},
        )
        self.splitter = RecursiveCharacterTextSplitter(
            chunk_size=CHUNK_SIZE,
            chunk_overlap=CHUNK_OVERLAP,
            separators=["\n\n", "\n", ". ", ", ", " "],
        )
        self.vector_store = SupabaseVectorStore(
            client=self.supabase,
            embedding=self.embeddings,
            table_name="zit_documentos",
            query_name="zit_buscar_documentos_similares",
        )

    # ── Ingesta de lista de dicionários ──────────────────────────────────────
    def ingerir_textos(self, itens: list[dict]) -> int:
        """
        itens: lista de {"conteudo": str, "categoria": str, "metadata": dict}
        """
        documentos = []
        for item in itens:
            chunks = self.splitter.split_text(item["conteudo"])
            for i, chunk in enumerate(chunks):
                documentos.append(Document(
                    page_content=chunk,
                    metadata={
                        "categoria": item.get("categoria", "geral"),
                        "chunk_index": i,
                        "total_chunks": len(chunks),
                        **item.get("metadata", {}),
                    }
                ))

        if not documentos:
            logger.warning("Nenhum documento gerado para ingestão.")
            return 0

        self.vector_store.add_documents(documentos)
        logger.info("%d chunks ingeridos com sucesso.", len(documentos))
        return len(documentos)

    # ── Ingesta de arquivo .txt ───────────────────────────────────────────────
    def ingerir_txt(self, caminho: str, categoria: str = "geral", metadata: Optional[dict] = None) -> int:
        texto = Path(caminho).read_text(encoding="utf-8")
        return self.ingerir_textos([{
            "conteudo": texto,
            "categoria": categoria,
            "metadata": {"arquivo": Path(caminho).name, **(metadata or {})},
        }])

    # ── Ingesta de arquivo .pdf ───────────────────────────────────────────────
    def ingerir_pdf(self, caminho: str, categoria: str = "geral", metadata: Optional[dict] = None) -> int:
        try:
            import fitz  # PyMuPDF
        except ImportError:
            raise RuntimeError("Instale PyMuPDF: pip install pymupdf")

        doc = fitz.open(caminho)
        paginas = len(doc)
        texto = "\n\n".join(page.get_text() for page in doc)
        doc.close()

        return self.ingerir_textos([{
            "conteudo": texto,
            "categoria": categoria,
            "metadata": {
                "arquivo": Path(caminho).name,
                "paginas": paginas,
                **(metadata or {}),
            },
        }])

    # ── Ingesta de FAQ em PDF ─────────────────────────────────────────────────
    def ingerir_faq_pdf(self, caminho: str, metadata: Optional[dict] = None) -> int:
        """
        Ingesta PDF de FAQ tratando cada par Q&A como um chunk individual.
        Detecta automaticamente os padrões mais comuns em português.
        Fallback para chunking padrão se nenhum padrão for encontrado.
        """
        try:
            import fitz
        except ImportError:
            raise RuntimeError("Instale PyMuPDF: pip install pymupdf")

        doc = fitz.open(caminho)
        paginas = len(doc)
        texto = "\n".join(page.get_text() for page in doc)
        doc.close()

        pares = self._extrair_pares_faq(texto)

        if pares:
            logger.info("FAQ: %d pares Q&A detectados em '%s'.", len(pares), Path(caminho).name)
            documentos = []
            for i, (pergunta, resposta) in enumerate(pares):
                conteudo = f"Pergunta: {pergunta.strip()}\nResposta: {resposta.strip()}"
                documentos.append(Document(
                    page_content=conteudo,
                    metadata={
                        "categoria": "faq",
                        "pergunta": pergunta.strip()[:150],
                        "chunk_index": i,
                        "total_chunks": len(pares),
                        "arquivo": Path(caminho).name,
                        "paginas": paginas,
                        **(metadata or {}),
                    },
                ))
            self.vector_store.add_documents(documentos)
            logger.info("%d chunks de FAQ ingeridos.", len(documentos))
            return len(documentos)

        logger.warning(
            "FAQ: nenhum padrão Q&A detectado em '%s'. Usando chunking padrão com categoria='faq'.",
            Path(caminho).name,
        )
        return self.ingerir_pdf(caminho, categoria="faq", metadata=metadata)

    @staticmethod
    def _extrair_pares_faq(texto: str) -> list[tuple[str, str]]:
        """
        Tenta 3 padrões comuns de FAQ em português, em ordem de prioridade.
        Retorna lista de (pergunta, resposta) ou [] se nenhum padrão bater.
        """
        # Padrão 1: marcadores explícitos P/Pergunta e R/Resposta
        pares = re.findall(
            r'[Pp](?:ergunta)?[:\.\)]\s*(.+?)\s*[Rr](?:esposta)?[:\.\)]\s*(.+?)(?=\s*[Pp](?:ergunta)?[:\.\)]|\Z)',
            texto, re.DOTALL,
        )
        if len(pares) >= 2:
            return [(p.strip(), r.strip()) for p, r in pares]

        # Padrão 2: itens numerados onde a pergunta termina com "?"
        pares = re.findall(
            r'\d+[\.\)]\s*(.+?\?)\s*\n+(.+?)(?=\n*\d+[\.\)]|\Z)',
            texto, re.DOTALL,
        )
        if len(pares) >= 2:
            return [(p.strip(), r.strip()) for p, r in pares]

        # Padrão 3: blocos separados por linha em branco onde o 1º termina em "?"
        blocos = re.split(r'\n{2,}', texto.strip())
        pares = []
        i = 0
        while i < len(blocos) - 1:
            pergunta = blocos[i].strip()
            resposta = blocos[i + 1].strip()
            if pergunta.endswith('?') and len(resposta) > 15:
                pares.append((pergunta, resposta))
                i += 2
            else:
                i += 1
        if len(pares) >= 2:
            return pares

        return []

    # ── Ingesta via JSON ──────────────────────────────────────────────────────
    def ingerir_json(self, caminho: str) -> int:
        """
        Espera um JSON com lista de objetos:
        [{"conteudo": "...", "categoria": "...", "metadata": {...}}, ...]
        """
        with open(caminho, encoding="utf-8") as f:
            itens = json.load(f)
        return self.ingerir_textos(itens)

    # ── Limpar todos os documentos ────────────────────────────────────────────
    def limpar_base(self, confirmar: bool = False) -> None:
        if not confirmar:
            raise ValueError("Passe confirmar=True para deletar todos os documentos.")
        self.supabase.table("zit_documentos").delete().neq("id", "00000000-0000-0000-0000-000000000000").execute()
        logger.warning("Todos os documentos foram removidos da base.")


# ─── Ingesta completa da base de conhecimento ────────────────────────────────
if __name__ == "__main__":
    ingestor = IngestorDocumentos()
    total = 0

    fontes = [
        {
            "arquivo": "ZIT_Connect_FAQ_RAG.pdf",
            "tipo": "faq_pdf",
            "metadata": {"fonte": "faq_zit_connect"},
        },
    ]

    for fonte in fontes:
        caminho = fonte["arquivo"]
        if not Path(caminho).exists():
            print(f"⚠️  Arquivo não encontrado, pulando: {caminho}")
            continue

        if fonte["tipo"] == "faq_pdf":
            n = ingestor.ingerir_faq_pdf(caminho, metadata=fonte.get("metadata"))
        else:
            n = ingestor.ingerir_pdf(
                caminho,
                categoria=fonte.get("categoria", "geral"),
                metadata=fonte.get("metadata"),
            )

        print(f"✅ {caminho}: {n} chunks indexados.")
        total += n

    print(f"\n🏁 Total: {total} chunks na base do Supabase.")
