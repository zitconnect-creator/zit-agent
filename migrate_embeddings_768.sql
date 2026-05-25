-- Migração: OpenAI text-embedding-3-small (1536 dim) → HuggingFace multilingual-mpnet (768 dim)
-- Execute no SQL Editor do Supabase antes de rodar ingest.py

-- 1. Remove embeddings antigos (incompatíveis com nova dimensão)
DELETE FROM zit_documentos;

-- 2. Recria a coluna embedding com nova dimensão
ALTER TABLE zit_documentos DROP COLUMN IF EXISTS embedding;
ALTER TABLE zit_documentos ADD COLUMN embedding VECTOR(768);

-- 3. Recria o índice HNSW
DROP INDEX IF EXISTS zit_documentos_embedding_idx;
CREATE INDEX zit_documentos_embedding_idx
    ON zit_documentos
    USING hnsw (embedding vector_cosine_ops)
    WITH (m = 16, ef_construction = 64);

-- 4. Recria a função de busca semântica com nova dimensão
DROP FUNCTION IF EXISTS zit_buscar_documentos_similares(vector, integer, text);

CREATE OR REPLACE FUNCTION zit_buscar_documentos_similares(
    query_embedding VECTOR(768),
    match_count      INT  DEFAULT 5,
    filtro_categoria TEXT DEFAULT NULL
)
RETURNS TABLE (
    id          UUID,
    content     TEXT,
    metadata    JSONB,
    categoria   TEXT,
    similarity  FLOAT
)
LANGUAGE SQL STABLE
AS $$
    SELECT
        id,
        content,
        metadata,
        categoria,
        1 - (embedding <=> query_embedding) AS similarity
    FROM zit_documentos
    WHERE filtro_categoria IS NULL OR categoria = filtro_categoria
    ORDER BY embedding <=> query_embedding
    LIMIT match_count;
$$;
