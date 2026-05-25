-- ============================================================
-- SETUP SUPABASE - Agente Z-IT Connect
-- Execute este script no SQL Editor do seu projeto Supabase
-- ============================================================

-- 1. Habilitar a extensão pgvector
CREATE EXTENSION IF NOT EXISTS vector;

-- 2. Tabela principal de documentos (knowledge base)
CREATE TABLE IF NOT EXISTS zit_documentos (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    content     TEXT NOT NULL,
    metadata    JSONB DEFAULT '{}'::jsonb,
    embedding   VECTOR(1536),           -- Dimensão do text-embedding-3-small (OpenAI)
    categoria   TEXT,                   -- Ex: 'faq', 'servicos', 'tecnologias', 'processo'
    criado_em   TIMESTAMPTZ DEFAULT NOW(),
    atualizado_em TIMESTAMPTZ DEFAULT NOW()
);

-- 3. Index HNSW para busca vetorial rápida
CREATE INDEX IF NOT EXISTS zit_documentos_embedding_idx
    ON zit_documentos
    USING hnsw (embedding vector_cosine_ops)
    WITH (m = 16, ef_construction = 64);

-- 4. Tabela de log de interações (auditoria + melhoria contínua)
CREATE TABLE IF NOT EXISTS zit_interacoes (
    id              BIGSERIAL PRIMARY KEY,
    session_id      TEXT NOT NULL,
    pergunta        TEXT NOT NULL,
    resposta        TEXT,
    score_rag       FLOAT,              -- Score de similaridade do RAG
    score_status    TEXT,              -- 'respondido', 'baixa_confianca', 'sem_resultado'
    doc_ids_usados  UUID[],            -- IDs dos documentos utilizados
    canal           TEXT DEFAULT 'web', -- 'web' | 'whatsapp'
    criado_em       TIMESTAMPTZ DEFAULT NOW()
);

-- 5. Função para busca semântica com score de similaridade
DROP FUNCTION IF EXISTS zit_buscar_documentos_similares(vector, int, text);

CREATE FUNCTION zit_buscar_documentos_similares(
    query_embedding     VECTOR(1536),
    match_count         INT DEFAULT 5,
    filtro_categoria    TEXT DEFAULT NULL
)
RETURNS TABLE (
    id          UUID,
    content     TEXT,
    metadata    JSONB,
    categoria   TEXT,
    similarity  FLOAT
)
LANGUAGE plpgsql
AS $$
BEGIN
    RETURN QUERY
    SELECT
        d.id,
        d.content,
        d.metadata,
        d.categoria,
        1 - (d.embedding <=> query_embedding) AS similarity  -- Cosine similarity
    FROM zit_documentos d
    WHERE
        (filtro_categoria IS NULL OR d.categoria = filtro_categoria)
        AND d.embedding IS NOT NULL
    ORDER BY d.embedding <=> query_embedding  -- Menor distância = maior similaridade
    LIMIT match_count;
END;
$$;

-- 6. Trigger para atualizar 'atualizado_em' automaticamente
CREATE OR REPLACE FUNCTION update_atualizado_em()
RETURNS TRIGGER AS $$
BEGIN
    NEW.atualizado_em = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_zit_documentos_atualizado
    BEFORE UPDATE ON zit_documentos
    FOR EACH ROW
    EXECUTE FUNCTION update_atualizado_em();

-- 7. RLS (Row Level Security) - Habilitar para produção
-- ALTER TABLE zit_documentos ENABLE ROW LEVEL SECURITY;
-- ALTER TABLE zit_interacoes ENABLE ROW LEVEL SECURITY;

-- 8. Tabela de leads (clientes com intenção de contratar)
CREATE TABLE IF NOT EXISTS leads (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    nome            TEXT NOT NULL,
    telefone        TEXT NOT NULL,
    plano_interesse TEXT,               -- Serviço de interesse (Automação, Agente de IA, Consultoria)
    mensagem_original TEXT,
    session_id      TEXT,
    status          TEXT DEFAULT 'novo',  -- novo | contatado | convertido | perdido
    criado_em       TIMESTAMPTZ DEFAULT NOW()
);

-- 9. Tabela de histórico de conversa (memória persistente por telefone)
CREATE TABLE IF NOT EXISTS zit_historico (
    id          BIGSERIAL PRIMARY KEY,
    telefone    TEXT NOT NULL,
    canal       TEXT DEFAULT 'web',   -- 'web' | 'whatsapp'
    role        TEXT NOT NULL,        -- 'user' | 'agent'
    conteudo    TEXT NOT NULL,
    criado_em   TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS zit_historico_telefone_idx
    ON zit_historico (telefone, criado_em);

-- 10. View para monitoramento de qualidade das respostas
CREATE OR REPLACE VIEW v_zit_qualidade_respostas AS
SELECT
    DATE_TRUNC('day', criado_em) AS dia,
    COUNT(*) AS total_interacoes,
    COUNT(*) FILTER (WHERE score_status = 'respondido') AS respondidas,
    COUNT(*) FILTER (WHERE score_status = 'baixa_confianca') AS baixa_confianca,
    COUNT(*) FILTER (WHERE score_status = 'sem_resultado') AS sem_resultado,
    ROUND(AVG(score_rag)::NUMERIC, 3) AS score_medio,
    ROUND(
        (COUNT(*) FILTER (WHERE score_status = 'respondido')::FLOAT / COUNT(*) * 100)::NUMERIC, 1
    ) AS taxa_resposta_pct
FROM zit_interacoes
GROUP BY 1
ORDER BY 1 DESC;
