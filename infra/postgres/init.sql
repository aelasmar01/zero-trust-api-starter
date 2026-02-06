CREATE TABLE IF NOT EXISTS resources (
    id SERIAL PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    name TEXT NOT NULL,
    classification TEXT NOT NULL DEFAULT 'internal',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

INSERT INTO resources (tenant_id, name, classification)
VALUES
    ('tenant-a', 'alpha-doc', 'internal'),
    ('tenant-b', 'beta-doc', 'restricted')
ON CONFLICT DO NOTHING;
