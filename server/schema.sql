-- BC-ASSISTANT schema. Single shared workspace + file metadata.
CREATE TABLE IF NOT EXISTS workspace (
  id         integer PRIMARY KEY DEFAULT 1,
  state      jsonb       NOT NULL DEFAULT '{}'::jsonb,
  updated_at timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT workspace_single_row CHECK (id = 1)
);
INSERT INTO workspace (id, state) VALUES (1, '{}'::jsonb)
  ON CONFLICT (id) DO NOTHING;

CREATE TABLE IF NOT EXISTS files (
  id         text PRIMARY KEY,
  name       text NOT NULL,
  type       text,
  size       bigint,
  path       text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now()
);
