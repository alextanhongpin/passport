
-- +migrate Up
-- Use sorted v1 for best performance! uuid_generate_v1mc();
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- +migrate Down
DROP EXTENSION IF EXISTS "uuid-ossp";
