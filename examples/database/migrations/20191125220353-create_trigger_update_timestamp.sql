
-- +migrate Up
-- +migrate StatementBegin
CREATE OR REPLACE FUNCTION update_timestamp()
RETURNS TRIGGER AS $$
BEGIN
   NEW.updated_at = now(); 
   RETURN NEW;
END;
$$ language 'plpgsql';
--  CREATE TRIGGER update_ab_changetimestamp BEFORE UPDATE
--    ON ab FOR EACH ROW EXECUTE PROCEDURE
--    update_timestamp();
-- +migrate StatementEnd

-- +migrate Down
DROP FUNCTION IF EXISTS update_timestamp;

