-- Modified in this fork: new file.
--
-- Before and after images on change events, for event handlers (the
-- replacement for Cloud Functions document triggers) that need to compare a
-- document's state before and after a write. Live listeners still re-read
-- current state and ignore these columns.
ALTER TABLE changelog
    ADD COLUMN before_data   jsonb,
    ADD COLUMN before_create timestamptz,
    ADD COLUMN before_update timestamptz,
    ADD COLUMN after_data    jsonb,
    ADD COLUMN after_create  timestamptz,
    ADD COLUMN after_update  timestamptz;
