-- Session tokens become BLAKE2b digests. Existing raw-token rows are dropped, not
-- rehashed: rehashing would leave the plaintext in freelist pages and the WAL
-- anyway. Operators sign in once more.
DELETE FROM sessions;
ALTER TABLE sessions RENAME COLUMN token TO token_hash;
