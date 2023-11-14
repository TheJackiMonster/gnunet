--
-- This file is part of GNUnet
-- Copyright (C) 2014--2022 GNUnet e.V.
--
-- GNUnet is free software; you can redistribute it and/or modify it under the
-- terms of the GNU General Public License as published by the Free Software
-- Foundation; either version 3, or (at your option) any later version.
--
-- GNUnet is distributed in the hope that it will be useful, but WITHOUT ANY
-- WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR
-- A PARTICULAR PURPOSE.  See the GNU General Public License for more details.
--
-- You should have received a copy of the GNU General Public License along with
-- GNUnet; see the file COPYING.  If not, see <http://www.gnu.org/licenses/>
--

-- Everything in one big transaction
BEGIN;

-- Check patch versioning is in place.
SELECT _v.register_patch('namecache-0001', NULL, NULL);

-------------------- Schema ----------------------------

CREATE SCHEMA datacache;
COMMENT ON SCHEMA datacache IS 'gnunet-datacache data';

SET search_path TO datacache;

CREATE TABLE IF NOT EXISTS ns096blocks (
  query BYTEA NOT NULL DEFAULT '',
  block BYTEA NOT NULL DEFAULT '',
  expiration_time BIGINT NOT NULL DEFAULT 0);

CREATE INDEX ir_query_hash
  ON ns096blocks (query,expiration_time);

CREATE INDEX ir_block_expiration
  ON ns096blocks (expiration_time);


COMMIT;
