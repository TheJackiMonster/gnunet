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
SELECT _v.register_patch('namestore-0001', NULL, NULL);

-------------------- Schema ----------------------------

CREATE SCHEMA namestore;
COMMENT ON SCHEMA namestore IS 'gnunet-namestore data';

SET search_path TO namestore;

CREATE TABLE ns098records (
  seq BIGSERIAL PRIMARY KEY,
  zone_private_key BYTEA NOT NULL DEFAULT '',
  pkey BYTEA DEFAULT '',
  rvalue BYTEA NOT NULL DEFAULT '',
  record_count INTEGER NOT NULL DEFAULT 0,
  record_data BYTEA NOT NULL DEFAULT '',
  label TEXT NOT NULL DEFAULT '',
  CONSTRAINT zl UNIQUE (zone_private_key,label));

CREATE INDEX IF NOT EXISTS ir_pkey_reverse 
  ON ns098records (zone_private_key,pkey);
CREATE INDEX IF NOT EXISTS ir_pkey_iter 
  ON ns098records (zone_private_key,seq);
CREATE INDEX IF NOT EXISTS ir_label 
  ON ns098records (label);


COMMIT;
