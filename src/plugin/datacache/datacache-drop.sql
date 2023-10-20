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


SELECT _v.unregister_patch('datacache-0001');

DROP SCHEMA datacache CASCADE;

COMMIT;
