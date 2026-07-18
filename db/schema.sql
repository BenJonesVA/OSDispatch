CREATE TABLE IF NOT EXISTS users (
  id SERIAL PRIMARY KEY,
  username TEXT UNIQUE NOT NULL,
  password_hash TEXT,
  role TEXT NOT NULL CHECK (role IN ('driver', 'dispatcher')),
  display_name TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Drivers authenticate with a 4-digit PIN instead of a password; dispatchers
-- keep password_hash. Both columns are nullable at the table level so a
-- single users table can serve either credential shape.
ALTER TABLE users ALTER COLUMN password_hash DROP NOT NULL;
ALTER TABLE users ADD COLUMN IF NOT EXISTS pin_hash TEXT;
ALTER TABLE users ADD COLUMN IF NOT EXISTS active BOOLEAN NOT NULL DEFAULT true;

-- Only dispatchers are required to have a password_hash. Added NOT VALID so
-- upgrading an existing database doesn't fail validation against driver rows
-- that predate the PIN feature (their pin_hash starts out NULL until reset).
ALTER TABLE users DROP CONSTRAINT IF EXISTS users_dispatcher_password_check;
ALTER TABLE users ADD CONSTRAINT users_dispatcher_password_check
  CHECK (role != 'dispatcher' OR password_hash IS NOT NULL) NOT VALID;

CREATE TABLE IF NOT EXISTS location_pings (
  id BIGSERIAL PRIMARY KEY,
  user_id INTEGER NOT NULL REFERENCES users(id),
  latitude DOUBLE PRECISION NOT NULL,
  longitude DOUBLE PRECISION NOT NULL,
  recorded_at TIMESTAMPTZ NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Instantaneous speed at this ping (km/h), computed server-side the same way
-- as the live dashboard telemetry. Nullable: pings recorded before this
-- column existed have no historical speed and are never backfilled.
ALTER TABLE location_pings ADD COLUMN IF NOT EXISTS speed_kmh DOUBLE PRECISION;

-- Posted speed limit (km/h) for the road nearest this ping, best-effort
-- looked up from OpenStreetMap at insert time. Null when no tagged road was
-- found nearby, the lookup was rate-limited/failed, or the ping predates
-- this column.
ALTER TABLE location_pings ADD COLUMN IF NOT EXISTS speed_limit_kmh DOUBLE PRECISION;

CREATE INDEX IF NOT EXISTS idx_location_pings_user_id_recorded_at
  ON location_pings (user_id, recorded_at);
