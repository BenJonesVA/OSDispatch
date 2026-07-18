const path = require('path');
const express = require('express');
const helmet = require('helmet');
const bcrypt = require('bcryptjs');
const session = require('express-session');
const pgSessionFactory = require('connect-pg-simple');
const rateLimit = require('express-rate-limit');
const http = require('http');
const { Server } = require('socket.io');
const { pool, initSchema } = require('./db');
const { seedUsers } = require('./db/seed');

const app = express();
const server = http.createServer(app);
const io = new Server(server);

const PORT = process.env.PORT || 3000;

// Breadcrumbs: how many recent points we keep per driver for trail/telemetry.
const HISTORY_LENGTH = 10;
// A driver with no update in this long (well past the ~7s emit interval, so a
// couple of missed beats don't false-positive) is considered silently
// disconnected rather than having deliberately ended their shift.
const STALE_TIMEOUT_MS = Number(process.env.STALE_TIMEOUT_MS) || 20_000;
const STALE_SWEEP_INTERVAL_MS = 5_000;
// A single stale/glitchy GPS fix can imply a physically impossible speed
// (e.g. a position jump paired with a short time delta) — anything above
// this is treated as unknown rather than let it spike the dashboard/history.
// Comfortably above any real vehicle's cruising speed, including highways.
const MAX_PLAUSIBLE_SPEED_KMH = 200;

// Trust X-Forwarded-* headers from any private-network hop (Docker containers,
// including a TLS-terminating proxy like Nginx Proxy Manager sitting in front
// of our own nginx) rather than a fixed hop count, since the proxy chain
// length can change independently of app code.
app.set('trust proxy', 'loopback, linklocal, uniquelocal');

app.use(
  helmet({
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'self'"],
        scriptSrc: ["'self'", "'unsafe-inline'", 'https://unpkg.com'],
        styleSrc: ["'self'", "'unsafe-inline'", 'https://unpkg.com', 'https://fonts.googleapis.com'],
        imgSrc: ["'self'", 'data:', 'https://*.basemaps.cartocdn.com'],
        connectSrc: ["'self'", 'ws:', 'wss:'],
        // Helmet's default CSP includes this directive, which tells browsers to
        // silently rewrite http:// sub-resource requests (fetch/XHR/forms) to
        // https:// — breaks every fetch() call whenever this is reached directly
        // over plain HTTP (e.g. local testing without a TLS proxy in front).
        // Left disabled permanently: it adds no real protection here (nothing
        // in the app links to a hardcoded http:// URL, so there's no mixed
        // content to upgrade) and the downside is a footgun we've already hit.
        upgradeInsecureRequests: null,
      },
    },
    // HSTS is safe to leave on Helmet's default even for local plain-HTTP
    // testing: browsers only honor Strict-Transport-Security when it's
    // received over an actual HTTPS connection, so it's a no-op until the
    // TLS-terminating proxy (Nginx Proxy Manager) is actually in front.
  })
);

// Helmet doesn't ship a Permissions-Policy middleware; the driver page needs an
// explicit geolocation allowance or the browser silently blocks the prompt.
app.use((req, res, next) => {
  res.setHeader('Permissions-Policy', 'geolocation=(self)');
  next();
});

app.use(express.json());

const PgSession = pgSessionFactory(session);
const sessionMiddleware = session({
  store: new PgSession({ pool, createTableIfMissing: true }),
  secret: process.env.SESSION_SECRET || 'dev-secret-change-me',
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    sameSite: 'lax',
    // 'auto' marks the cookie Secure only when the request is actually HTTPS
    // (via req.secure, which respects X-Forwarded-Proto once trust proxy is
    // set) — works whether this is reached directly over plain HTTP (local
    // testing) or through Nginx Proxy Manager terminating real TLS in front.
    secure: 'auto',
    maxAge: 1000 * 60 * 60 * 12,
  },
});
app.use(sessionMiddleware);

// Public PWA assets — deliberately unauthenticated, since the browser's own
// "Add to Home Screen" / install machinery fetches these directly and isn't
// guaranteed to carry the session cookie the way a page's own fetch() calls do.
app.get('/manifest.webmanifest', (req, res) => {
  res.type('application/manifest+json');
  res.sendFile(path.join(__dirname, 'views', 'manifest.webmanifest'));
});

app.get('/sw.js', (req, res) => {
  res.type('application/javascript');
  res.sendFile(path.join(__dirname, 'views', 'sw.js'));
});

app.use('/icons', express.static(path.join(__dirname, 'views', 'icons')));
app.use('/assets', express.static(path.join(__dirname, 'views', 'assets')));

function requireRole(role) {
  return (req, res, next) => {
    if (!req.session.user || req.session.user.role !== role) {
      return res.redirect('/login');
    }
    next();
  };
}

app.get('/login', (req, res) => {
  res.sendFile(path.join(__dirname, 'views', 'login.html'));
});

app.post('/api/login', async (req, res) => {
  const { username, password } = req.body || {};
  if (typeof username !== 'string' || typeof password !== 'string') {
    return res.status(400).json({ error: 'Username and password are required.' });
  }

  const result = await pool.query(
    'SELECT id, username, password_hash, role, display_name FROM users WHERE username = $1',
    [username]
  );
  const user = result.rows[0];
  if (!user || !(await bcrypt.compare(password, user.password_hash))) {
    return res.status(401).json({ error: 'Invalid username or password.' });
  }

  req.session.user = {
    id: user.id,
    username: user.username,
    role: user.role,
    displayName: user.display_name,
  };
  res.json({ role: user.role });
});

// A 4-digit PIN is only 10,000 combinations — much weaker than a password —
// so brute-force attempts are rate-limited per IP.
const driverLoginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 10,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Too many login attempts. Please try again later.' },
});

app.post('/api/login/driver', driverLoginLimiter, async (req, res) => {
  const { code, pin } = req.body || {};
  if (typeof code !== 'string' || typeof pin !== 'string') {
    return res.status(400).json({ error: 'Driver code and PIN are required.' });
  }

  const result = await pool.query(
    `SELECT id, username, pin_hash, role, display_name
     FROM users WHERE username = $1 AND role = 'driver' AND active = true`,
    [code]
  );
  const user = result.rows[0];
  // A null pin_hash (no PIN set yet) is always an invalid login, not a
  // bcrypt.compare(pin, null) call — bcryptjs doesn't guarantee that behaves
  // consistently across versions.
  if (!user || !user.pin_hash || !(await bcrypt.compare(pin, user.pin_hash))) {
    return res.status(401).json({ error: 'Invalid driver code or PIN.' });
  }

  req.session.user = {
    id: user.id,
    username: user.username,
    role: user.role,
    displayName: user.display_name,
  };
  res.json({ role: user.role });
});

app.post('/api/logout', (req, res) => {
  req.session.destroy(() => {
    res.clearCookie('connect.sid');
    res.json({ ok: true });
  });
});

app.get('/api/me', (req, res) => {
  if (!req.session.user) return res.status(401).json({ error: 'Not authenticated' });

  const user = { ...req.session.user };
  if (user.role === 'driver') {
    // Lets the driver page tell a real in-progress shift apart from a fresh
    // page load, so a refresh (or the phone briefly losing/regaining the
    // tab) can resume tracking instead of resetting to "Start Shift" — that
    // reset looked like being signed out even though the session was fine.
    const driver = drivers.get(String(user.id));
    user.shiftActive = !!driver && driver.status === 'active';
  }
  res.json(user);
});

app.get('/api/config', (req, res) => {
  res.json({ units: process.env.UNITS === 'imperial' ? 'imperial' : 'metric' });
});

app.get('/driver', requireRole('driver'), (req, res) => {
  res.sendFile(path.join(__dirname, 'views', 'driver.html'));
});

app.get('/dispatch', requireRole('dispatcher'), (req, res) => {
  res.sendFile(path.join(__dirname, 'views', 'dispatch.html'));
});

app.get('/dispatch/drivers', requireRole('dispatcher'), (req, res) => {
  res.sendFile(path.join(__dirname, 'views', 'drivers.html'));
});

const PIN_PATTERN = /^\d{4}$/;

function mapDriverRow(row) {
  return {
    id: row.id,
    code: row.username,
    displayName: row.display_name,
    active: row.active,
    createdAt: row.created_at,
    phone: row.phone,
    vehicleId: row.vehicle_id,
    hasPin: row.has_pin,
    lastActive: row.last_active === undefined ? null : row.last_active,
  };
}

app.get('/api/drivers', requireRole('dispatcher'), async (req, res) => {
  const result = await pool.query(
    `SELECT u.id, u.username, u.display_name, u.active, u.created_at,
            u.phone, u.vehicle_id, (u.pin_hash IS NOT NULL) AS has_pin,
            MAX(lp.recorded_at) AS last_active
     FROM users u
     LEFT JOIN location_pings lp ON lp.user_id = u.id
     WHERE u.role = 'driver'
     GROUP BY u.id
     ORDER BY u.created_at ASC`
  );
  res.json(result.rows.map(mapDriverRow));
});

app.post('/api/drivers', requireRole('dispatcher'), async (req, res) => {
  const { code, displayName, pin, phone, vehicleId } = req.body || {};
  if (typeof code !== 'string' || !code.trim() || typeof displayName !== 'string' || !displayName.trim()) {
    return res.status(400).json({ error: 'Driver code and display name are required.' });
  }
  if (typeof pin !== 'string' || !PIN_PATTERN.test(pin)) {
    return res.status(400).json({ error: 'PIN must be exactly 4 digits.' });
  }

  const pinHash = await bcrypt.hash(pin, 10);
  try {
    const result = await pool.query(
      `INSERT INTO users (username, pin_hash, role, display_name, active, phone, vehicle_id)
       VALUES ($1, $2, 'driver', $3, true, $4, $5)
       RETURNING id, username, display_name, active, created_at, phone, vehicle_id, true AS has_pin`,
      [
        code.trim(),
        pinHash,
        displayName.trim(),
        typeof phone === 'string' && phone.trim() ? phone.trim() : null,
        typeof vehicleId === 'string' && vehicleId.trim() ? vehicleId.trim() : null,
      ]
    );
    res.status(201).json(mapDriverRow(result.rows[0]));
  } catch (err) {
    if (err.code === '23505') {
      return res.status(409).json({ error: 'That driver code is already in use.' });
    }
    console.error('Failed to create driver:', err.message);
    res.status(500).json({ error: 'Failed to create driver.' });
  }
});

app.patch('/api/drivers/:id', requireRole('dispatcher'), async (req, res) => {
  const id = Number(req.params.id);
  if (!Number.isInteger(id)) return res.status(400).json({ error: 'Invalid driver id.' });

  const { displayName, active, pin, phone, vehicleId } = req.body || {};
  const sets = [];
  const values = [];

  if (displayName !== undefined) {
    if (typeof displayName !== 'string' || !displayName.trim()) {
      return res.status(400).json({ error: 'Display name cannot be empty.' });
    }
    values.push(displayName.trim());
    sets.push(`display_name = $${values.length}`);
  }

  if (active !== undefined) {
    if (typeof active !== 'boolean') {
      return res.status(400).json({ error: 'active must be a boolean.' });
    }
    values.push(active);
    sets.push(`active = $${values.length}`);
  }

  if (pin !== undefined) {
    if (typeof pin !== 'string' || !PIN_PATTERN.test(pin)) {
      return res.status(400).json({ error: 'PIN must be exactly 4 digits.' });
    }
    values.push(await bcrypt.hash(pin, 10));
    sets.push(`pin_hash = $${values.length}`);
  }

  if (phone !== undefined) {
    values.push(typeof phone === 'string' && phone.trim() ? phone.trim() : null);
    sets.push(`phone = $${values.length}`);
  }

  if (vehicleId !== undefined) {
    values.push(typeof vehicleId === 'string' && vehicleId.trim() ? vehicleId.trim() : null);
    sets.push(`vehicle_id = $${values.length}`);
  }

  if (!sets.length) {
    return res.status(400).json({ error: 'No fields to update.' });
  }

  values.push(id);
  const result = await pool.query(
    `UPDATE users SET ${sets.join(', ')}
     WHERE id = $${values.length} AND role = 'driver'
     RETURNING id, username, display_name, active, created_at, phone, vehicle_id, (pin_hash IS NOT NULL) AS has_pin`,
    values
  );

  if (!result.rows[0]) return res.status(404).json({ error: 'Driver not found.' });
  res.json(mapDriverRow(result.rows[0]));
});

app.get('/dispatch/history', requireRole('dispatcher'), (req, res) => {
  res.sendFile(path.join(__dirname, 'views', 'history.html'));
});

app.get('/api/history', requireRole('dispatcher'), async (req, res) => {
  const driverId = Number(req.query.driverId);
  if (!Number.isInteger(driverId)) {
    return res.status(400).json({ error: 'driverId is required.' });
  }

  const from = req.query.from ? new Date(req.query.from) : null;
  const to = req.query.to ? new Date(req.query.to) : new Date();
  if (!from || Number.isNaN(from.getTime()) || Number.isNaN(to.getTime())) {
    return res.status(400).json({ error: 'A valid from date (and optional to date) is required.' });
  }

  const driverResult = await pool.query(
    `SELECT id, display_name FROM users WHERE id = $1 AND role = 'driver'`,
    [driverId]
  );
  if (!driverResult.rows[0]) return res.status(404).json({ error: 'Driver not found.' });

  const pingsResult = await pool.query(
    `SELECT latitude, longitude, recorded_at, speed_kmh, speed_limit_kmh
     FROM location_pings
     WHERE user_id = $1 AND recorded_at BETWEEN $2 AND $3
     ORDER BY recorded_at ASC`,
    [driverId, from, to]
  );

  const points = pingsResult.rows.map((row) => ({
    latitude: row.latitude,
    longitude: row.longitude,
    recordedAt: row.recorded_at,
    // Clamped the same way live telemetry is: a handful of pings recorded
    // before that guard existed can still carry an implausible spike (e.g. a
    // stale-fix artifact from a reconnect), and those shouldn't inflate the
    // max-speed figure or get flagged as a real speeding event.
    speedKmh:
      typeof row.speed_kmh === 'number' && row.speed_kmh >= 0 && row.speed_kmh <= MAX_PLAUSIBLE_SPEED_KMH
        ? row.speed_kmh
        : null,
    speedLimitKmh: row.speed_limit_kmh,
  }));

  // A gap this long (well past the ~7s cadence and a couple of missed beats)
  // means the connection dropped for a real stretch, not just a missed ping
  // — the path in between is unknown, so it's excluded from the distance
  // total rather than summed as a straight line between the two endpoints.
  const HISTORY_GAP_MS = 90_000;
  let distanceKm = 0;
  for (let i = 1; i < points.length; i++) {
    const gapMs = new Date(points[i].recordedAt) - new Date(points[i - 1].recordedAt);
    if (gapMs > HISTORY_GAP_MS) continue;
    distanceKm += haversineDistanceKm(points[i - 1], points[i]);
  }

  const knownSpeeds = points.map((p) => p.speedKmh).filter((s) => typeof s === 'number');
  const avgSpeedKmh = knownSpeeds.length ? knownSpeeds.reduce((a, b) => a + b, 0) / knownSpeeds.length : null;
  const maxSpeedKmh = knownSpeeds.length ? Math.max(...knownSpeeds) : null;

  res.json({
    driver: { id: driverResult.rows[0].id, displayName: driverResult.rows[0].display_name },
    points,
    summary: { distanceKm, avgSpeedKmh, maxSpeedKmh, pointCount: points.length },
  });
});

app.get('/health', (req, res) => {
  res.json({ status: 'ok' });
});

app.get('/', (req, res) => {
  if (!req.session.user) return res.redirect('/login');
  res.redirect(req.session.user.role === 'dispatcher' ? '/dispatch' : '/driver');
});

/**
 * In-memory driver state. Not the durable record — Postgres (`location_pings`)
 * logs every ping for history/reporting. This Map is the hot path driving
 * live breadcrumbs/speed/distance without a DB round trip per tick.
 *
 * driverId -> {
 *   driverId, name, status: 'active' | 'ended' | 'disconnected',
 *   history: [{ latitude, longitude, timestamp }, ...] (oldest first, capped at HISTORY_LENGTH),
 *   distanceKm, speedKmh, speedLimitKmh, lastSeen
 * }
 */
const drivers = new Map();

// Haversine formula: great-circle distance in km between two lat/lng points,
// accounting for the Earth's curvature (a flat Pythagorean distance would be
// wrong even over a few km at typical driving speeds).
function haversineDistanceKm(a, b) {
  const R = 6371; // mean Earth radius in km
  const toRad = (deg) => (deg * Math.PI) / 180;

  const dLat = toRad(b.latitude - a.latitude);
  const dLon = toRad(b.longitude - a.longitude);
  const lat1 = toRad(a.latitude);
  const lat2 = toRad(b.latitude);

  const h =
    Math.sin(dLat / 2) ** 2 +
    Math.cos(lat1) * Math.cos(lat2) * Math.sin(dLon / 2) ** 2;
  const c = 2 * Math.atan2(Math.sqrt(h), Math.sqrt(1 - h));

  return R * c;
}

// Distance traveled = sum of Haversine distances between each consecutive
// pair of breadcrumb points. Speed = distance / time between only the last
// two points (an instantaneous rate, not an average over the whole trail).
function computeTelemetry(history) {
  let distanceKm = 0;
  for (let i = 1; i < history.length; i++) {
    distanceKm += haversineDistanceKm(history[i - 1], history[i]);
  }

  // Prefer the device's own GPS-derived speed (Doppler-based, not subject to
  // position-differencing artifacts) when the client supplied one; otherwise
  // fall back to distance/time between the last two points. Unknown (not an
  // artificial 0) until we have something to base it on.
  let speedKmh = null;
  const curr = history[history.length - 1];
  if (curr && typeof curr.deviceSpeedKmh === 'number') {
    speedKmh = curr.deviceSpeedKmh;
  } else if (history.length >= 2) {
    const prev = history[history.length - 2];
    const segmentKm = haversineDistanceKm(prev, curr);
    const deltaHours = (curr.timestamp - prev.timestamp) / 1000 / 3600;
    speedKmh = deltaHours > 0 ? segmentKm / deltaHours : null;
  }

  if (speedKmh !== null && (speedKmh < 0 || speedKmh > MAX_PLAUSIBLE_SPEED_KMH)) {
    speedKmh = null;
  }

  return { distanceKm, speedKmh };
}

function publicDriverState(driver) {
  return {
    driverId: driver.driverId,
    name: driver.name,
    status: driver.status,
    history: driver.history,
    distanceKm: driver.distanceKm,
    speedKmh: driver.speedKmh,
    speedLimitKmh: driver.speedLimitKmh,
    lastSeen: driver.lastSeen,
  };
}

function broadcastSnapshot() {
  io.to('dispatch').emit(
    'drivers_state',
    Array.from(drivers.values()).map(publicDriverState)
  );
}

async function insertPing(userId, latitude, longitude, recordedAtMs, speedKmh, speedLimitKmh) {
  try {
    await pool.query(
      `INSERT INTO location_pings (user_id, latitude, longitude, recorded_at, speed_kmh, speed_limit_kmh)
       VALUES ($1, $2, $3, to_timestamp($4 / 1000.0), $5, $6)`,
      [userId, latitude, longitude, recordedAtMs, speedKmh, speedLimitKmh]
    );
  } catch (err) {
    console.error('Failed to persist location ping:', err.message);
  }
}

// --- Speed limit lookup ------------------------------------------------
// Best-effort "what's the posted limit on the nearest tagged road" lookup
// against the free public Overpass API (OpenStreetMap data) — deliberately
// not a full map-matching/routing pipeline (out of scope by request), just
// enough to tag each ping with a limit to compare its speed against.
const SPEED_LIMIT_LOOKUP_ENABLED = process.env.SPEED_LIMIT_LOOKUP !== 'false';
const OVERPASS_URL = 'https://overpass-api.de/api/interpreter';
const SPEED_LIMIT_LOOKUP_RADIUS_M = 25;
const SPEED_LIMIT_HIT_TTL_MS = 24 * 60 * 60 * 1000; // posted limits rarely change
const SPEED_LIMIT_MISS_TTL_MS = 10 * 60 * 1000; // retry sooner after a miss/failure
// Overpass's public instance has a fair-use policy — this keeps us to well
// under one request/second regardless of how many drivers are pinging.
const SPEED_LIMIT_MIN_INTERVAL_MS = 1000;

// Keyed to ~3 decimal places (~111m grid) rather than a tighter grid: roads
// keep the same posted limit over much longer stretches than that, and a
// coarser grid means far more cache hits per Overpass request, which matters
// a lot given the global throttle above.
function speedLimitCacheKey(latitude, longitude) {
  return `${latitude.toFixed(3)},${longitude.toFixed(3)}`;
}

const speedLimitCache = new Map(); // key -> { speedLimitKmh, expiresAt }
let lastSpeedLimitRequestAt = 0;

function parseMaxSpeedKmh(raw) {
  if (typeof raw !== 'string') return null;
  const mphMatch = raw.match(/^(\d+(\.\d+)?)\s*mph$/i);
  if (mphMatch) return Number(mphMatch[1]) * 1.60934;
  const kmhMatch = raw.match(/^(\d+(\.\d+)?)(\s*km\/h)?$/i);
  if (kmhMatch) return Number(kmhMatch[1]);
  return null; // e.g. "national", "signals", "none" — not a numeric limit
}

async function fetchSpeedLimitKmh(latitude, longitude) {
  const query =
    `[out:json][timeout:5];` +
    `way(around:${SPEED_LIMIT_LOOKUP_RADIUS_M},${latitude},${longitude})[highway][maxspeed];` +
    `out tags 1;`;

  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 5000);
  try {
    const res = await fetch(OVERPASS_URL, {
      method: 'POST',
      // Overpass's public instance returns 406 Not Acceptable to requests
      // with no User-Agent at all (Node's fetch sends none by default).
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        'User-Agent': 'OSDispatch/1.0 (self-hosted driver dispatch tracker)',
      },
      body: 'data=' + encodeURIComponent(query),
      signal: controller.signal,
    });
    if (!res.ok) return null;
    const data = await res.json();
    const way = data.elements && data.elements[0];
    return way ? parseMaxSpeedKmh(way.tags && way.tags.maxspeed) : null;
  } catch (err) {
    console.error('Speed limit lookup failed:', err.message);
    return null;
  } finally {
    clearTimeout(timeout);
  }
}

async function getSpeedLimitKmh(latitude, longitude) {
  if (!SPEED_LIMIT_LOOKUP_ENABLED) return null;

  const key = speedLimitCacheKey(latitude, longitude);
  const cached = speedLimitCache.get(key);
  if (cached && cached.expiresAt > Date.now()) return cached.speedLimitKmh;

  const now = Date.now();
  if (now - lastSpeedLimitRequestAt < SPEED_LIMIT_MIN_INTERVAL_MS) {
    // Throttled — skip this ping's lookup rather than queue it up; the next
    // ping (or a nearby cache hit) will pick it up instead.
    return cached ? cached.speedLimitKmh : null;
  }
  lastSpeedLimitRequestAt = now;

  const speedLimitKmh = await fetchSpeedLimitKmh(latitude, longitude);
  const ttl = speedLimitKmh !== null ? SPEED_LIMIT_HIT_TTL_MS : SPEED_LIMIT_MISS_TTL_MS;
  speedLimitCache.set(key, { speedLimitKmh, expiresAt: Date.now() + ttl });
  return speedLimitKmh;
}

// Share the session middleware with Socket.io so socket.request.session is
// populated from the same cookie the HTTP routes use (Socket.io v4.6+ pattern).
io.engine.use(sessionMiddleware);

io.on('connection', (socket) => {
  const userSession = socket.request.session;
  if (!userSession || !userSession.user) {
    socket.disconnect(true);
    return;
  }

  socket.on('join_dispatch', () => {
    if (userSession.user.role !== 'dispatcher') return;
    socket.join('dispatch');
    socket.emit(
      'drivers_state',
      Array.from(drivers.values()).map(publicDriverState)
    );
  });

  socket.on('location_update', (payload) => {
    if (userSession.user.role !== 'driver') return;

    const { latitude, longitude, timestamp, speed } = payload || {};
    if (
      typeof latitude !== 'number' ||
      typeof longitude !== 'number' ||
      typeof timestamp !== 'number'
    ) {
      return; // malformed payload, drop silently
    }
    // Device-reported speed (m/s, from the Geolocation API's coords.speed) ->
    // km/h, when the client had one to send.
    const deviceSpeedKmh = typeof speed === 'number' && speed >= 0 ? speed * 3.6 : null;

    // Identity always comes from the authenticated session, never the
    // client payload — this is what stops one driver from spoofing another.
    const driverId = String(userSession.user.id);
    const name = userSession.user.displayName;

    let driver = drivers.get(driverId);
    // A ping arriving while the driver wasn't 'active' (a fresh shift start,
    // or a reconnect after going silent) starts a new trail segment instead
    // of appending to the old one — we have no idea what path was taken
    // during the gap, so we don't draw a breadcrumb line across it or let it
    // factor into a distance/speed computed against the stale prior point.
    const isNewSegment = !driver || driver.status !== 'active';
    if (!driver) {
      driver = {
        driverId,
        name,
        status: 'active',
        history: [],
        distanceKm: 0,
        speedKmh: null,
        speedLimitKmh: null,
        lastSeen: timestamp,
      };
      drivers.set(driverId, driver);
    }

    driver.name = name;
    driver.status = 'active';
    driver.lastSeen = timestamp;
    if (isNewSegment) {
      driver.history = [];
    }
    driver.history.push({ latitude, longitude, timestamp, deviceSpeedKmh });
    if (driver.history.length > HISTORY_LENGTH) {
      driver.history.shift();
    }

    const telemetry = computeTelemetry(driver.history);
    driver.distanceKm = telemetry.distanceKm;
    driver.speedKmh = telemetry.speedKmh;

    io.to('dispatch').emit('driver_update', publicDriverState(driver));

    const speedKmhToStore = driver.speedKmh;
    getSpeedLimitKmh(latitude, longitude)
      .catch(() => null)
      .then((speedLimitKmh) => {
        insertPing(userSession.user.id, latitude, longitude, timestamp, speedKmhToStore, speedLimitKmh);
        // The lookup is best-effort and often lags the position broadcast
        // above (cache miss + throttle) — re-broadcast once it resolves so
        // the dashboard's SPEEDING badge catches up rather than never
        // showing up at all.
        driver.speedLimitKmh = speedLimitKmh;
        io.to('dispatch').emit('driver_update', publicDriverState(driver));
      });
  });

  socket.on('end_shift', () => {
    if (userSession.user.role !== 'driver') return;
    const driverId = String(userSession.user.id);
    const driver = drivers.get(driverId);
    if (!driver) return;
    driver.status = 'ended';
    io.to('dispatch').emit('driver_update', publicDriverState(driver));
  });

  socket.on('disconnect', () => {
    // Intentionally no-op: a dropped socket (e.g. phone screen lock) doesn't
    // necessarily mean the shift ended. Staleness is handled by the sweep below.
  });
});

// Periodically flag drivers that have gone silent so the dashboard surfaces
// a dropped connection distinctly from a driver who deliberately ended their
// shift (see the 'disconnected' vs 'ended' status distinction below).
setInterval(() => {
  const now = Date.now();
  let changed = false;
  for (const [driverId, driver] of drivers) {
    if (driver.status === 'active' && now - driver.lastSeen > STALE_TIMEOUT_MS) {
      driver.status = 'disconnected';
      changed = true;
    }
  }
  if (changed) broadcastSnapshot();
}, STALE_SWEEP_INTERVAL_MS);

async function start() {
  await initSchema();
  await seedUsers();
  server.listen(PORT, () => {
    console.log(`Dispatch tracker listening on port ${PORT}`);
  });
}

start().catch((err) => {
  console.error('Failed to start server:', err);
  process.exit(1);
});
