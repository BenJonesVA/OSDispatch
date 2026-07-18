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
        scriptSrc: ["'self'", "'unsafe-inline'", 'https://cdn.tailwindcss.com', 'https://unpkg.com'],
        styleSrc: ["'self'", "'unsafe-inline'", 'https://unpkg.com'],
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
  res.json(req.session.user);
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

app.get('/api/drivers', requireRole('dispatcher'), async (req, res) => {
  const result = await pool.query(
    `SELECT id, username, display_name, active, created_at
     FROM users WHERE role = 'driver' ORDER BY created_at ASC`
  );
  res.json(
    result.rows.map((row) => ({
      id: row.id,
      code: row.username,
      displayName: row.display_name,
      active: row.active,
      createdAt: row.created_at,
    }))
  );
});

app.post('/api/drivers', requireRole('dispatcher'), async (req, res) => {
  const { code, displayName, pin } = req.body || {};
  if (typeof code !== 'string' || !code.trim() || typeof displayName !== 'string' || !displayName.trim()) {
    return res.status(400).json({ error: 'Driver code and display name are required.' });
  }
  if (typeof pin !== 'string' || !PIN_PATTERN.test(pin)) {
    return res.status(400).json({ error: 'PIN must be exactly 4 digits.' });
  }

  const pinHash = await bcrypt.hash(pin, 10);
  try {
    const result = await pool.query(
      `INSERT INTO users (username, pin_hash, role, display_name, active)
       VALUES ($1, $2, 'driver', $3, true)
       RETURNING id, username, display_name, active, created_at`,
      [code.trim(), pinHash, displayName.trim()]
    );
    const row = result.rows[0];
    res.status(201).json({
      id: row.id,
      code: row.username,
      displayName: row.display_name,
      active: row.active,
      createdAt: row.created_at,
    });
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

  const { displayName, active, pin } = req.body || {};
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

  if (!sets.length) {
    return res.status(400).json({ error: 'No fields to update.' });
  }

  values.push(id);
  const result = await pool.query(
    `UPDATE users SET ${sets.join(', ')}
     WHERE id = $${values.length} AND role = 'driver'
     RETURNING id, username, display_name, active, created_at`,
    values
  );

  if (!result.rows[0]) return res.status(404).json({ error: 'Driver not found.' });
  const row = result.rows[0];
  res.json({
    id: row.id,
    code: row.username,
    displayName: row.display_name,
    active: row.active,
    createdAt: row.created_at,
  });
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
    `SELECT latitude, longitude, recorded_at, speed_kmh
     FROM location_pings
     WHERE user_id = $1 AND recorded_at BETWEEN $2 AND $3
     ORDER BY recorded_at ASC`,
    [driverId, from, to]
  );

  const points = pingsResult.rows.map((row) => ({
    latitude: row.latitude,
    longitude: row.longitude,
    recordedAt: row.recorded_at,
    speedKmh: row.speed_kmh,
  }));

  // Distance is recomputed from the raw historical points (not read from any
  // stored total) so it reflects exactly the requested date range.
  let distanceKm = 0;
  for (let i = 1; i < points.length; i++) {
    distanceKm += haversineDistanceKm(points[i - 1], points[i]);
  }

  // speed_kmh is null for any ping recorded before that column existed —
  // excluded here rather than treated as 0, so old gaps don't drag the
  // average down or hide a real max from before the gap.
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
 *   distanceKm, speedKmh, lastSeen
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

  let speedKmh = 0;
  if (history.length >= 2) {
    const prev = history[history.length - 2];
    const curr = history[history.length - 1];
    const segmentKm = haversineDistanceKm(prev, curr);
    const deltaHours = (curr.timestamp - prev.timestamp) / 1000 / 3600;
    speedKmh = deltaHours > 0 ? segmentKm / deltaHours : 0;
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
    lastSeen: driver.lastSeen,
  };
}

function broadcastSnapshot() {
  io.to('dispatch').emit(
    'drivers_state',
    Array.from(drivers.values()).map(publicDriverState)
  );
}

async function insertPing(userId, latitude, longitude, recordedAtMs, speedKmh) {
  try {
    await pool.query(
      `INSERT INTO location_pings (user_id, latitude, longitude, recorded_at, speed_kmh)
       VALUES ($1, $2, $3, to_timestamp($4 / 1000.0), $5)`,
      [userId, latitude, longitude, recordedAtMs, speedKmh]
    );
  } catch (err) {
    console.error('Failed to persist location ping:', err.message);
  }
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

    const { latitude, longitude, timestamp } = payload || {};
    if (
      typeof latitude !== 'number' ||
      typeof longitude !== 'number' ||
      typeof timestamp !== 'number'
    ) {
      return; // malformed payload, drop silently
    }

    // Identity always comes from the authenticated session, never the
    // client payload — this is what stops one driver from spoofing another.
    const driverId = String(userSession.user.id);
    const name = userSession.user.displayName;

    let driver = drivers.get(driverId);
    if (!driver) {
      driver = {
        driverId,
        name,
        status: 'active',
        history: [],
        distanceKm: 0,
        speedKmh: 0,
        lastSeen: timestamp,
      };
      drivers.set(driverId, driver);
    }

    driver.name = name;
    driver.status = 'active';
    driver.lastSeen = timestamp;
    driver.history.push({ latitude, longitude, timestamp });
    if (driver.history.length > HISTORY_LENGTH) {
      driver.history.shift();
    }

    const telemetry = computeTelemetry(driver.history);
    driver.distanceKm = telemetry.distanceKm;
    driver.speedKmh = telemetry.speedKmh;

    io.to('dispatch').emit('driver_update', publicDriverState(driver));

    insertPing(userSession.user.id, latitude, longitude, timestamp, driver.speedKmh);
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
