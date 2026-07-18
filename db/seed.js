const path = require('path');
const fs = require('fs');
const bcrypt = require('bcryptjs');
const { pool } = require('./index');

const SEED_FILE = path.join(__dirname, 'seed-users.json');
const EXAMPLE_SEED_FILE = path.join(__dirname, 'seed-users.example.json');

async function seedUsers() {
  let seedPath = SEED_FILE;
  if (!fs.existsSync(SEED_FILE)) {
    console.warn(
      'db/seed-users.json not found — falling back to db/seed-users.example.json placeholder accounts. ' +
      'Create db/seed-users.json with real accounts before using this outside local testing.'
    );
    seedPath = EXAMPLE_SEED_FILE;
  }

  const users = JSON.parse(fs.readFileSync(seedPath, 'utf8'));

  for (const user of users) {
    // Dispatchers authenticate with a password; drivers with a 4-digit PIN.
    const passwordHash = user.role === 'dispatcher' ? await bcrypt.hash(user.password, 10) : null;
    const pinHash = user.role === 'driver' ? await bcrypt.hash(user.pin, 10) : null;

    // ON CONFLICT DO NOTHING: this seed step only ever creates missing
    // accounts. A credential changed directly in the database is never
    // silently reverted by a later boot.
    await pool.query(
      `INSERT INTO users (username, password_hash, pin_hash, role, display_name, active)
       VALUES ($1, $2, $3, $4, $5, true)
       ON CONFLICT (username) DO NOTHING`,
      [user.username, passwordHash, pinHash, user.role, user.displayName]
    );
  }

  console.log(`Seed check complete: ${users.length} account(s) in ${path.basename(seedPath)}`);
}

module.exports = { seedUsers };
