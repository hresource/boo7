const fs = require('fs');
const path = require('path');

let db = { hashes: new Set(), keys: {} };
try {
  const raw = fs.readFileSync(path.join(__dirname, '../data/allowed.json'), 'utf8');
  const json = JSON.parse(raw);
  db.hashes = new Set(json.hashes || []);
  db.keys = json.keys || {};
} catch (e) {}

module.exports = (req, res) => {
  if (req.method !== 'POST') return res.status(405).json({ valid: false });

  const { key_hash, machine_id, expiry } = req.body || {};
  if (!key_hash || !machine_id || !expiry) {
    return res.status(400).json({ valid: false, reason: 'MISSING' });
  }

  if (!db.hashes.has(key_hash)) {
    return res.json({ valid: false, reason: 'REVOKED' });
  }

  const info = db.keys[key_hash];
  if (info && info.machine && info.machine !== machine_id) {
    return res.json({ valid: false, reason: 'MACHINE_MISMATCH' });
  }

  if (new Date(expiry) < new Date()) {
    return res.json({ valid: false, reason: 'EXPIRED' });
  }

  res.json({ valid: true });
};