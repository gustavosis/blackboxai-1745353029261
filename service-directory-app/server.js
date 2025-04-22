const express = require('express');
const bodyParser = require('body-parser');
const path = require('path');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcrypt');
const multer = require('multer');
const fs = require('fs');

const app = express();
const port = 3000;

// Middleware
app.use(bodyParser.json());

// Serve static files from the 'public' directory
app.use(express.static(path.join(__dirname, 'public')));

// Setup multer for file uploads
const uploadDir = path.join(__dirname, 'uploads');
if (!fs.existsSync(uploadDir)) {
  fs.mkdirSync(uploadDir);
}
const storage = multer.diskStorage({
  destination: function (req, file, cb) {
    cb(null, uploadDir);
  },
  filename: function (req, file, cb) {
    const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
    cb(null, uniqueSuffix + '-' + file.originalname);
  }
});
const upload = multer({ storage: storage });

// Initialize SQLite database
const db = new sqlite3.Database('./service-directory.db', (err) => {
  if (err) {
    console.error('Error opening database', err.message);
  } else {
    console.log('Connected to SQLite database.');
  }
});

// Create tables if not exist
db.serialize(() => {
  db.run(`CREATE TABLE IF NOT EXISTS providers (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    service TEXT NOT NULL,
    description TEXT,
    contact TEXT NOT NULL,
    location TEXT,
    latitude REAL,
    longitude REAL,
    active INTEGER DEFAULT 1
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL UNIQUE,
    password TEXT NOT NULL,
    email TEXT,
    role TEXT DEFAULT 'user'
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS service_requests (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    provider_id INTEGER,
    location TEXT NOT NULL,
    status TEXT DEFAULT 'pending',
    communication TEXT,
    eta TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(user_id) REFERENCES users(id),
    FOREIGN KEY(provider_id) REFERENCES providers(id)
  )`);

  // New table for provider documents (photos, diplomas, etc)
  db.run(`CREATE TABLE IF NOT EXISTS provider_documents (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    provider_id INTEGER NOT NULL,
    type TEXT NOT NULL, -- e.g. 'photo', 'diploma'
    file_path TEXT NOT NULL,
    uploaded_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(provider_id) REFERENCES providers(id)
  )`);
});

app.post('/providers', (req, res) => {
  const { name, service, description, contact, location, latitude, longitude } = req.body;
  if (!name || !service || !contact) {
    return res.status(400).json({ error: 'Name, service, and contact are required.' });
  }
  const sql = `INSERT INTO providers (name, service, description, contact, location, latitude, longitude, active)
               VALUES (?, ?, ?, ?, ?, ?, ?, 1)`;
  const params = [name, service.toLowerCase(), description || '', contact, location || '', latitude || null, longitude || null];
  db.run(sql, params, function(err) {
    if (err) {
      console.error(err.message);
      return res.status(500).json({ error: 'Failed to register provider' });
    }
    res.status(201).json({ id: this.lastID, ...req.body, active: 1 });
  });
});

// POST /providers/:id/documents - Upload provider documents (photos, diplomas)
app.post('/providers/:id/documents', upload.array('documents', 10), (req, res) => {
  const providerId = req.params.id;
  if (!req.files || req.files.length === 0) {
    return res.status(400).json({ error: 'No files uploaded' });
  }
  const stmt = db.prepare(`INSERT INTO provider_documents (provider_id, type, file_path) VALUES (?, ?, ?)`);
  req.files.forEach(file => {
    // Determine type by mimetype or originalname extension
    let type = 'photo';
    if (file.originalname.match(/\.(jpg|jpeg|png|gif)$/i)) {
      type = 'photo';
    } else if (file.originalname.match(/\.(pdf|doc|docx)$/i)) {
      type = 'diploma';
    }
    stmt.run(providerId, type, file.filename);
  });
  stmt.finalize(err => {
    if (err) {
      console.error(err.message);
      return res.status(500).json({ error: 'Failed to save documents' });
    }
    res.status(201).json({ message: 'Documents uploaded successfully' });
  });
});

app.get('/providers', (req, res) => {
  const search = (req.query.search || '').toLowerCase();
  const lat = parseFloat(req.query.lat);
  const lng = parseFloat(req.query.lng);
  const radius = parseFloat(req.query.radius) || 10; // default radius in km

  let sql = `SELECT *, 
    ( 6371 * acos( cos( radians(?) ) * cos( radians(latitude) ) * cos( radians(longitude) - radians(?) ) + sin( radians(?) ) * sin( radians(latitude) ) ) ) AS distance 
    FROM providers WHERE active = 1`;
  let params = [lat, lng, lat];

  if (search) {
    sql += ` AND service LIKE ?`;
    params.push(`%${search}%`);
  }

  sql += ` HAVING distance <= ? ORDER BY distance ASC`;
  params.push(radius);

  db.all(sql, params, (err, rows) => {
    if (err) {
      console.error(err.message);
      return res.status(500).json({ error: 'Failed to fetch providers' });
    }
    res.json(rows);
  });
});

app.post('/users/register', async (req, res) => {
  const { username, password, email, role } = req.body;
  if (!username || !password) {
    return res.status(400).json({ error: 'Username and password are required.' });
  }
  try {
    const hashedPassword = await bcrypt.hash(password, 10);
    const sql = `INSERT INTO users (username, password, email, role) VALUES (?, ?, ?, ?)`;
    const params = [username, hashedPassword, email || '', role || 'user'];
    db.run(sql, params, function(err) {
      if (err) {
        console.error(err.message);
        return res.status(500).json({ error: 'Failed to register user' });
      }
      res.status(201).json({ id: this.lastID, username, email, role: role || 'user' });
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Error hashing password' });
  }
});

app.post('/users/login', (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) {
    return res.status(400).json({ error: 'Username and password are required.' });
  }
  const sql = `SELECT * FROM users WHERE username = ?`;
  db.get(sql, [username], async (err, row) => {
    if (err) {
      console.error(err.message);
      return res.status(500).json({ error: 'Login failed' });
    }
    if (!row) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }
    try {
      const match = await bcrypt.compare(password, row.password);
      if (!match) {
        return res.status(401).json({ error: 'Invalid credentials' });
      }
      res.json({ message: 'Login successful', user: { id: row.id, username: row.username, email: row.email, role: row.role } });
    } catch (error) {
      console.error(error);
      res.status(500).json({ error: 'Error during login' });
    }
  });
});

app.post('/service_requests', (req, res) => {
  const { user_id, provider_id, location } = req.body;
  if (!location) {
    return res.status(400).json({ error: 'Location is required.' });
  }
  // Allow user_id to be null for unregistered users
  const sql = `INSERT INTO service_requests (user_id, provider_id, location, status, created_at, updated_at)
               VALUES (?, ?, ?, 'pending', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)`;
  const params = [user_id || null, provider_id || null, location];
  db.run(sql, params, function(err) {
    if (err) {
      console.error(err.message);
      return res.status(500).json({ error: 'Failed to create service request' });
    }
    res.status(201).json({ id: this.lastID, user_id, provider_id, location, status: 'pending' });
  });
});

// PUT /service_requests/:id - Update a service request (status, communication, eta)
app.put('/service_requests/:id', (req, res) => {
  const { id } = req.params;
  const { status, communication, eta } = req.body;
  const sql = `UPDATE service_requests SET
               status = COALESCE(?, status),
               communication = COALESCE(?, communication),
               eta = COALESCE(?, eta),
               updated_at = CURRENT_TIMESTAMP
               WHERE id = ?`;
  const params = [status, communication, eta, id];
  db.run(sql, params, function(err) {
    if (err) {
      console.error(err.message);
      return res.status(500).json({ error: 'Failed to update service request' });
    }
    res.json({ message: 'Service request updated' });
  });
});

// GET /service_requests/:id - Get service request by ID
app.get('/service_requests/:id', (req, res) => {
  const { id } = req.params;
  const sql = `SELECT * FROM service_requests WHERE id = ?`;
  db.get(sql, [id], (err, row) => {
    if (err) {
      console.error(err.message);
      return res.status(500).json({ error: 'Failed to fetch service request' });
    }
    if (!row) {
      return res.status(404).json({ error: 'Service request not found' });
    }
    res.json(row);
  });
});

// Explicitly serve index.html on root route
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Start server
app.listen(port, () => {
  console.log("Service Directory API listening at http://localhost:" + port);
});
