const express = require('express');
const bodyParser = require('body-parser');
const path = require('path');
const sqlite3 = require('sqlite3').verbose();
const passport = require('passport');
const LocalStrategy = require('passport-local').Strategy;
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const FacebookStrategy = require('passport-facebook').Strategy;
const bcrypt = require('bcrypt');
const multer = require('multer');
const fs = require('fs');
const rateLimit = require('express-rate-limit');

const app = express();
const port = 3000;

const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // limit each IP to 100 requests per windowMs
  message: 'Too many requests from this IP, please try again later.'
});

// Middleware
app.use(bodyParser.json());
app.use(passport.initialize());
app.use(passport.session());

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
const upload = multer({
  storage: storage,
  fileFilter: (req, file, cb) => {
    const allowedTypes = ['image/jpeg', 'image/png', 'application/pdf'];
    if (allowedTypes.includes(file.mimetype)) {
      cb(null, true);
    } else {
      cb(new Error('Tipo de archivo no permitido'), false);
    }
  },
  limits: {
    fileSize: 5 * 1024 * 1024, // 5MB
    files: 5
  }
});

// Initialize SQLite database
const db = new sqlite3.Database('./service-directory.db', (err) => {
  if (err) {
    console.error('Error opening database', err.message);
  } else {
    console.log('Connected to SQLite database.');
  }
});

// Configure Passport strategies
passport.use(new LocalStrategy(
  { usernameField: 'email' },
  async (email, password, done) => {
    try {
      const user = await db.get('SELECT * FROM users WHERE email = ?', [email]);
      if (!user) return done(null, false);
      const isValid = await bcrypt.compare(password, user.password);
      return isValid ? done(null, user) : done(null, false);
    } catch (err) {
      return done(err);
    }
  }
));

/*
passport.use(new GoogleStrategy({
    clientID: process.env.GOOGLE_CLIENT_ID,
    clientSecret: process.env.GOOGLE_CLIENT_SECRET,
    callbackURL: "/auth/google/callback"
  },
  async (accessToken, refreshToken, profile, done) => {
    try {
      let user = await db.get('SELECT * FROM users WHERE googleId = ?', [profile.id]);
      if (!user) {
        await db.run(
          'INSERT INTO users (googleId, email, name) VALUES (?, ?, ?)',
          [profile.id, profile.emails[0].value, profile.displayName]
        );
        user = await db.get('SELECT * FROM users WHERE googleId = ?', [profile.id]);
      }
      return done(null, user);
    } catch (err) {
      return done(err);
    }
  }
));

passport.use(new FacebookStrategy({
    clientID: process.env.FACEBOOK_APP_ID,
    clientSecret: process.env.FACEBOOK_APP_SECRET,
    callbackURL: "/auth/facebook/callback",
    profileFields: ['id', 'emails', 'name']
  },
  async (accessToken, refreshToken, profile, done) => {
    try {
      let user = await db.get('SELECT * FROM users WHERE facebookId = ?', [profile.id]);
      if (!user) {
        await db.run(
          'INSERT INTO users (facebookId, email, name) VALUES (?, ?, ?)',
          [profile.id, profile.emails[0].value, profile.displayName]
        );
        user = await db.get('SELECT * FROM users WHERE facebookId = ?', [profile.id]);
      }
      return done(null, user);
    } catch (err) {
      return done(err);
    }
  }
));
*/

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

const sqlstring = require('sqlstring');

app.post('/providers', async (req, res) => {
  const { name, service, description, contact, location, latitude, longitude, password, email } = req.body;
  if (!name || !service || !contact || !password || !email) {
    return res.status(400).json({ error: 'Name, service, contact, email, and password are required.' });
  }
  try {
    // Hash the password
    const hashedPassword = await bcrypt.hash(password, 10);

    // Insert user record
    const userSql = `INSERT INTO users (username, password, email) VALUES (?, ?, ?)`;
    const userParams = [contact, hashedPassword, email];
    db.run(userSql, userParams, function(err) {
      if (err) {
        console.error(err.message);
        return res.status(500).json({ error: 'Failed to register user' });
      }
      const userId = this.lastID;

      // Insert provider record linked to user
      const providerSql = `INSERT INTO providers (name, service, description, contact, location, latitude, longitude, active) VALUES (?, ?, ?, ?, ?, ?, ?, 1)`;
      const providerParams = [name, service.toLowerCase(), description || '', contact, location || '', parseFloat(latitude) || null, parseFloat(longitude) || null];
      db.run(providerSql, providerParams, function(err) {
        if (err) {
          console.error(err.message);
          return res.status(500).json({ error: 'Failed to register provider' });
        }
        res.status(201).json({ userId, providerId: this.lastID, active: 1 });
      });
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Server error during registration' });
  }
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

app.post('/users/register', authLimiter, async (req, res) => {
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

app.post('/users/login', authLimiter, (req, res) => {
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

// Authentication routes
app.get('/auth/google',
  passport.authenticate('google', { scope: ['profile', 'email'] }));

app.get('/auth/google/callback', 
  passport.authenticate('google', { failureRedirect: '/login' }),
  (req, res) => res.redirect('/profile'));

app.get('/auth/facebook',
  passport.authenticate('facebook', { scope: ['email'] }));

app.get('/auth/facebook/callback',
  passport.authenticate('facebook', { failureRedirect: '/login' }),
  (req, res) => res.redirect('/profile'));

// Explicitly serve index.html on root route
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Start server
app.listen(port, () => {
  console.log("Service Directory API listening at http://localhost:" + port);
});
