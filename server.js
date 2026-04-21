const express = require('express');
const mysql = require('mysql2/promise');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const PDFDocument = require('pdfkit');
const csv = require('csv-parser');
const axios = require('axios');
const nodemailer = require('nodemailer');
const crypto = require('crypto');
const {
  generateRegistrationOptions,
  verifyRegistrationResponse,
  generateAuthenticationOptions,
  verifyAuthenticationResponse,
} = require('@simplewebauthn/server');

require('dotenv').config();

const app = express();

/* =========================
   APP CONFIG
========================= */
const CLIENT_ORIGIN = process.env.CLIENT_ORIGIN || 'http://localhost:5500';
const CLIENT_ORIGINS = (process.env.CLIENT_ORIGINS || CLIENT_ORIGIN)
  .split(',')
  .map(v => v.trim())
  .filter(Boolean);

app.use(cors({
  origin(origin, cb) {
    if (!origin) return cb(null, true);
    if (CLIENT_ORIGINS.includes(origin)) return cb(null, true);
    return cb(new Error('CORS blocked'));
  },
  credentials: true,
}));

app.use(express.json({ limit: '15mb' }));
app.use(express.urlencoded({ extended: true }));

app.use(express.static(path.join(__dirname, 'public')));

const uploadDir = process.env.RENDER_DISK_PATH || path.join(__dirname, 'uploads');
if (!fs.existsSync(uploadDir)) fs.mkdirSync(uploadDir, { recursive: true });
app.use('/uploads', express.static(uploadDir));

const storage = multer.diskStorage({
  destination: (_, __, cb) => cb(null, uploadDir),
  filename: (_, file, cb) => {
    const safeName = file.originalname.replace(/\s+/g, '_').replace(/[^\w.\-]/g, '');
    cb(null, `${Date.now()}_${safeName}`);
  }
});
const upload = multer({ storage });

/* =========================
   DATABASE
========================= */
const dbConfig = {
  connectionLimit: 10,
  waitForConnections: true,
  multipleStatements: true
};

if (process.env.DATABASE_URL) {
  dbConfig.uri = process.env.DATABASE_URL;
  dbConfig.ssl = { rejectUnauthorized: false };
} else {
  dbConfig.host = process.env.DB_HOST;
  dbConfig.user = process.env.DB_USER;
  dbConfig.password = process.env.DB_PASSWORD;
  dbConfig.database = process.env.DB_NAME;
}

const pool = mysql.createPool(dbConfig);

async function queryOne(sql, params = []) {
  const [rows] = await pool.query(sql, params);
  return rows[0] || null;
}

/* =========================
   EMAIL
========================= */
const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS
  }
});

async function sendMail({ to, subject, html }) {
  if (!process.env.EMAIL_USER || !process.env.EMAIL_PASS) {
    console.warn('Email credentials missing. Skipping email send.');
    return;
  }

  await transporter.sendMail({
    from: process.env.EMAIL_FROM || process.env.EMAIL_USER,
    to,
    subject,
    html
  });
}

/* =========================
   AUTH HELPERS
========================= */
function signToken(user) {
  return jwt.sign(
    {
      id: user.id,
      name: user.name,
      email: user.email || null,
      role: user.role,
      referral_code: user.referral_code || null,
      points: user.points || 0
    },
    process.env.JWT_SECRET,
    { expiresIn: '24h' }
  );
}

function authenticateToken(req, res, next) {
  const authHeader = req.headers.authorization || '';
  const token = authHeader.startsWith('Bearer ') ? authHeader.slice(7) : null;
  if (!token) return res.status(401).json({ error: 'Unauthorized' });

  jwt.verify(token, process.env.JWT_SECRET, (err, payload) => {
    if (err) return res.status(403).json({ error: 'Invalid token' });
    req.user = payload;
    next();
  });
}

function isAdmin(req, res, next) {
  if (req.user.role !== 'admin') return res.status(403).json({ error: 'Admin only' });
  next();
}

function isCustomer(req, res, next) {
  if (req.user.role === 'admin') return res.status(403).json({ error: 'Admins cannot shop' });
  next();
}

async function logAdminAction(req, action) {
  try {
    await pool.query(
      'INSERT INTO audit_logs (user_id, user_name, action) VALUES (?, ?, ?)',
      [req.user?.id || 0, req.user?.name || 'System', action]
    );
  } catch (err) {
    console.error('Audit log failed:', err.message);
  }
}

/* =========================
   WEBAUTHN HELPERS
========================= */
const rpName = process.env.WEBAUTHN_RP_NAME || 'UrbanMart';
const rpID = process.env.WEBAUTHN_RP_ID || 'localhost';
const expectedOrigins = (process.env.WEBAUTHN_ORIGINS || CLIENT_ORIGIN)
  .split(',')
  .map(v => v.trim())
  .filter(Boolean);

function toBase64URL(buffer) {
  return Buffer.from(buffer).toString('base64url');
}

function fromBase64URL(value) {
  return Buffer.from(value, 'base64url');
}

/* =========================
   DATABASE INIT
========================= */
async function initializeDatabase() {
  try {
    console.log('Initializing database...');

    await pool.query(`
      CREATE TABLE IF NOT EXISTS categories (
        id INT AUTO_INCREMENT PRIMARY KEY,
        name VARCHAR(100) NOT NULL,
        slug VARCHAR(100) UNIQUE NOT NULL,
        icon VARCHAR(50) DEFAULT 'fa-tag'
      );

      CREATE TABLE IF NOT EXISTS products (
        id INT AUTO_INCREMENT PRIMARY KEY,
        name VARCHAR(255) NOT NULL,
        category_slug VARCHAR(100),
        price DECIMAL(10,2) NOT NULL,
        old_price DECIMAL(10,2),
        stock INT NOT NULL DEFAULT 0,
        image VARCHAR(255),
        description TEXT,
        rating DECIMAL(3,1) DEFAULT 4.0,
        is_best_selling BOOLEAN DEFAULT FALSE,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (category_slug) REFERENCES categories(slug) ON DELETE SET NULL
      );

      CREATE TABLE IF NOT EXISTS users (
        id INT AUTO_INCREMENT PRIMARY KEY,
        name VARCHAR(100) NOT NULL,
        email VARCHAR(100) UNIQUE NOT NULL,
        password VARCHAR(255) NOT NULL,
        role ENUM('customer') DEFAULT 'customer',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );

      CREATE TABLE IF NOT EXISTS loyalty (
        user_id INT PRIMARY KEY,
        referral_code VARCHAR(20) UNIQUE NOT NULL,
        points INT DEFAULT 0,
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
      );

      CREATE TABLE IF NOT EXISTS cart (
        id INT AUTO_INCREMENT PRIMARY KEY,
        user_id INT NOT NULL,
        product_id INT NOT NULL,
        quantity INT NOT NULL DEFAULT 1,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
        FOREIGN KEY (product_id) REFERENCES products(id) ON DELETE CASCADE
      );

      CREATE TABLE IF NOT EXISTS orders (
        id INT AUTO_INCREMENT PRIMARY KEY,
        order_number VARCHAR(50) UNIQUE NOT NULL,
        user_id INT NOT NULL,
        customer_name VARCHAR(100) NOT NULL,
        total DECIMAL(10,2) NOT NULL,
        status ENUM('Pending','Processing','Packed','Shipped','Delivered','Cancelled') DEFAULT 'Pending',
        mpesa_receipt VARCHAR(100),
        checkout_request_id VARCHAR(120),
        merchant_request_id VARCHAR(120),
        payment_method VARCHAR(40) DEFAULT 'COD',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
      );

      CREATE TABLE IF NOT EXISTS order_items (
        id INT AUTO_INCREMENT PRIMARY KEY,
        order_id INT NOT NULL,
        product_id INT NOT NULL,
        product_name VARCHAR(255) NOT NULL,
        quantity INT NOT NULL,
        price DECIMAL(10,2) NOT NULL,
        FOREIGN KEY (order_id) REFERENCES orders(id) ON DELETE CASCADE
      );

      CREATE TABLE IF NOT EXISTS settings (
        id INT PRIMARY KEY,
        hero_product_id INT,
        color_primary VARCHAR(20) DEFAULT '#0f172a',
        color_secondary VARCHAR(20) DEFAULT '#1e293b',
        color_accent VARCHAR(20) DEFAULT '#10b981',
        color_bg VARCHAR(20) DEFAULT '#f8fafc',
        color_surface VARCHAR(20) DEFAULT '#ffffff',
        FOREIGN KEY (hero_product_id) REFERENCES products(id) ON DELETE SET NULL
      );

      CREATE TABLE IF NOT EXISTS audit_logs (
        id INT AUTO_INCREMENT PRIMARY KEY,
        user_id INT,
        user_name VARCHAR(100),
        action VARCHAR(255) NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );

      CREATE TABLE IF NOT EXISTS coupons (
        id INT AUTO_INCREMENT PRIMARY KEY,
        code VARCHAR(50) UNIQUE NOT NULL,
        discount_percent INT NOT NULL,
        is_active BOOLEAN DEFAULT TRUE
      );

      CREATE TABLE IF NOT EXISTS reviews (
        id INT AUTO_INCREMENT PRIMARY KEY,
        product_id INT NOT NULL,
        user_id INT NOT NULL,
        rating INT NOT NULL,
        comment TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (product_id) REFERENCES products(id) ON DELETE CASCADE,
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
      );

      CREATE TABLE IF NOT EXISTS password_resets (
        id INT AUTO_INCREMENT PRIMARY KEY,
        email VARCHAR(100) NOT NULL,
        token VARCHAR(255) NOT NULL,
        expires_at DATETIME NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );

      CREATE TABLE IF NOT EXISTS addresses (
        id INT AUTO_INCREMENT PRIMARY KEY,
        user_id INT NOT NULL,
        label VARCHAR(100) NOT NULL,
        recipient_name VARCHAR(120) NOT NULL,
        phone VARCHAR(30) NOT NULL,
        county VARCHAR(100) NOT NULL,
        city VARCHAR(100) NOT NULL,
        area VARCHAR(100) NOT NULL,
        address_line VARCHAR(255) NOT NULL,
        is_default BOOLEAN DEFAULT FALSE,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
      );

      CREATE TABLE IF NOT EXISTS webauthn_credentials (
        id INT AUTO_INCREMENT PRIMARY KEY,
        user_id INT NOT NULL,
        credential_id VARCHAR(255) UNIQUE NOT NULL,
        public_key TEXT NOT NULL,
        counter BIGINT DEFAULT 0,
        transports VARCHAR(255),
        device_type VARCHAR(50),
        backed_up BOOLEAN DEFAULT FALSE,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
      );

      CREATE TABLE IF NOT EXISTS webauthn_challenges (
        id INT AUTO_INCREMENT PRIMARY KEY,
        user_id INT,
        email VARCHAR(100),
        purpose ENUM('register','login') NOT NULL,
        challenge TEXT NOT NULL,
        expires_at DATETIME NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );
    `);

    const [catRows] = await pool.query('SELECT COUNT(*) as count FROM categories');
    if (catRows[0].count === 0) {
      await pool.query(`
        INSERT INTO categories (name, slug, icon) VALUES
        ('Smartphone & Tablet', 'smartphone-tablet', 'fa-mobile-screen-button'),
        ('Watch & Jewelry', 'watch-jewelry', 'fa-clock'),
        ('Audio', 'audio', 'fa-headphones'),
        ('Accessories', 'accessories', 'fa-plug-circle-bolt')
      `);
    }

    const [couponRows] = await pool.query('SELECT COUNT(*) as count FROM coupons');
    if (couponRows[0].count === 0) {
      await pool.query(`INSERT INTO coupons (code, discount_percent, is_active) VALUES ('DISCOUNT10', 10, TRUE)`);
    }

    const [setRows] = await pool.query('SELECT COUNT(*) as count FROM settings');
    if (setRows[0].count === 0) {
      await pool.query(`INSERT INTO settings (id, color_primary) VALUES (1, '#0f172a')`);
    }

    console.log('Database initialized successfully.');
  } catch (err) {
    console.error('Database initialization failed:', err.message);
  }
}

/* =========================
   M-PESA HELPERS
========================= */
function getMpesaBaseUrl() {
  return process.env.MPESA_ENV === 'production'
    ? 'https://api.safaricom.co.ke'
    : 'https://sandbox.safaricom.co.ke';
}

async function getMpesaAccessToken() {
  const url = `${getMpesaBaseUrl()}/oauth/v1/generate?grant_type=client_credentials`;
  const auth = Buffer.from(`${process.env.MPESA_CONSUMER_KEY}:${process.env.MPESA_CONSUMER_SECRET}`).toString('base64');

  const response = await axios.get(url, {
    headers: { Authorization: `Basic ${auth}` }
  });

  return response.data.access_token;
}

function getMpesaTimestamp() {
  const d = new Date();
  const YYYY = d.getFullYear();
  const MM = String(d.getMonth() + 1).padStart(2, '0');
  const DD = String(d.getDate()).padStart(2, '0');
  const HH = String(d.getHours()).padStart(2, '0');
  const mm = String(d.getMinutes()).padStart(2, '0');
  const ss = String(d.getSeconds()).padStart(2, '0');
  return `${YYYY}${MM}${DD}${HH}${mm}${ss}`;
}

function getMpesaPassword(shortcode, passkey, timestamp) {
  return Buffer.from(`${shortcode}${passkey}${timestamp}`).toString('base64');
}

/* =========================
   CORE ROUTES
========================= */
app.get('/api/health', (_, res) => {
  res.json({ ok: true, service: 'UrbanMart API', timestamp: Date.now() });
});

app.get('/api/heartbeat', (_, res) => {
  res.json({ ok: true, timestamp: Date.now() });
});

app.get('/api/bootstrap', async (_, res) => {
  try {
    const [[products], [categories], [settings]] = await Promise.all([
      pool.query('SELECT * FROM products ORDER BY is_best_selling DESC, created_at DESC, id DESC'),
      pool.query('SELECT * FROM categories ORDER BY name ASC'),
      pool.query('SELECT * FROM settings WHERE id = 1')
    ]);

    res.json({
      products,
      categories,
      settings: settings[0] || {}
    });
  } catch {
    res.status(500).json({ error: 'Failed to load store data' });
  }
});

/* =========================
   AUTH ROUTES
========================= */
app.post('/api/auth/register', async (req, res) => {
  const connection = await pool.getConnection();
  try {
    await connection.beginTransaction();

    const { name, email, password, referral_code } = req.body;
    if (!name || !email || !password) throw new Error('All fields are required');
    if (String(password).length < 8) throw new Error('Password must be at least 8 characters');

    const existing = await queryOne('SELECT id FROM users WHERE email = ?', [String(email).toLowerCase().trim()]);
    if (existing) throw new Error('Email already exists');

    const hashed = await bcrypt.hash(password, 10);
    const [userResult] = await connection.query(
      'INSERT INTO users (name, email, password, role) VALUES (?, ?, ?, ?)',
      [name, String(email).toLowerCase().trim(), hashed, 'customer']
    );

    const userId = userResult.insertId;
    const newRefCode = 'UM' + Math.random().toString(36).substring(2, 8).toUpperCase();

    await connection.query(
      'INSERT INTO loyalty (user_id, referral_code, points) VALUES (?, ?, 0)',
      [userId, newRefCode]
    );

    if (referral_code) {
      const referrer = await queryOne('SELECT user_id FROM loyalty WHERE referral_code = ?', [referral_code]);
      if (referrer) {
        await connection.query('UPDATE loyalty SET points = points + 500 WHERE user_id = ?', [referrer.user_id]);
      }
    }

    await connection.commit();
    res.status(201).json({ message: 'Account created successfully' });
  } catch (err) {
    await connection.rollback();
    res.status(400).json({ error: err.message || 'Registration failed' });
  } finally {
    connection.release();
  }
});

app.post('/api/auth/login', async (req, res) => {
  try {
    const email = String(req.body.email || '').trim().toLowerCase();
    const password = String(req.body.password || '');
    const adminEmail = String(process.env.ADMIN_EMAIL || '').trim().toLowerCase();

    if (email === adminEmail && password === process.env.ADMIN_PASSWORD) {
      const adminUser = {
        id: 0,
        name: 'System Administrator',
        email: adminEmail,
        role: 'admin',
        referral_code: null,
        points: 0
      };
      await logAdminAction({ user: adminUser }, 'Admin logged into system');
      return res.json({ token: signToken(adminUser), user: adminUser });
    }

    const user = await queryOne(`
      SELECT u.*, l.referral_code, l.points
      FROM users u
      LEFT JOIN loyalty l ON u.id = l.user_id
      WHERE u.email = ?
    `, [email]);

    if (!user) return res.status(400).json({ error: 'Invalid credentials' });

    const valid = await bcrypt.compare(password, user.password);
    if (!valid) return res.status(400).json({ error: 'Invalid credentials' });

    const payloadUser = {
      id: user.id,
      name: user.name,
      email: user.email,
      role: user.role,
      referral_code: user.referral_code,
      points: user.points || 0
    };

    res.json({ token: signToken(payloadUser), user: payloadUser });
  } catch {
    res.status(500).json({ error: 'Login failed' });
  }
});

app.post('/api/auth/forgot-password', async (req, res) => {
  try {
    const email = String(req.body.email || '').trim().toLowerCase();
    if (!email) return res.status(400).json({ error: 'Email is required' });

    const user = await queryOne('SELECT id, name, email FROM users WHERE email = ?', [email]);
    if (!user) return res.status(404).json({ error: 'User not found' });

    const token = crypto.randomBytes(32).toString('hex');
    const expiresAt = new Date(Date.now() + 60 * 60 * 1000);

    await pool.query('DELETE FROM password_resets WHERE email = ?', [email]);
    await pool.query(
      'INSERT INTO password_resets (email, token, expires_at) VALUES (?, ?, ?)',
      [email, token, expiresAt]
    );

    const resetLink = `${CLIENT_ORIGIN}/?resetToken=${token}`;

    await sendMail({
      to: email,
      subject: 'UrbanMart Password Reset',
      html: `
        <div style="font-family:Arial,sans-serif;line-height:1.7">
          <h2>Password Reset</h2>
          <p>Hello ${user.name},</p>
          <p>You requested a password reset for your UrbanMart account.</p>
          <p><a href="${resetLink}" target="_blank">Click here to reset your password</a></p>
          <p>This link expires in 1 hour.</p>
        </div>
      `
    });

    res.json({ message: 'Reset link sent to email' });
  } catch (err) {
    res.status(500).json({ error: 'Failed to send reset link' });
  }
});

app.post('/api/auth/reset-password', async (req, res) => {
  try {
    const { token, password } = req.body;
    if (!token || !password) return res.status(400).json({ error: 'Token and password are required' });
    if (String(password).length < 8) return res.status(400).json({ error: 'Password must be at least 8 characters' });

    const reset = await queryOne('SELECT * FROM password_resets WHERE token = ?', [token]);
    if (!reset) return res.status(400).json({ error: 'Invalid token' });

    if (new Date(reset.expires_at).getTime() < Date.now()) {
      return res.status(400).json({ error: 'Token expired' });
    }

    const hashed = await bcrypt.hash(password, 10);
    await pool.query('UPDATE users SET password = ? WHERE email = ?', [hashed, reset.email]);
    await pool.query('DELETE FROM password_resets WHERE token = ?', [token]);

    res.json({ message: 'Password updated successfully' });
  } catch {
    res.status(500).json({ error: 'Password reset failed' });
  }
});

app.get('/api/auth/verify-email', (_, res) => {
  res.json({ message: 'Email verification route ready' });
});

/* =========================
   WEBAUTHN ROUTES
========================= */
app.post('/api/webauthn/register/options', authenticateToken, isCustomer, async (req, res) => {
  try {
    const user = await queryOne('SELECT id, email, name FROM users WHERE id = ?', [req.user.id]);
    if (!user) return res.status(404).json({ error: 'User not found' });

    const [existingRows] = await pool.query(
      'SELECT credential_id FROM webauthn_credentials WHERE user_id = ?',
      [user.id]
    );

    const options = await generateRegistrationOptions({
      rpName,
      rpID,
      userID: String(user.id),
      userName: user.email,
      userDisplayName: user.name,
      timeout: 60000,
      attestationType: 'none',
      excludeCredentials: existingRows.map(row => ({
        id: fromBase64URL(row.credential_id),
        type: 'public-key',
      })),
      authenticatorSelection: {
        residentKey: 'preferred',
        userVerification: 'preferred'
      }
    });

    await pool.query(
      'INSERT INTO webauthn_challenges (user_id, email, purpose, challenge, expires_at) VALUES (?, ?, ?, ?, ?)',
      [user.id, user.email, 'register', options.challenge, new Date(Date.now() + 10 * 60 * 1000)]
    );

    res.json(options);
  } catch (err) {
    res.status(500).json({ error: 'Failed to generate registration options' });
  }
});

app.post('/api/webauthn/register/verify', authenticateToken, isCustomer, async (req, res) => {
  try {
    const user = await queryOne('SELECT id, email FROM users WHERE id = ?', [req.user.id]);
    if (!user) return res.status(404).json({ error: 'User not found' });

    const challengeRow = await queryOne(
      `SELECT * FROM webauthn_challenges
       WHERE user_id = ? AND purpose = 'register'
       ORDER BY id DESC`,
      [user.id]
    );

    if (!challengeRow) return res.status(400).json({ error: 'Registration challenge not found' });

    const verification = await verifyRegistrationResponse({
      response: req.body,
      expectedChallenge: challengeRow.challenge,
      expectedOrigin: expectedOrigins,
      expectedRPID: rpID,
      requireUserVerification: false,
    });

    const { verified, registrationInfo } = verification;
    if (!verified || !registrationInfo) {
      return res.status(400).json({ error: 'Biometric registration failed' });
    }

    const { credential, credentialDeviceType, credentialBackedUp } = registrationInfo;

    await pool.query(
      `INSERT INTO webauthn_credentials
       (user_id, credential_id, public_key, counter, transports, device_type, backed_up)
       VALUES (?, ?, ?, ?, ?, ?, ?)`,
      [
        user.id,
        toBase64URL(credential.id),
        toBase64URL(credential.publicKey),
        credential.counter || 0,
        JSON.stringify(req.body?.response?.transports || []),
        credentialDeviceType || null,
        !!credentialBackedUp
      ]
    );

    await pool.query(
      'DELETE FROM webauthn_challenges WHERE user_id = ? AND purpose = ?',
      [user.id, 'register']
    );

    res.json({ message: 'Biometric authentication enabled', verified: true });
  } catch (err) {
    res.status(500).json({ error: 'Failed to verify biometric registration' });
  }
});

app.post('/api/webauthn/login/options', async (req, res) => {
  try {
    const email = String(req.body.email || '').trim().toLowerCase();
    if (!email) return res.status(400).json({ error: 'Email is required' });

    const user = await queryOne(`
      SELECT u.id, u.email, u.name, u.role, l.referral_code, l.points
      FROM users u
      LEFT JOIN loyalty l ON u.id = l.user_id
      WHERE u.email = ?
    `, [email]);

    if (!user) return res.status(404).json({ error: 'User not found' });

    const [credentials] = await pool.query(
      'SELECT * FROM webauthn_credentials WHERE user_id = ?',
      [user.id]
    );

    if (!credentials.length) {
      return res.status(400).json({ error: 'No biometric credentials registered for this account' });
    }

    const options = await generateAuthenticationOptions({
      rpID,
      timeout: 60000,
      userVerification: 'preferred',
      allowCredentials: credentials.map(c => ({
        id: fromBase64URL(c.credential_id),
        type: 'public-key'
      }))
    });

    await pool.query(
      'INSERT INTO webauthn_challenges (user_id, email, purpose, challenge, expires_at) VALUES (?, ?, ?, ?, ?)',
      [user.id, user.email, 'login', options.challenge, new Date(Date.now() + 10 * 60 * 1000)]
    );

    res.json(options);
  } catch {
    res.status(500).json({ error: 'Failed to generate biometric login options' });
  }
});

app.post('/api/webauthn/login/verify', async (req, res) => {
  try {
    const email = String(req.body.email || '').trim().toLowerCase();
    const credentialResponse = req.body.credential;

    if (!email || !credentialResponse) {
      return res.status(400).json({ error: 'Email and credential are required' });
    }

    const user = await queryOne(`
      SELECT u.id, u.email, u.name, u.role, l.referral_code, l.points
      FROM users u
      LEFT JOIN loyalty l ON u.id = l.user_id
      WHERE u.email = ?
    `, [email]);

    if (!user) return res.status(404).json({ error: 'User not found' });

    const challengeRow = await queryOne(
      `SELECT * FROM webauthn_challenges
       WHERE user_id = ? AND purpose = 'login'
       ORDER BY id DESC`,
      [user.id]
    );

    if (!challengeRow) return res.status(400).json({ error: 'Login challenge not found' });

    const credentialID = toBase64URL(Buffer.from(credentialResponse.rawId, 'base64url'));
    const authenticator = await queryOne(
      'SELECT * FROM webauthn_credentials WHERE credential_id = ? AND user_id = ?',
      [credentialID, user.id]
    );

    if (!authenticator) {
      return res.status(400).json({ error: 'Credential not found' });
    }

    const verification = await verifyAuthenticationResponse({
      response: credentialResponse,
      expectedChallenge: challengeRow.challenge,
      expectedOrigin: expectedOrigins,
      expectedRPID: rpID,
      authenticator: {
        credentialID: fromBase64URL(authenticator.credential_id),
        credentialPublicKey: fromBase64URL(authenticator.public_key),
        counter: Number(authenticator.counter),
        transports: JSON.parse(authenticator.transports || '[]')
      },
      requireUserVerification: false,
    });

    if (!verification.verified) {
      return res.status(400).json({ error: 'Biometric login failed' });
    }

    if (verification.authenticationInfo?.newCounter !== undefined) {
      await pool.query(
        'UPDATE webauthn_credentials SET counter = ? WHERE id = ?',
        [verification.authenticationInfo.newCounter, authenticator.id]
      );
    }

    await pool.query(
      'DELETE FROM webauthn_challenges WHERE user_id = ? AND purpose = ?',
      [user.id, 'login']
    );

    const payloadUser = {
      id: user.id,
      name: user.name,
      email: user.email,
      role: user.role,
      referral_code: user.referral_code,
      points: user.points || 0
    };

    res.json({
      token: signToken(payloadUser),
      user: payloadUser
    });
  } catch (err) {
    res.status(500).json({ error: 'Failed to verify biometric login' });
  }
});

/* =========================
   ADDRESS ROUTES
========================= */
app.get('/api/addresses', authenticateToken, isCustomer, async (req, res) => {
  try {
    const [rows] = await pool.query(
      'SELECT * FROM addresses WHERE user_id = ? ORDER BY is_default DESC, id DESC',
      [req.user.id]
    );
    res.json(rows);
  } catch {
    res.status(500).json({ error: 'Failed to load addresses' });
  }
});

app.post('/api/addresses', authenticateToken, isCustomer, async (req, res) => {
  try {
    const { label, recipient_name, phone, county, city, area, address_line, is_default } = req.body;
    if (!label || !recipient_name || !phone || !county || !city || !area || !address_line) {
      return res.status(400).json({ error: 'All address fields are required' });
    }

    if (is_default) {
      await pool.query('UPDATE addresses SET is_default = FALSE WHERE user_id = ?', [req.user.id]);
    }

    await pool.query(
      `INSERT INTO addresses
      (user_id, label, recipient_name, phone, county, city, area, address_line, is_default)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      [req.user.id, label, recipient_name, phone, county, city, area, address_line, !!is_default]
    );

    res.status(201).json({ message: 'Address created' });
  } catch {
    res.status(500).json({ error: 'Failed to create address' });
  }
});

app.put('/api/addresses/:id', authenticateToken, isCustomer, async (req, res) => {
  try {
    const { label, recipient_name, phone, county, city, area, address_line, is_default } = req.body;

    const address = await queryOne(
      'SELECT * FROM addresses WHERE id = ? AND user_id = ?',
      [req.params.id, req.user.id]
    );
    if (!address) return res.status(404).json({ error: 'Address not found' });

    if (is_default) {
      await pool.query('UPDATE addresses SET is_default = FALSE WHERE user_id = ?', [req.user.id]);
    }

    await pool.query(
      `UPDATE addresses
       SET label = ?, recipient_name = ?, phone = ?, county = ?, city = ?, area = ?, address_line = ?, is_default = ?
       WHERE id = ? AND user_id = ?`,
      [label, recipient_name, phone, county, city, area, address_line, !!is_default, req.params.id, req.user.id]
    );

    res.json({ message: 'Address updated' });
  } catch {
    res.status(500).json({ error: 'Failed to update address' });
  }
});

app.delete('/api/addresses/:id', authenticateToken, isCustomer, async (req, res) => {
  try {
    await pool.query('DELETE FROM addresses WHERE id = ? AND user_id = ?', [req.params.id, req.user.id]);
    res.json({ message: 'Address deleted' });
  } catch {
    res.status(500).json({ error: 'Failed to delete address' });
  }
});

/* =========================
   CART ROUTES
========================= */
app.get('/api/cart', authenticateToken, isCustomer, async (req, res) => {
  try {
    const [rows] = await pool.query(`
      SELECT c.product_id, c.quantity, p.*
      FROM cart c
      JOIN products p ON c.product_id = p.id
      WHERE c.user_id = ?
      ORDER BY c.id DESC
    `, [req.user.id]);

    res.json(rows);
  } catch {
    res.status(500).json({ error: 'Failed to load cart' });
  }
});

app.post('/api/cart', authenticateToken, isCustomer, async (req, res) => {
  try {
    const { product_id, quantity = 1 } = req.body;
    const product = await queryOne('SELECT id, stock FROM products WHERE id = ?', [product_id]);
    if (!product) return res.status(404).json({ error: 'Product not found' });

    const existing = await queryOne(
      'SELECT id, quantity FROM cart WHERE user_id = ? AND product_id = ?',
      [req.user.id, product_id]
    );

    if (existing) {
      if (Number(existing.quantity) + Number(quantity) > Number(product.stock)) {
        return res.status(400).json({ error: 'Not enough stock' });
      }
      await pool.query(
        'UPDATE cart SET quantity = ? WHERE id = ?',
        [Number(existing.quantity) + Number(quantity), existing.id]
      );
    } else {
      if (Number(quantity) > Number(product.stock)) {
        return res.status(400).json({ error: 'Not enough stock' });
      }
      await pool.query(
        'INSERT INTO cart (user_id, product_id, quantity) VALUES (?, ?, ?)',
        [req.user.id, product_id, quantity]
      );
    }

    res.json({ message: 'Added to cart' });
  } catch {
    res.status(500).json({ error: 'Failed to add to cart' });
  }
});

app.put('/api/cart/:productId', authenticateToken, isCustomer, async (req, res) => {
  try {
    const { quantity } = req.body;
    if (!quantity || Number(quantity) < 1) return res.status(400).json({ error: 'Invalid quantity' });

    const product = await queryOne('SELECT stock FROM products WHERE id = ?', [req.params.productId]);
    if (!product) return res.status(404).json({ error: 'Product not found' });
    if (Number(quantity) > Number(product.stock)) return res.status(400).json({ error: 'Not enough stock' });

    await pool.query(
      'UPDATE cart SET quantity = ? WHERE user_id = ? AND product_id = ?',
      [quantity, req.user.id, req.params.productId]
    );

    res.json({ message: 'Cart updated' });
  } catch {
    res.status(500).json({ error: 'Failed to update cart' });
  }
});

app.delete('/api/cart/:productId', authenticateToken, isCustomer, async (req, res) => {
  try {
    await pool.query(
      'DELETE FROM cart WHERE user_id = ? AND product_id = ?',
      [req.user.id, req.params.productId]
    );
    res.json({ message: 'Removed' });
  } catch {
    res.status(500).json({ error: 'Failed to remove item' });
  }
});

/* =========================
   ORDER ROUTES
========================= */
app.post('/api/orders', authenticateToken, isCustomer, async (req, res) => {
  const connection = await pool.getConnection();
  try {
    await connection.beginTransaction();

    const { couponCode, mpesaPhone } = req.body;

    const [cartItems] = await connection.query(`
      SELECT c.quantity, p.id, p.name, p.price, p.stock
      FROM cart c
      JOIN products p ON c.product_id = p.id
      WHERE c.user_id = ?
    `, [req.user.id]);

    if (cartItems.length === 0) throw new Error('Your cart is empty');

    let subtotal = 0;
    for (const item of cartItems) {
      if (Number(item.stock) < Number(item.quantity)) {
        throw new Error(`Insufficient stock for ${item.name}`);
      }
      subtotal += Number(item.price) * Number(item.quantity);
    }

    let discount = 0;
    if (couponCode) {
      const coupon = await queryOne(
        'SELECT discount_percent FROM coupons WHERE code = ? AND is_active = TRUE',
        [couponCode]
      );
      if (coupon) discount = subtotal * (Number(coupon.discount_percent) / 100);
    }

    const total = subtotal - discount;
    const orderNumber = `ORD${Date.now()}`;

    let mpesaReceipt = null;
    let initialStatus = 'Pending';
    let paymentMethod = 'COD';
    let checkoutRequestId = null;
    let merchantRequestId = null;

    if (mpesaPhone) {
      paymentMethod = 'MPESA';
      initialStatus = 'Pending';

      const accessToken = await getMpesaAccessToken();
      const timestamp = getMpesaTimestamp();
      const password = getMpesaPassword(
        process.env.MPESA_SHORTCODE,
        process.env.MPESA_PASSKEY,
        timestamp
      );

      const stkPayload = {
        BusinessShortCode: process.env.MPESA_SHORTCODE,
        Password: password,
        Timestamp: timestamp,
        TransactionType: 'CustomerPayBillOnline',
        Amount: Math.ceil(total),
        PartyA: mpesaPhone,
        PartyB: process.env.MPESA_SHORTCODE,
        PhoneNumber: mpesaPhone,
        CallBackURL: process.env.MPESA_CALLBACK_URL,
        AccountReference: orderNumber,
        TransactionDesc: 'UrbanMart Order Payment'
      };

      const stkResponse = await axios.post(
        `${getMpesaBaseUrl()}/mpesa/stkpush/v1/processrequest`,
        stkPayload,
        {
          headers: {
            Authorization: `Bearer ${accessToken}`
          }
        }
      );

      if (stkResponse.data.ResponseCode !== '0') {
        throw new Error(stkResponse.data.ResponseDescription || 'Failed to initiate M-Pesa payment');
      }

      checkoutRequestId = stkResponse.data.CheckoutRequestID || null;
      merchantRequestId = stkResponse.data.MerchantRequestID || null;
    }

    const [orderResult] = await connection.query(`
      INSERT INTO orders
      (order_number, user_id, customer_name, total, status, mpesa_receipt, checkout_request_id, merchant_request_id, payment_method)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    `, [
      orderNumber,
      req.user.id,
      req.user.name,
      total,
      initialStatus,
      mpesaReceipt,
      checkoutRequestId,
      merchantRequestId,
      paymentMethod
    ]);

    const orderId = orderResult.insertId;

    for (const item of cartItems) {
      await connection.query(`
        INSERT INTO order_items (order_id, product_id, product_name, quantity, price)
        VALUES (?, ?, ?, ?, ?)
      `, [orderId, item.id, item.name, item.quantity, item.price]);

      await connection.query(
        'UPDATE products SET stock = stock - ? WHERE id = ?',
        [item.quantity, item.id]
      );
    }

    await connection.query('DELETE FROM cart WHERE user_id = ?', [req.user.id]);
    await connection.commit();

    res.status(201).json({
      message: paymentMethod === 'MPESA'
        ? 'M-Pesa payment initiated. Check your phone.'
        : 'Order placed successfully',
      orderNumber
    });
  } catch (err) {
    await connection.rollback();
    res.status(400).json({ error: err.message || 'Failed to place order' });
  } finally {
    connection.release();
  }
});

app.post('/api/mpesa/callback', async (req, res) => {
  try {
    const body = req.body?.Body?.stkCallback;
    if (!body) return res.json({ ResultCode: 0, ResultDesc: 'Accepted' });

    const checkoutRequestId = body.CheckoutRequestID;
    const resultCode = body.ResultCode;

    const order = await queryOne(
      'SELECT * FROM orders WHERE checkout_request_id = ?',
      [checkoutRequestId]
    );

    if (!order) return res.json({ ResultCode: 0, ResultDesc: 'Accepted' });

    if (Number(resultCode) === 0) {
      const items = body.CallbackMetadata?.Item || [];
      const receiptItem = items.find(i => i.Name === 'MpesaReceiptNumber');
      const mpesaReceipt = receiptItem?.Value || null;

      await pool.query(
        'UPDATE orders SET status = ?, mpesa_receipt = ? WHERE id = ?',
        ['Processing', mpesaReceipt, order.id]
      );
    } else {
      await pool.query(
        'UPDATE orders SET status = ? WHERE id = ?',
        ['Cancelled', order.id]
      );
    }

    res.json({ ResultCode: 0, ResultDesc: 'Accepted' });
  } catch (err) {
    console.error('M-Pesa callback error:', err.message);
    res.json({ ResultCode: 0, ResultDesc: 'Accepted' });
  }
});

app.get('/api/orders', authenticateToken, async (req, res) => {
  try {
    let sql = 'SELECT * FROM orders';
    const params = [];

    if (req.user.role !== 'admin') {
      sql += ' WHERE user_id = ?';
      params.push(req.user.id);
    }

    sql += ' ORDER BY created_at DESC, id DESC';

    const [orders] = await pool.query(sql, params);

    for (const order of orders) {
      const [items] = await pool.query(
        'SELECT * FROM order_items WHERE order_id = ? ORDER BY id ASC',
        [order.id]
      );
      order.items = items;
    }

    res.json(orders);
  } catch {
    res.status(500).json({ error: 'Failed to load orders' });
  }
});

app.get('/api/orders/:orderNumber/invoice', authenticateToken, async (req, res) => {
  try {
    const order = await queryOne('SELECT * FROM orders WHERE order_number = ?', [req.params.orderNumber]);
    if (!order) return res.status(404).json({ error: 'Order not found' });
    if (req.user.role !== 'admin' && Number(order.user_id) !== Number(req.user.id)) {
      return res.status(403).json({ error: 'Unauthorized' });
    }

    const [items] = await pool.query('SELECT * FROM order_items WHERE order_id = ?', [order.id]);

    const doc = new PDFDocument({ margin: 50 });
    res.setHeader('Content-Disposition', `attachment; filename=invoice_${order.order_number}.pdf`);
    res.setHeader('Content-Type', 'application/pdf');
    doc.pipe(res);

    doc.fontSize(20).text('UrbanMart Invoice', { align: 'center' });
    doc.moveDown();
    doc.fontSize(12).text(`Order Number: ${order.order_number}`);
    doc.text(`Date: ${new Date(order.created_at).toLocaleString()}`);
    doc.text(`Customer: ${order.customer_name}`);
    doc.text(`Status: ${order.status}`);
    doc.text(`Payment Method: ${order.payment_method || 'COD'}`);
    if (order.mpesa_receipt) doc.text(`M-Pesa Receipt: ${order.mpesa_receipt}`);
    doc.moveDown();

    doc.text('Items:', { underline: true });
    items.forEach(item => {
      doc.text(`${item.product_name} - Qty: ${item.quantity} - KSh ${item.price}`);
    });

    doc.moveDown();
    doc.fontSize(14).text(`Total: KSh ${order.total}`, { align: 'right' });
    doc.end();
  } catch {
    res.status(500).json({ error: 'Failed to generate invoice' });
  }
});

/* =========================
   REVIEW ROUTES
========================= */
app.post('/api/products/:id/reviews', authenticateToken, isCustomer, async (req, res) => {
  try {
    const { rating, comment } = req.body;
    if (!rating || Number(rating) < 1 || Number(rating) > 5) {
      return res.status(400).json({ error: 'Valid rating required' });
    }

    await pool.query(
      'INSERT INTO reviews (product_id, user_id, rating, comment) VALUES (?, ?, ?, ?)',
      [req.params.id, req.user.id, rating, comment || null]
    );

    const [avg] = await pool.query(
      'SELECT AVG(rating) as average FROM reviews WHERE product_id = ?',
      [req.params.id]
    );

    if (avg[0]?.average) {
      await pool.query(
        'UPDATE products SET rating = ? WHERE id = ?',
        [avg[0].average, req.params.id]
      );
    }

    res.json({ message: 'Review submitted successfully' });
  } catch {
    res.status(500).json({ error: 'Failed to submit review' });
  }
});

/* =========================
   ADMIN ROUTES
========================= */
app.put('/api/orders/:id', authenticateToken, isAdmin, async (req, res) => {
  try {
    const { status } = req.body;
    await pool.query('UPDATE orders SET status = ? WHERE id = ?', [status, req.params.id]);
    await logAdminAction(req, `Updated Order #${req.params.id} status to ${status}`);
    res.json({ message: 'Order updated' });
  } catch {
    res.status(500).json({ error: 'Failed to update order' });
  }
});

app.get('/api/admin/stats', authenticateToken, isAdmin, async (_, res) => {
  try {
    const [stats] = await pool.query(`
      SELECT
        (SELECT COUNT(*) FROM products) as totalProducts,
        (SELECT COUNT(*) FROM categories) as totalCategories,
        (SELECT COUNT(*) FROM users) as totalUsers,
        (SELECT COUNT(*) FROM orders) as totalOrders,
        (SELECT COALESCE(SUM(total), 0) FROM orders WHERE status != 'Cancelled') as totalRevenue,
        (SELECT COUNT(*) FROM products WHERE stock <= 5) as lowStockProducts
    `);

    res.json(stats[0]);
  } catch {
    res.status(500).json({ error: 'Failed to load stats' });
  }
});

app.get('/api/admin/audit', authenticateToken, isAdmin, async (_, res) => {
  try {
    const [logs] = await pool.query(
      'SELECT * FROM audit_logs ORDER BY created_at DESC LIMIT 50'
    );
    res.json(logs);
  } catch {
    res.status(500).json({ error: 'Failed to load audit logs' });
  }
});

app.post('/api/admin/recover-carts', authenticateToken, isAdmin, async (req, res) => {
  try {
    const [carts] = await pool.query(`
      SELECT DISTINCT u.email, u.name
      FROM cart c
      JOIN users u ON c.user_id = u.id
    `);

    for (const user of carts) {
      await sendMail({
        to: user.email,
        subject: 'You left items in your UrbanMart cart',
        html: `
          <div style="font-family:Arial,sans-serif;line-height:1.7">
            <h2>Hello ${user.name}</h2>
            <p>You left items in your cart. Complete your order now.</p>
            <p><a href="${CLIENT_ORIGIN}" target="_blank">Return to UrbanMart</a></p>
          </div>
        `
      });
    }

    await logAdminAction(req, `Triggered abandoned cart recovery emails for ${carts.length} users`);
    res.json({ message: `Recovery emails sent to ${carts.length} users.` });
  } catch {
    res.status(500).json({ error: 'Failed to recover carts' });
  }
});

app.put('/api/settings', authenticateToken, isAdmin, async (req, res) => {
  try {
    const {
      hero_product_id = null,
      color_primary,
      color_secondary,
      color_accent,
      color_bg,
      color_surface
    } = req.body;

    await pool.query(`
      UPDATE settings
      SET hero_product_id = ?, color_primary = ?, color_secondary = ?, color_accent = ?, color_bg = ?, color_surface = ?
      WHERE id = 1
    `, [hero_product_id, color_primary, color_secondary, color_accent, color_bg, color_surface]);

    await logAdminAction(req, 'Updated store appearance settings');
    res.json({ message: 'Settings updated' });
  } catch {
    res.status(500).json({ error: 'Failed to update settings' });
  }
});

app.post('/api/categories', authenticateToken, isAdmin, async (req, res) => {
  try {
    const { name, slug, icon } = req.body;
    await pool.query(
      'INSERT INTO categories (name, slug, icon) VALUES (?, ?, ?)',
      [name, String(slug).toLowerCase(), icon || 'fa-tag']
    );
    await logAdminAction(req, `Created category: ${name}`);
    res.status(201).json({ message: 'Category created' });
  } catch {
    res.status(500).json({ error: 'Failed to create category' });
  }
});

app.delete('/api/categories/:id', authenticateToken, isAdmin, async (req, res) => {
  try {
    await pool.query('DELETE FROM categories WHERE id = ?', [req.params.id]);
    await logAdminAction(req, `Deleted category ID: ${req.params.id}`);
    res.json({ message: 'Category deleted' });
  } catch {
    res.status(500).json({ error: 'Failed to delete category' });
  }
});

app.post('/api/products/bulk', authenticateToken, isAdmin, upload.single('csv'), async (req, res) => {
  try {
    if (!req.file) return res.status(400).json({ error: 'No CSV file uploaded' });

    const results = [];
    fs.createReadStream(req.file.path)
      .pipe(csv())
      .on('data', (data) => results.push(data))
      .on('end', async () => {
        try {
          for (const item of results) {
            if (item.name && item.price) {
              await pool.query(`
                INSERT INTO products (name, category_slug, price, stock, description)
                VALUES (?, ?, ?, ?, ?)
              `, [
                item.name,
                item.category_slug || null,
                item.price,
                item.stock || 0,
                item.description || ''
              ]);
            }
          }

          if (fs.existsSync(req.file.path)) fs.unlinkSync(req.file.path);
          await logAdminAction(req, `Bulk uploaded ${results.length} products via CSV`);
          res.json({ message: 'Bulk upload successful' });
        } catch {
          res.status(500).json({ error: 'Error processing CSV data' });
        }
      });
  } catch {
    res.status(500).json({ error: 'Bulk upload failed' });
  }
});

app.post('/api/products', authenticateToken, isAdmin, upload.single('image'), async (req, res) => {
  try {
    const { name, category_slug, price, stock, description, is_best_selling } = req.body;
    const image = req.file ? `/uploads/${req.file.filename}` : null;

    await pool.query(`
      INSERT INTO products (name, category_slug, price, stock, image, description, is_best_selling)
      VALUES (?, ?, ?, ?, ?, ?, ?)
    `, [
      name,
      category_slug || null,
      price,
      stock,
      image,
      description || '',
      is_best_selling === 'true'
    ]);

    await logAdminAction(req, `Created product: ${name}`);
    res.status(201).json({ message: 'Product created' });
  } catch {
    res.status(500).json({ error: 'Failed to create product' });
  }
});

app.put('/api/products/:id', authenticateToken, isAdmin, upload.single('image'), async (req, res) => {
  try {
    const { name, category_slug, price, old_price, stock, description, is_best_selling } = req.body;
    const current = await queryOne('SELECT * FROM products WHERE id = ?', [req.params.id]);
    if (!current) return res.status(404).json({ error: 'Product not found' });

    let image = current.image;
    if (req.file) image = `/uploads/${req.file.filename}`;

    await pool.query(`
      UPDATE products
      SET name = ?, category_slug = ?, price = ?, old_price = ?, stock = ?, image = ?, description = ?, is_best_selling = ?
      WHERE id = ?
    `, [
      name,
      category_slug || null,
      price,
      old_price || null,
      stock,
      image,
      description || '',
      is_best_selling === 'true',
      req.params.id
    ]);

    await logAdminAction(req, `Updated product ID: ${req.params.id}`);
    res.json({ message: 'Product updated' });
  } catch {
    res.status(500).json({ error: 'Failed to update product' });
  }
});

app.delete('/api/products/:id', authenticateToken, isAdmin, async (req, res) => {
  try {
    await pool.query('DELETE FROM products WHERE id = ?', [req.params.id]);
    await logAdminAction(req, `Deleted product ID: ${req.params.id}`);
    res.json({ message: 'Product deleted' });
  } catch {
    res.status(500).json({ error: 'Failed to delete product' });
  }
});

app.get('/api/users', authenticateToken, isAdmin, async (_, res) => {
  try {
    const [rows] = await pool.query(`
      SELECT id, name, email, role, created_at
      FROM users
      ORDER BY created_at DESC, id DESC
    `);
    res.json(rows);
  } catch {
    res.status(500).json({ error: 'Failed to load users' });
  }
});

/* =========================
   FALLBACKS
========================= */
app.use('/api/*', (_, res) => res.status(404).json({ error: 'API route not found' }));

app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

/* =========================
   START SERVER
========================= */
const PORT = process.env.PORT || 5000;

initializeDatabase().then(() => {
  app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
  });
});
