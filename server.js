require('dotenv').config();
const express = require('express');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const mysql = require('mysql2/promise');
const nodemailer = require('nodemailer');
const PDFDocument = require('pdfkit');

const app = express();
app.use(cors());
app.use(express.json());

// Aiven MySQL Database Pool
// Aiven provides a single URI. We use ssl: { rejectUnauthorized: true } or false depending on your cert setup.
const pool = mysql.createPool({
  uri: process.env.DATABASE_URL, 
  ssl: {
    rejectUnauthorized: false // Adjust this based on Aiven's specific CA cert requirements
  },
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0
});

const JWT_SECRET = process.env.JWT_SECRET || 'super_secret_key_123';

// ---------------------------------------------------------
// 6-Phase Modular Database Initialization
// ---------------------------------------------------------
async function initializeDatabase() {
  try {
    const connection = await pool.getConnection();
    console.log('Initiating 6-phase database modular initialization...');

    // Phase 1: Connection & Core Setup
    // Verify connection is alive before proceeding
    await connection.ping();

    // Phase 2: Core Identity Architecture
    await connection.query(`
      CREATE TABLE IF NOT EXISTS users (
        id INT AUTO_INCREMENT PRIMARY KEY,
        name VARCHAR(255) NOT NULL,
        email VARCHAR(255) UNIQUE NOT NULL,
        password VARCHAR(255) NOT NULL,
        role ENUM('user', 'admin') DEFAULT 'user',
        points INT DEFAULT 0,
        referral_code VARCHAR(50),
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);

    // Phase 3: Catalog & Inventory Management
    await connection.query(`
      CREATE TABLE IF NOT EXISTS categories (
        slug VARCHAR(100) PRIMARY KEY,
        name VARCHAR(255) NOT NULL
      )
    `);

    await connection.query(`
      CREATE TABLE IF NOT EXISTS products (
        id INT AUTO_INCREMENT PRIMARY KEY,
        name VARCHAR(255) NOT NULL,
        category_slug VARCHAR(100),
        description TEXT,
        price DECIMAL(10,2) NOT NULL,
        old_price DECIMAL(10,2),
        stock INT DEFAULT 0,
        image VARCHAR(500),
        rating DECIMAL(3,2) DEFAULT 0.00,
        review_count INT DEFAULT 0,
        is_best_selling BOOLEAN DEFAULT FALSE,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (category_slug) REFERENCES categories(slug) ON DELETE SET NULL
      )
    `);

    // Phase 4: Commerce & Transaction Pipeline
    await connection.query(`
      CREATE TABLE IF NOT EXISTS orders (
        id INT AUTO_INCREMENT PRIMARY KEY,
        user_id INT NOT NULL,
        order_number VARCHAR(100) UNIQUE NOT NULL,
        total DECIMAL(10,2) NOT NULL,
        status ENUM('Pending', 'Processing', 'Packed', 'Shipped', 'Delivered', 'Cancelled') DEFAULT 'Pending',
        payment_method VARCHAR(50),
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
      )
    `);

    await connection.query(`
      CREATE TABLE IF NOT EXISTS order_items (
        id INT AUTO_INCREMENT PRIMARY KEY,
        order_id INT NOT NULL,
        product_id INT NOT NULL,
        product_name VARCHAR(255),
        quantity INT NOT NULL,
        price DECIMAL(10,2) NOT NULL,
        FOREIGN KEY (order_id) REFERENCES orders(id) ON DELETE CASCADE,
        FOREIGN KEY (product_id) REFERENCES products(id) ON DELETE NO ACTION
      )
    `);

    await connection.query(`
      CREATE TABLE IF NOT EXISTS cart (
        id INT AUTO_INCREMENT PRIMARY KEY,
        user_id INT NOT NULL,
        product_id INT NOT NULL,
        quantity INT DEFAULT 1,
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
        FOREIGN KEY (product_id) REFERENCES products(id) ON DELETE CASCADE,
        UNIQUE KEY user_product_unique (user_id, product_id)
      )
    `);

    // Phase 5: Account Context & Engagement
    await connection.query(`
      CREATE TABLE IF NOT EXISTS addresses (
        id INT AUTO_INCREMENT PRIMARY KEY,
        user_id INT NOT NULL,
        label VARCHAR(100),
        full_name VARCHAR(255),
        phone VARCHAR(50),
        address_line TEXT,
        city VARCHAR(100),
        region VARCHAR(100),
        is_default BOOLEAN DEFAULT FALSE,
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
      )
    `);

    await connection.query(`
      CREATE TABLE IF NOT EXISTS notifications (
        id INT AUTO_INCREMENT PRIMARY KEY,
        user_id INT NOT NULL,
        title VARCHAR(255) NOT NULL,
        message TEXT,
        read_at TIMESTAMP NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
      )
    `);

    // Phase 6: System Audit & Telemetry
    await connection.query(`
      CREATE TABLE IF NOT EXISTS audit_logs (
        id INT AUTO_INCREMENT PRIMARY KEY,
        actor_id INT,
        actor_name VARCHAR(255),
        action VARCHAR(255) NOT NULL,
        target VARCHAR(255),
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);

    connection.release();
    console.log('Database initialization completed successfully.');
  } catch (error) {
    console.error('Failed to initialize database schema:', error);
  }
}

// Execute the modular initialization immediately
initializeDatabase();


// ---------------------------------------------------------
// Middleware
// ---------------------------------------------------------
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  
  if (!token) return res.status(401).json({ error: 'Access token required' });

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ error: 'Invalid or expired token' });
    req.user = user;
    next();
  });
};

const requireAdmin = (req, res, next) => {
  if (req.user.role !== 'admin') return res.status(403).json({ error: 'Admin access required' });
  next();
};

// ---------------------------------------------------------
// System Routes
// ---------------------------------------------------------
app.get('/api/heartbeat', authenticateToken, (req, res) => {
  res.status(200).json({ status: 'alive', timestamp: Date.now() });
});

// A Vercel-specific root route to verify the serverless function is awake
app.get('/api/health', (req, res) => {
  res.json({ status: 'API is running', database: 'Initializing/Ready' });
});

// ---------------------------------------------------------
// Export for Vercel
// ---------------------------------------------------------
// Vercel serverless functions require the app to be exported rather than explicitly listening on a port.
if (process.env.NODE_ENV !== 'production') {
  const PORT = process.env.PORT || 3000;
  app.listen(PORT, () => {
    console.log(`Server running locally on port ${PORT}`);
  });
}

module.exports = app;
// ... (previous code above)

// ---------------------------------------------------------
// Startup Logic
// ---------------------------------------------------------
const PORT = process.env.PORT || 3000;

async function startServer() {
  try {
    // Phase 0: Initialize Database first
    await initializeDatabase();

    // Phase 1: Start listening on the port required by the host
    app.listen(PORT, '0.0.0.0', () => {
      console.log(`✅ UrbanMart Pro API is live on port ${PORT}`);
    });
  } catch (err) {
    console.error('❌ Critical failure during startup:', err);
    process.exit(1);
  }
}

startServer();

// For Vercel compatibility
module.exports = app;
