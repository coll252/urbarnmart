// =======================
// CORE IMPORTS
// =======================
const express = require('express');
const mysql = require('mysql2/promise');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const axios = require('axios');
const crypto = require('crypto');
const nodemailer = require('nodemailer');
const {
  generateRegistrationOptions,
  verifyRegistrationResponse,
  generateAuthenticationOptions,
  verifyAuthenticationResponse
} = require('@simplewebauthn/server');

require('dotenv').config();

const app = express();

// =======================
// CONFIG
// =======================
app.use(cors({ origin: process.env.CLIENT_ORIGIN, credentials: true }));
app.use(express.json());

const pool = mysql.createPool({
  uri: process.env.DATABASE_URL,
  connectionLimit: 10,
  ssl: { rejectUnauthorized: false }
});

// =======================
// EMAIL SETUP
// =======================
const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS
  }
});

// =======================
// JWT
// =======================
function signToken(user) {
  return jwt.sign(user, process.env.JWT_SECRET, { expiresIn: '24h' });
}

// =======================
// PASSWORD RESET
// =======================
app.post('/api/auth/forgot-password', async (req, res) => {
  const { email } = req.body;

  const [rows] = await pool.query('SELECT * FROM users WHERE email=?', [email]);
  if (!rows.length) return res.status(404).json({ error: 'User not found' });

  const token = crypto.randomBytes(32).toString('hex');
  const expires = new Date(Date.now() + 3600000);

  await pool.query(
    'INSERT INTO password_resets (email, token, expires_at) VALUES (?, ?, ?)',
    [email, token, expires]
  );

  const link = `${process.env.CLIENT_ORIGIN}/?resetToken=${token}`;

  await transporter.sendMail({
    to: email,
    subject: 'Reset Password',
    html: `<a href="${link}">Reset Password</a>`
  });

  res.json({ message: 'Reset link sent' });
});

app.post('/api/auth/reset-password', async (req, res) => {
  const { token, password } = req.body;

  const [rows] = await pool.query(
    'SELECT * FROM password_resets WHERE token=?',
    [token]
  );

  if (!rows.length) return res.status(400).json({ error: 'Invalid token' });

  const hashed = await bcrypt.hash(password, 10);

  await pool.query(
    'UPDATE users SET password=? WHERE email=?',
    [hashed, rows[0].email]
  );

  res.json({ message: 'Password updated' });
});

// =======================
// M-PESA STK PUSH
// =======================
async function getMpesaToken() {
  const res = await axios.get(
    `https://${process.env.MPESA_ENV === 'production'
      ? 'api'
      : 'sandbox'}.safaricom.co.ke/oauth/v1/generate?grant_type=client_credentials`,
    {
      auth: {
        username: process.env.MPESA_CONSUMER_KEY,
        password: process.env.MPESA_CONSUMER_SECRET
      }
    }
  );
  return res.data.access_token;
}

app.post('/api/mpesa/pay', async (req, res) => {
  const token = await getMpesaToken();

  const timestamp = new Date()
    .toISOString()
    .replace(/[-:.TZ]/g, '')
    .slice(0, 14);

  const password = Buffer.from(
    process.env.MPESA_SHORTCODE +
      process.env.MPESA_PASSKEY +
      timestamp
  ).toString('base64');

  const response = await axios.post(
    `https://${process.env.MPESA_ENV === 'production'
      ? 'api'
      : 'sandbox'}.safaricom.co.ke/mpesa/stkpush/v1/processrequest`,
    {
      BusinessShortCode: process.env.MPESA_SHORTCODE,
      Password: password,
      Timestamp: timestamp,
      TransactionType: 'CustomerPayBillOnline',
      Amount: req.body.amount,
      PartyA: req.body.phone,
      PartyB: process.env.MPESA_SHORTCODE,
      PhoneNumber: req.body.phone,
      CallBackURL: process.env.MPESA_CALLBACK_URL,
      AccountReference: 'UrbanMart',
      TransactionDesc: 'Payment'
    },
    {
      headers: { Authorization: `Bearer ${token}` }
    }
  );

  res.json(response.data);
});

// =======================
// BIOMETRICS (WEBAUTHN)
// =======================
const challenges = new Map();

app.post('/api/auth/webauthn/register-options', (req, res) => {
  const options = generateRegistrationOptions({
    rpName: 'UrbanMart',
    rpID: process.env.WEBAUTHN_RP_ID,
    userID: '123',
    userName: 'user@example.com'
  });

  challenges.set('123', options.challenge);
  res.json(options);
});

app.post('/api/auth/webauthn/register-verify', async (req, res) => {
  const verification = await verifyRegistrationResponse({
    response: req.body,
    expectedChallenge: challenges.get('123'),
    expectedOrigin: process.env.CLIENT_ORIGIN,
    expectedRPID: process.env.WEBAUTHN_RP_ID
  });

  res.json({ verified: verification.verified });
});

// =======================
// BASIC AUTH LOGIN
// =======================
app.post('/api/auth/login', async (req, res) => {
  const { email, password } = req.body;

  const [rows] = await pool.query('SELECT * FROM users WHERE email=?', [email]);
  if (!rows.length) return res.status(400).json({ error: 'Invalid' });

  const valid = await bcrypt.compare(password, rows[0].password);
  if (!valid) return res.status(400).json({ error: 'Invalid' });

  res.json({ token: signToken(rows[0]) });
});

// =======================
// SERVER START
// =======================
app.listen(process.env.PORT || 5000, () =>
  console.log('Server running...')
);
