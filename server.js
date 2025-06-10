const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const sqlite3 = require('sqlite3').verbose();
const nodemailer = require('nodemailer');
const rateLimit = require('express-rate-limit');
const { body, validationResult } = require('express-validator');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3000;

// Security middleware
app.use(helmet());
app.use(cors({
  origin: process.env.FRONTEND_URL || true, // Allow all origins for Railway
  credentials: true
}));
app.use(express.json({ limit: '10mb' }));
app.use(express.static('.')); // Serve your HTML files

// Rate limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 5, // 5 requests per window
  message: 'Too many requests, please try again later.'
});

// Initialize SQLite Database
const db = new sqlite3.Database('./social_archive.db', (err) => {
  if (err) {
    console.error('Error opening database:', err);
  } else {
    console.log('✅ Connected to SQLite database');
    initializeDatabase();
  }
});

// Create tables
function initializeDatabase() {
  db.serialize(() => {
    // Users table
    db.run(`CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT NOT NULL,
      email TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      connection TEXT,
      status TEXT DEFAULT 'pending',
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      approved_at DATETIME,
      last_login DATETIME
    )`);

    // Posts table (for future use)
    db.run(`CREATE TABLE IF NOT EXISTS posts (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      title TEXT,
      content TEXT,
      image_url TEXT,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )`);

    // Admin users table
    db.run(`CREATE TABLE IF NOT EXISTS admin_users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      email TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )`);
  });
}

// Email setup
const transporter = nodemailer.createTransport({
  service: 'gmail', // or your email service
  auth: {
    user: process.env.EMAIL_USER, // your email
    pass: process.env.EMAIL_PASS  // your app password
  }
});

// Validation middleware
const validateSignup = [
  body('name').trim().isLength({ min: 2, max: 100 }).escape(),
  body('email').isEmail().normalizeEmail(),
  body('password').isLength({ min: 8, max: 128 }),
  body('connection').optional().trim().isLength({ max: 500 }).escape()
];

// Routes


// Get all users (for testing)
app.get('/api/users', (req, res) => {
  db.all(
    'SELECT id, name, email, status, created_at FROM users ORDER BY created_at DESC',
    (err, rows) => {
      if (err) {
        console.error('Database error:', err);
        return res.status(500).json({ success: false, message: 'Database error' });
      }
      res.json({ success: true, users: rows });
    }
  );
});

// Health check
app.get('/api/health', (req, res) => {
  res.json({ status: 'OK', timestamp: new Date().toISOString() });
});

// Submit access request
app.post('/api/request-access', limiter, validateSignup, async (req, res) => {
  try {
    // Check for validation errors
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({
        success: false,
        message: 'Invalid input data',
        errors: errors.array()
      });
    }

    const { name, email, password, connection } = req.body;

    // Check if email already exists
    db.get('SELECT id FROM users WHERE email = ?', [email], async (err, row) => {
      if (err) {
        console.error('Database error:', err);
        return res.status(500).json({
          success: false,
          message: 'Database error occurred'
        });
      }

      if (row) {
        return res.status(400).json({
          success: false,
          message: 'An account with this email already exists'
        });
      }

      // Hash password
      const passwordHash = await bcrypt.hash(password, 12);

      // Insert new user
      db.run(
        'INSERT INTO users (name, email, password_hash, connection) VALUES (?, ?, ?, ?)',
        [name, email, passwordHash, connection || null],
        function(err) {
          if (err) {
            console.error('Error inserting user:', err);
            return res.status(500).json({
              success: false,
              message: 'Failed to create account'
            });
          }

          // Send notification email to you
          sendNotificationEmail(name, email, connection);

          res.json({
            success: true,
            message: 'Access request submitted successfully! Huntrezz will review your application and email you within 48 hours.',
            userId: this.lastID
          });
        }
      );
    });

  } catch (error) {
    console.error('Server error:', error);
    res.status(500).json({
      success: false,
      message: 'Internal server error'
    });
  }
});

// Send notification email
async function sendNotificationEmail(name, email, connection) {
  try {
    const mailOptions = {
      from: process.env.EMAIL_USER,
      to: process.env.ADMIN_EMAIL || process.env.EMAIL_USER,
      subject: `🎨 New Social Archive Access Request from ${name}`,
      html: `
        <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
          <h2 style="color: #6c63ff;">New Social Archive Access Request</h2>
          
          <div style="background: #f5f7fa; padding: 20px; border-radius: 10px; margin: 20px 0;">
            <p><strong>Name:</strong> ${name}</p>
            <p><strong>Email:</strong> ${email}</p>
            <p><strong>Connection:</strong> ${connection || 'Not specified'}</p>
            <p><strong>Submitted:</strong> ${new Date().toLocaleString()}</p>
          </div>

          <div style="margin: 30px 0;">
            <p>Visit your admin dashboard to approve or deny this request.</p>
            <a href="${process.env.FRONTEND_URL || 'http://localhost:3000'}/admin" 
               style="background: #6c63ff; color: white; padding: 12px 24px; text-decoration: none; border-radius: 5px; display: inline-block;">
              Review Request
            </a>
          </div>
        </div>
      `
    };

    await transporter.sendMail(mailOptions);
    console.log(`✅ Notification email sent for ${name} (${email})`);
  } catch (error) {
    console.error('Error sending notification email:', error);
  }
}

// Get all pending requests (admin only)
app.get('/api/admin/requests', async (req, res) => {
  // TODO: Add admin authentication middleware
  db.all(
    'SELECT id, name, email, connection, status, created_at FROM users WHERE status = "pending" ORDER BY created_at DESC',
    (err, rows) => {
      if (err) {
        return res.status(500).json({ success: false, message: 'Database error' });
      }
      res.json({ success: true, requests: rows });
    }
  );
});

// Approve/deny user (admin only)
app.patch('/api/admin/users/:id', async (req, res) => {
  // TODO: Add admin authentication middleware
  const { id } = req.params;
  const { status } = req.body; // 'approved' or 'denied'

  if (!['approved', 'denied'].includes(status)) {
    return res.status(400).json({ success: false, message: 'Invalid status' });
  }

  const approvedAt = status === 'approved' ? new Date().toISOString() : null;

  db.run(
    'UPDATE users SET status = ?, approved_at = ? WHERE id = ?',
    [status, approvedAt, id],
    function(err) {
      if (err) {
        return res.status(500).json({ success: false, message: 'Database error' });
      }
      
      if (this.changes === 0) {
        return res.status(404).json({ success: false, message: 'User not found' });
      }

      res.json({ success: true, message: `User ${status} successfully` });
    }
  );
});

// Login endpoint (for future use)
app.post('/api/login', async (req, res) => {
  // TODO: Implement login logic
  res.json({ success: false, message: 'Login feature coming soon!' });
});

// Error handling middleware
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).json({
    success: false,
    message: 'Something went wrong!'
  });
});

// Start server
app.listen(PORT, () => {
  console.log(`🚀 Social Archive server running on port ${PORT}`);
  console.log(`📁 Database file: ./social_archive.db`);
  console.log(`🌐 Frontend URL: ${process.env.FRONTEND_URL || 'http://localhost:3000'}`);
});

// Graceful shutdown
process.on('SIGINT', () => {
  console.log('\n⏹️  Shutting down server...');
  db.close((err) => {
    if (err) {
      console.error('Error closing database:', err);
    } else {
      console.log('✅ Database connection closed');
    }
    process.exit(0);
  });
}); 
