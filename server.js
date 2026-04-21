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
require('dotenv').config();

const app = express();

app.use(cors());
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true }));

// Serve static frontend files from the 'public' directory
app.use(express.static(path.join(__dirname, 'public')));

// Configure persistent storage path for Render or fallback to local
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

// Configure Database Connection for Aiven (SSL) or Local
const dbConfig = {
    connectionLimit: 10,
    waitForConnections: true,
    multipleStatements: true 
};

if (process.env.DATABASE_URL) {
    dbConfig.uri = process.env.DATABASE_URL;
    dbConfig.ssl = { rejectUnauthorized: false }; // Required for Aiven
} else {
    dbConfig.host = process.env.DB_HOST;
    dbConfig.user = process.env.DB_USER;
    dbConfig.password = process.env.DB_PASSWORD;
    dbConfig.database = process.env.DB_NAME;
}

const pool = mysql.createPool(dbConfig);

// ==========================================
// AUTOMATIC DATABASE INITIALIZATION
// ==========================================
async function initializeDatabase() {
    try {
        console.log("Checking and initializing database tables...");

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
                price DECIMAL(10, 2) NOT NULL,
                old_price DECIMAL(10, 2),
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
            CREATE TABLE IF NOT EXISTS cart (
                id INT AUTO_INCREMENT PRIMARY KEY,
                user_id INT NOT NULL,
                product_id INT NOT NULL,
                quantity INT NOT NULL DEFAULT 1,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
                FOREIGN KEY (product_id) REFERENCES products(id) ON DELETE CASCADE
            );
            CREATE TABLE IF NOT EXISTS orders (
                id INT AUTO_INCREMENT PRIMARY KEY,
                order_number VARCHAR(50) UNIQUE NOT NULL,
                user_id INT NOT NULL,
                customer_name VARCHAR(100) NOT NULL,
                total DECIMAL(10, 2) NOT NULL,
                status ENUM('Pending', 'Processing', 'Packed', 'Shipped', 'Delivered', 'Cancelled') DEFAULT 'Pending',
                mpesa_receipt VARCHAR(50),
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
            );
            CREATE TABLE IF NOT EXISTS order_items (
                id INT AUTO_INCREMENT PRIMARY KEY,
                order_id INT NOT NULL,
                product_id INT NOT NULL,
                product_name VARCHAR(255) NOT NULL,
                quantity INT NOT NULL,
                price DECIMAL(10, 2) NOT NULL,
                FOREIGN KEY (order_id) REFERENCES orders(id) ON DELETE CASCADE
            );
            CREATE TABLE IF NOT EXISTS settings (
                id INT PRIMARY KEY,
                hero_product_id INT,
                color_primary VARCHAR(20) DEFAULT '#020617',
                color_secondary VARCHAR(20) DEFAULT '#0f172a',
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
        `);

        // Seed data logic
        const [catRows] = await pool.query('SELECT COUNT(*) as count FROM categories');
        if (catRows[0].count === 0) {
            await pool.query(`INSERT INTO categories (name, slug, icon) VALUES 
                ('Smartphone & Tablet', 'smartphone-tablet', 'fa-mobile-alt'), 
                ('Watch & Jewelry', 'watch-jewelry', 'fa-clock'),
                ('Audio & Electronics', 'electronics', 'fa-headphones'),
                ('Laptops & PCs', 'laptop', 'fa-laptop');`);
        }
        
        const [couponRows] = await pool.query('SELECT COUNT(*) as count FROM coupons');
        if (couponRows[0].count === 0) {
            await pool.query(`INSERT INTO coupons (code, discount_percent) VALUES ('DISCOUNT10', 10);`);
        }

        const [setRows] = await pool.query('SELECT COUNT(*) as count FROM settings');
        if (setRows[0].count === 0) {
            await pool.query(`INSERT INTO settings (id, color_primary) VALUES (1, '#0f172a');`);
        }

        console.log("Database initialized successfully!");
    } catch (err) {
        console.error("Database initialization failed:", err.message);
    }
}

// ==========================================
// CORE UTILITIES & MIDDLEWARE
// ==========================================
function signToken(user) {
    return jwt.sign({ id: user.id, role: user.role, name: user.name, email: user.email || null }, process.env.JWT_SECRET, { expiresIn: '24h' });
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

async function queryOne(sql, params = []) {
    const [rows] = await pool.query(sql, params);
    return rows[0] || null;
}

async function logAdminAction(req, action) {
    try {
        await pool.query('INSERT INTO audit_logs (user_id, user_name, action) VALUES (?, ?, ?)', [req.user.id || 0, req.user.name || 'System', action]);
    } catch (err) { 
        console.error('Audit log failed', err); 
    }
}

// ==========================================
// API ROUTES
// ==========================================
// Heartbeat to keep session active
app.get('/api/heartbeat', (_, res) => res.json({ ok: true, timestamp: Date.now() }));

app.get('/api/bootstrap', async (_, res) => {
    try {
        const [[products], [categories], [settings]] = await Promise.all([
            pool.query('SELECT * FROM products ORDER BY is_best_selling DESC, created_at DESC, id DESC'),
            pool.query('SELECT * FROM categories ORDER BY name ASC'),
            pool.query('SELECT * FROM settings WHERE id = 1')
        ]);
        res.json({ products, categories, settings: settings[0] || {} });
    } catch { res.status(500).json({ error: 'Failed to load store data' }); }
});

app.post('/api/auth/register', async (req, res) => {
    try {
        const name = String(req.body.name || '').trim();
        const email = String(req.body.email || '').trim().toLowerCase();
        const password = String(req.body.password || '');

        if (!name || !email || !password) return res.status(400).json({ error: 'All fields are required' });
        
        const existing = await queryOne('SELECT id FROM users WHERE email = ?', [email]);
        if (existing) return res.status(400).json({ error: 'Email already exists' });

        const hashed = await bcrypt.hash(password, 10);
        await pool.query('INSERT INTO users (name, email, password, role) VALUES (?, ?, ?, ?)', [name, email, hashed, 'customer']);
        res.status(201).json({ message: 'Account created successfully' });
    } catch { res.status(500).json({ error: 'Registration failed' }); }
});

app.post('/api/auth/login', async (req, res) => {
    try {
        const email = String(req.body.email || '').trim().toLowerCase();
        const password = String(req.body.password || '');
        const adminEmail = String(process.env.ADMIN_EMAIL || '').trim().toLowerCase();

        if (email === adminEmail && password === process.env.ADMIN_PASSWORD) {
            const adminUser = { id: 0, name: 'System Administrator', email: adminEmail, role: 'admin' };
            await logAdminAction({ user: adminUser }, 'Admin logged into system');
            return res.json({ token: signToken(adminUser), user: adminUser });
        }

        const user = await queryOne('SELECT * FROM users WHERE email = ?', [email]);
        if (!user || !(await bcrypt.compare(password, user.password))) return res.status(400).json({ error: 'Invalid credentials' });

        const payloadUser = { id: user.id, name: user.name, email: user.email, role: user.role };
        res.json({ token: signToken(payloadUser), user: payloadUser });
    } catch { res.status(500).json({ error: 'Login failed' }); }
});

// -- CART & ORDERS --
app.get('/api/cart', authenticateToken, isCustomer, async (req, res) => {
    try {
        const [rows] = await pool.query(`SELECT c.product_id, c.quantity, p.* FROM cart c JOIN products p ON c.product_id = p.id WHERE c.user_id = ? ORDER BY c.id DESC`, [req.user.id]);
        res.json(rows);
    } catch { res.status(500).json({ error: 'Failed to load cart' }); }
});

app.post('/api/cart', authenticateToken, isCustomer, async (req, res) => {
    try {
        const { product_id, quantity = 1 } = req.body;
        const product = await queryOne('SELECT id, stock FROM products WHERE id = ?', [product_id]);
        if (!product) return res.status(404).json({ error: 'Product not found' });

        const existing = await queryOne('SELECT id, quantity FROM cart WHERE user_id = ? AND product_id = ?', [req.user.id, product_id]);
        if (existing) {
            if (existing.quantity + quantity > product.stock) return res.status(400).json({ error: 'Not enough stock' });
            await pool.query('UPDATE cart SET quantity = ? WHERE id = ?', [existing.quantity + quantity, existing.id]);
        } else {
            if (quantity > product.stock) return res.status(400).json({ error: 'Not enough stock' });
            await pool.query('INSERT INTO cart (user_id, product_id, quantity) VALUES (?, ?, ?)', [req.user.id, product_id, quantity]);
        }
        res.json({ message: 'Added to cart' });
    } catch { res.status(500).json({ error: 'Failed to add to cart' }); }
});

app.put('/api/cart/:productId', authenticateToken, isCustomer, async (req, res) => {
    try {
        const { quantity } = req.body;
        await pool.query('UPDATE cart SET quantity = ? WHERE user_id = ? AND product_id = ?', [quantity, req.user.id, req.params.productId]);
        res.json({ message: 'Cart updated' });
    } catch { res.status(500).json({ error: 'Failed to update cart' }); }
});

app.delete('/api/cart/:productId', authenticateToken, isCustomer, async (req, res) => {
    try {
        await pool.query('DELETE FROM cart WHERE user_id = ? AND product_id = ?', [req.user.id, req.params.productId]);
        res.json({ message: 'Removed' });
    } catch { res.status(500).json({ error: 'Failed to remove' }); }
});

// Order Placement & M-Pesa STK Push
app.post('/api/orders', authenticateToken, isCustomer, async (req, res) => {
    const connection = await pool.getConnection();
    try {
        await connection.beginTransaction();
        const { couponCode, mpesaPhone } = req.body;

        const [cartItems] = await connection.query(`SELECT c.quantity, p.id, p.name, p.price, p.stock FROM cart c JOIN products p ON c.product_id = p.id WHERE c.user_id = ?`, [req.user.id]);
        if (cartItems.length === 0) throw new Error('Your cart is empty');

        let subtotal = 0;
        for (const item of cartItems) {
            if (item.stock < item.quantity) throw new Error(`Insufficient stock for ${item.name}`);
            subtotal += Number(item.price) * Number(item.quantity);
        }

        let discount = 0;
        if (couponCode) {
            const coupon = await queryOne('SELECT discount_percent FROM coupons WHERE code = ? AND is_active = TRUE', [couponCode]);
            if (coupon) discount = subtotal * (coupon.discount_percent / 100);
        }

        const total = subtotal - discount;
        const orderNumber = `ORD${Date.now()}`;
        
        // M-Pesa Implementation Structure
        let mpesaReceipt = null;
        let initialStatus = 'Pending';
        if (mpesaPhone) {
            console.log(`Initiating STK Push to ${mpesaPhone} for KES ${total}`);
            // Mocking successful push response
            mpesaReceipt = `MPESA${Math.floor(Math.random() * 1000000)}`;
            initialStatus = 'Processing'; // Payment successful
        }

        const [orderResult] = await connection.query(`INSERT INTO orders (order_number, user_id, customer_name, total, status, mpesa_receipt) VALUES (?, ?, ?, ?, ?, ?)`, [orderNumber, req.user.id, req.user.name, total, initialStatus, mpesaReceipt]);
        const orderId = orderResult.insertId;

        for (const item of cartItems) {
            await connection.query(`INSERT INTO order_items (order_id, product_id, product_name, quantity, price) VALUES (?, ?, ?, ?, ?)`, [orderId, item.id, item.name, item.quantity, item.price]);
            await connection.query('UPDATE products SET stock = stock - ? WHERE id = ?', [item.quantity, item.id]);
        }

        await connection.query('DELETE FROM cart WHERE user_id = ?', [req.user.id]);
        await connection.commit();

        res.status(201).json({ message: 'Order placed successfully', orderNumber });
    } catch (err) {
        await connection.rollback();
        res.status(400).json({ error: err.message || 'Failed to place order' });
    } finally { connection.release(); }
});

app.get('/api/orders', authenticateToken, async (req, res) => {
    try {
        let sql = 'SELECT * FROM orders';
        const params = [];
        if (req.user.role !== 'admin') { sql += ' WHERE user_id = ?'; params.push(req.user.id); }
        sql += ' ORDER BY created_at DESC, id DESC';

        const [orders] = await pool.query(sql, params);
        for (const order of orders) {
            const [items] = await pool.query('SELECT * FROM order_items WHERE order_id = ? ORDER BY id ASC', [order.id]);
            order.items = items;
        }
        res.json(orders);
    } catch { res.status(500).json({ error: 'Failed to load orders' }); }
});

// PDF Invoice Generation
app.get('/api/orders/:orderNumber/invoice', authenticateToken, async (req, res) => {
    try {
        const order = await queryOne('SELECT * FROM orders WHERE order_number = ?', [req.params.orderNumber]);
        if (!order) return res.status(404).json({ error: 'Order not found' });
        
        if (req.user.role !== 'admin' && order.user_id !== req.user.id) return res.status(403).json({ error: 'Unauthorized' });

        const [items] = await pool.query('SELECT * FROM order_items WHERE order_id = ?', [order.id]);

        const doc = new PDFDocument({ margin: 50 });
        res.setHeader('Content-disposition', `attachment; filename=invoice_${order.order_number}.pdf`);
        res.setHeader('Content-type', 'application/pdf');
        doc.pipe(res);

        doc.fontSize(20).text('UrbanMart Invoice', { align: 'center' });
        doc.moveDown();
        doc.fontSize(12).text(`Order Number: ${order.order_number}`);
        doc.text(`Date: ${new Date(order.created_at).toLocaleString()}`);
        doc.text(`Customer: ${order.customer_name}`);
        doc.text(`Status: ${order.status}`);
        if(order.mpesa_receipt) doc.text(`M-Pesa Receipt: ${order.mpesa_receipt}`);
        doc.moveDown();
        
        doc.text('Items:', { underline: true });
        items.forEach(item => {
            doc.text(`${item.product_name} - Qty: ${item.quantity} - KSh ${item.price}`);
        });
        
        doc.moveDown();
        doc.fontSize(14).text(`Total: KSh ${order.total}`, { align: 'right' });
        doc.end();

    } catch (err) { res.status(500).json({ error: 'Failed to generate invoice' }); }
});

// -- ADMIN ROUTES --
app.put('/api/orders/:id', authenticateToken, isAdmin, async (req, res) => {
    try {
        const { status } = req.body;
        await pool.query('UPDATE orders SET status = ? WHERE id = ?', [status, req.params.id]);
        await logAdminAction(req, `Updated Order #${req.params.id} status to ${status}`);
        res.json({ message: 'Order updated' });
    } catch { res.status(500).json({ error: 'Failed to update order' }); }
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
    } catch { res.status(500).json({ error: 'Failed to load stats' }); }
});

app.get('/api/admin/audit', authenticateToken, isAdmin, async (_, res) => {
    try {
        const [logs] = await pool.query('SELECT * FROM audit_logs ORDER BY created_at DESC LIMIT 50');
        res.json(logs);
    } catch { res.status(500).json({ error: 'Failed to load audit logs' }); }
});

// Settings Management
app.put('/api/settings', authenticateToken, isAdmin, async (req, res) => {
    try {
        const { hero_product_id = null, color_primary, color_secondary, color_accent, color_bg, color_surface } = req.body;
        await pool.query(
            `UPDATE settings SET hero_product_id = ?, color_primary = ?, color_secondary = ?, color_accent = ?, color_bg = ?, color_surface = ? WHERE id = 1`,
            [hero_product_id, color_primary, color_secondary, color_accent, color_bg, color_surface]
        );
        await logAdminAction(req, 'Updated store appearance settings');
        res.json({ message: 'Settings updated' });
    } catch { res.status(500).json({ error: 'Failed to update settings' }); }
});

// Category Management
app.post('/api/categories', authenticateToken, isAdmin, async (req, res) => {
    try {
        const { name, slug, icon } = req.body;
        if (!name || !slug) return res.status(400).json({ error: 'Name and slug are required' });
        await pool.query('INSERT INTO categories (name, slug, icon) VALUES (?, ?, ?)', [name, slug.toLowerCase(), icon]);
        await logAdminAction(req, `Created category: ${name}`);
        res.status(201).json({ message: 'Category created' });
    } catch { res.status(500).json({ error: 'Failed to create category' }); }
});

app.delete('/api/categories/:id', authenticateToken, isAdmin, async (req, res) => {
    try {
        await pool.query('DELETE FROM categories WHERE id = ?', [req.params.id]);
        await logAdminAction(req, `Deleted category ID: ${req.params.id}`);
        res.json({ message: 'Category deleted' });
    } catch { res.status(500).json({ error: 'Failed to delete category' }); }
});

// Product Management & CSV Bulk Upload
app.post('/api/products/bulk', authenticateToken, isAdmin, upload.single('csv'), async (req, res) => {
    if (!req.file) return res.status(400).json({ error: 'No CSV file uploaded' });
    const results = [];
    
    fs.createReadStream(req.file.path)
        .pipe(csv())
        .on('data', (data) => results.push(data))
        .on('end', async () => {
            try {
                for (const item of results) {
                    if(item.name && item.price) {
                        await pool.query(
                            `INSERT INTO products (name, category_slug, price, stock, description) VALUES (?, ?, ?, ?, ?)`,
                            [item.name, item.category_slug, item.price, item.stock || 0, item.description || '']
                        );
                    }
                }
                fs.unlinkSync(req.file.path); 
                await logAdminAction(req, `Bulk uploaded ${results.length} products via CSV`);
                res.json({ message: 'Bulk upload successful' });
            } catch (err) {
                res.status(500).json({ error: 'Error processing CSV data' });
            }
        });
});

app.post('/api/products', authenticateToken, isAdmin, upload.single('image'), async (req, res) => {
    try {
        const { name, category_slug, price, stock, description, is_best_selling } = req.body;
        const image = req.file ? `/uploads/${req.file.filename}` : null;
        
        await pool.query(
            `INSERT INTO products (name, category_slug, price, stock, image, description, is_best_selling) VALUES (?, ?, ?, ?, ?, ?, ?)`,
            [name, category_slug, price, stock, image, description, is_best_selling === 'true']
        );
        await logAdminAction(req, `Created product: ${name}`);
        res.status(201).json({ message: 'Product created' });
    } catch { res.status(500).json({ error: 'Failed to create product' }); }
});

app.put('/api/products/:id', authenticateToken, isAdmin, upload.single('image'), async (req, res) => {
    try {
        const { name, category_slug, price, old_price, stock, description, is_best_selling } = req.body;
        const current = await queryOne('SELECT * FROM products WHERE id = ?', [req.params.id]);
        if (!current) return res.status(404).json({ error: 'Product not found' });

        let image = current.image;
        if (req.file) image = `/uploads/${req.file.filename}`;

        await pool.query(
            `UPDATE products SET name = ?, category_slug = ?, price = ?, old_price = ?, stock = ?, image = ?, description = ?, is_best_selling = ? WHERE id = ?`,
            [name, category_slug, price, old_price || null, stock, image, description, is_best_selling === 'true', req.params.id]
        );
        await logAdminAction(req, `Updated product ID: ${req.params.id}`);
        res.json({ message: 'Product updated' });
    } catch { res.status(500).json({ error: 'Failed to update product' }); }
});

app.delete('/api/products/:id', authenticateToken, isAdmin, async (req, res) => {
    try {
        await pool.query('DELETE FROM products WHERE id = ?', [req.params.id]);
        await logAdminAction(req, `Deleted product ID: ${req.params.id}`);
        res.json({ message: 'Product deleted' });
    } catch { res.status(500).json({ error: 'Failed to delete product' }); }
});

app.get('/api/users', authenticateToken, isAdmin, async (_, res) => {
    try {
        const [rows] = await pool.query('SELECT id, name, email, role, created_at FROM users ORDER BY created_at DESC, id DESC');
        res.json(rows);
    } catch { res.status(500).json({ error: 'Failed to load users' }); }
});

// Syntax Error Fixed here (removed the trailing semicolon inside the parenthesis)
app.use('/api/*', (_, res) => res.status(404).json({ error: 'API route not found' }));

app.get('*', (req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));

const PORT = process.env.PORT || 5000;
initializeDatabase().then(() => {
    app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
});
