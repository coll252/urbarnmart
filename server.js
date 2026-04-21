const express = require('express');
const mysql = require('mysql2/promise');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
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
    multipleStatements: true // Allows running multiple queries at once if needed
};

if (process.env.DATABASE_URL) {
    dbConfig.uri = process.env.DATABASE_URL;
    dbConfig.ssl = { rejectUnauthorized: true }; // Required for Aiven
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

        // 1. Create Tables using IF NOT EXISTS
        await pool.query(`
            CREATE TABLE IF NOT EXISTS categories (
                id INT AUTO_INCREMENT PRIMARY KEY,
                name VARCHAR(100) NOT NULL,
                slug VARCHAR(100) UNIQUE NOT NULL,
                icon VARCHAR(50) DEFAULT 'fa-tag'
            );
        `);

        await pool.query(`
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
        `);

        await pool.query(`
            CREATE TABLE IF NOT EXISTS users (
                id INT AUTO_INCREMENT PRIMARY KEY,
                name VARCHAR(100) NOT NULL,
                email VARCHAR(100) UNIQUE NOT NULL,
                password VARCHAR(255) NOT NULL,
                role ENUM('customer') DEFAULT 'customer',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
        `);

        await pool.query(`
            CREATE TABLE IF NOT EXISTS cart (
                id INT AUTO_INCREMENT PRIMARY KEY,
                user_id INT NOT NULL,
                product_id INT NOT NULL,
                quantity INT NOT NULL DEFAULT 1,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
                FOREIGN KEY (product_id) REFERENCES products(id) ON DELETE CASCADE
            );
        `);

        await pool.query(`
            CREATE TABLE IF NOT EXISTS orders (
                id INT AUTO_INCREMENT PRIMARY KEY,
                order_number VARCHAR(50) UNIQUE NOT NULL,
                user_id INT NOT NULL,
                customer_name VARCHAR(100) NOT NULL,
                total DECIMAL(10, 2) NOT NULL,
                status ENUM('Pending', 'Shipped', 'Delivered', 'Cancelled') DEFAULT 'Pending',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
            );
        `);

        await pool.query(`
            CREATE TABLE IF NOT EXISTS order_items (
                id INT AUTO_INCREMENT PRIMARY KEY,
                order_id INT NOT NULL,
                product_id INT NOT NULL,
                product_name VARCHAR(255) NOT NULL,
                quantity INT NOT NULL,
                price DECIMAL(10, 2) NOT NULL,
                FOREIGN KEY (order_id) REFERENCES orders(id) ON DELETE CASCADE
            );
        `);

        await pool.query(`
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
        `);

        // 2. Seed Data (Only inject if tables are empty to avoid duplicates on restart)
        const [catRows] = await pool.query('SELECT COUNT(*) as count FROM categories');
        if (catRows[0].count === 0) {
            console.log("Seeding categories...");
            await pool.query(`
                INSERT INTO categories (name, slug, icon) VALUES 
                ('Smartphone & Tablet', 'smartphone-tablet', 'fa-mobile-alt'),
                ('Watch & Jewelry', 'watch-jewelry', 'fa-clock'),
                ('Furniture & Decor', 'furniture-decor', 'fa-couch'),
                ('Fashion & Apparel', 'fashion', 'fa-tshirt'),
                ('Audio & Electronics', 'electronics', 'fa-headphones'),
                ('Laptops & PCs', 'laptop', 'fa-laptop');
            `);
        }

        const [prodRows] = await pool.query('SELECT COUNT(*) as count FROM products');
        if (prodRows[0].count === 0) {
            console.log("Seeding products...");
            await pool.query(`
                INSERT INTO products (name, category_slug, price, old_price, stock, description, is_best_selling) VALUES 
                ('iPhone 17 Pro Max Titanium', 'smartphone-tablet', 1299.00, 1499.00, 25, 'Latest A17 chip with 12GB RAM, 48MP advanced camera system.', TRUE),
                ('Rolex Submariner Replica', 'watch-jewelry', 599.00, 899.00, 15, 'Premium automatic movement watch with sapphire crystal.', TRUE),
                ('Nordic Minimalist Sofa', 'furniture-decor', 899.00, 1200.00, 8, 'Comfortable 3-seater sofa with premium fabric and wooden legs.', TRUE),
                ('Apple iPad Pro M4', 'smartphone-tablet', 999.00, 1199.00, 40, '12.9-inch Liquid Retina XDR display with ultra-fast M4 chip.', FALSE),
                ('Apple Watch Ultra 2', 'watch-jewelry', 799.00, 899.00, 12, 'Rugged titanium case, precision dual-frequency GPS.', TRUE),
                ('MacBook Pro 16" M3 Max', 'laptop', 3499.00, 3999.00, 5, '16-core CPU, 40-core GPU, 48GB Unified Memory.', TRUE),
                ('Dell XPS 15 OLED', 'laptop', 1599.00, 1999.00, 10, 'Intel Core i9, 32GB RAM, 1TB NVMe SSD, stunning OLED display.', FALSE),
                ('Sony WH-1000XM5', 'electronics', 349.00, 399.00, 20, 'Industry leading noise canceling wireless headphones.', TRUE),
                ('Premium Leather Jacket', 'fashion', 249.00, 350.00, 25, 'Genuine Italian leather with modern fit and durable zippers.', FALSE),
                ('Samsung Galaxy S24 Ultra', 'smartphone-tablet', 1199.00, 1299.00, 18, 'AI-powered flagship with built-in S Pen and 200MP camera.', TRUE);
            `);
        }

        const [setRows] = await pool.query('SELECT COUNT(*) as count FROM settings');
        if (setRows[0].count === 0) {
            console.log("Seeding settings...");
            await pool.query(`
                INSERT INTO settings (id, hero_product_id, color_primary, color_secondary, color_accent, color_bg, color_surface) 
                VALUES (1, 1, '#020617', '#0f172a', '#10b981', '#f8fafc', '#ffffff');
            `);
        }

        console.log("Database initialized successfully!");
    } catch (err) {
        console.error("Database initialization failed:", err.message);
    }
}

function signToken(user) {
    return jwt.sign(
        { id: user.id, role: user.role, name: user.name, email: user.email || null },
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

async function queryOne(sql, params = []) {
    const [rows] = await pool.query(sql, params);
    return rows[0] || null;
}

// Heartbeat endpoint to prevent session timeout and keep Render awake
app.get('/api/heartbeat', (_, res) => {
    res.json({ ok: true, timestamp: Date.now() });
});

app.get('/api/health', async (_, res) => {
    try {
        await pool.query('SELECT 1');
        res.json({ ok: true });
    } catch {
        res.status(500).json({ ok: false });
    }
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

app.post('/api/auth/register', async (req, res) => {
    try {
        const name = String(req.body.name || '').trim();
        const email = String(req.body.email || '').trim().toLowerCase();
        const password = String(req.body.password || '');

        if (!name || !email || !password) {
            return res.status(400).json({ error: 'All fields are required' });
        }

        if (email === String(process.env.ADMIN_EMAIL || '').trim().toLowerCase()) {
            return res.status(400).json({ error: 'This email is reserved by the system' });
        }

        const existing = await queryOne('SELECT id FROM users WHERE email = ?', [email]);
        if (existing) return res.status(400).json({ error: 'Email already exists' });

        const hashed = await bcrypt.hash(password, 10);
        await pool.query(
            'INSERT INTO users (name, email, password, role) VALUES (?, ?, ?, ?)',
            [name, email, hashed, 'customer']
        );

        res.status(201).json({ message: 'Account created successfully' });
    } catch {
        res.status(500).json({ error: 'Registration failed' });
    }
});

app.post('/api/auth/login', async (req, res) => {
    try {
        const email = String(req.body.email || '').trim().toLowerCase();
        const password = String(req.body.password || '');

        const adminEmail = String(process.env.ADMIN_EMAIL || '').trim().toLowerCase();
        const adminPassword = String(process.env.ADMIN_PASSWORD || '');

        if (email === adminEmail) {
            if (password !== adminPassword) {
                return res.status(400).json({ error: 'Invalid admin credentials' });
            }

            const adminUser = {
                id: 0,
                name: 'System Administrator',
                email: adminEmail,
                role: 'admin'
            };

            return res.json({
                token: signToken(adminUser),
                user: adminUser
            });
        }

        const user = await queryOne('SELECT * FROM users WHERE email = ?', [email]);
        if (!user) return res.status(400).json({ error: 'Invalid credentials' });

        const valid = await bcrypt.compare(password, user.password);
        if (!valid) return res.status(400).json({ error: 'Invalid credentials' });

        const payloadUser = {
            id: user.id,
            name: user.name,
            email: user.email,
            role: user.role
        };

        res.json({
            token: signToken(payloadUser),
            user: payloadUser
        });
    } catch {
        res.status(500).json({ error: 'Login failed' });
    }
});

app.get('/api/settings', async (_, res) => {
    try {
        const settings = await queryOne('SELECT * FROM settings WHERE id = 1');
        res.json(settings || {});
    } catch {
        res.status(500).json({ error: 'Failed to load settings' });
    }
});

app.put('/api/settings', authenticateToken, isAdmin, async (req, res) => {
    try {
        const {
            hero_product_id = null,
            color_primary = '#020617',
            color_secondary = '#0f172a',
            color_accent = '#10b981',
            color_bg = '#f8fafc',
            color_surface = '#ffffff'
        } = req.body;

        const existing = await queryOne('SELECT id FROM settings WHERE id = 1');

        if (existing) {
            await pool.query(
                `UPDATE settings
                 SET hero_product_id = ?, color_primary = ?, color_secondary = ?, color_accent = ?, color_bg = ?, color_surface = ?
                 WHERE id = 1`,
                [hero_product_id, color_primary, color_secondary, color_accent, color_bg, color_surface]
            );
        } else {
            await pool.query(
                `INSERT INTO settings
                 (id, hero_product_id, color_primary, color_secondary, color_accent, color_bg, color_surface)
                 VALUES (1, ?, ?, ?, ?, ?, ?)`,
                [hero_product_id, color_primary, color_secondary, color_accent, color_bg, color_surface]
            );
        }

        res.json({ message: 'Settings updated successfully' });
    } catch {
        res.status(500).json({ error: 'Failed to update settings' });
    }
});

app.get('/api/products', async (_, res) => {
    try {
        const [rows] = await pool.query(
            'SELECT * FROM products ORDER BY is_best_selling DESC, created_at DESC, id DESC'
        );
        res.json(rows);
    } catch {
        res.status(500).json({ error: 'Failed to load products' });
    }
});

app.post('/api/products', authenticateToken, isAdmin, upload.single('image'), async (req, res) => {
    try {
        const name = String(req.body.name || '').trim();
        const category_slug = req.body.category_slug || null;
        const price = Number(req.body.price || 0);
        const old_price = req.body.old_price ? Number(req.body.old_price) : null;
        const stock = Number(req.body.stock || 0);
        const description = String(req.body.description || '').trim();
        const is_best_selling =
            req.body.is_best_selling === true ||
            req.body.is_best_selling === 'true' ||
            req.body.is_best_selling === '1' ||
            req.body.is_best_selling === 1;

        if (!name || !category_slug || price <= 0) {
            return res.status(400).json({ error: 'Name, category and valid price are required' });
        }

        const existing = await queryOne('SELECT id FROM products WHERE name = ?', [name]);
        if (existing) return res.status(400).json({ error: 'Product with that name already exists' });

        const image = req.file ? `/uploads/${req.file.filename}` : null;

        await pool.query(
            `INSERT INTO products
            (name, category_slug, price, old_price, stock, image, description, is_best_selling)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
            [name, category_slug, price, old_price, stock, image, description, is_best_selling]
        );

        res.status(201).json({ message: 'Product created successfully' });
    } catch {
        res.status(500).json({ error: 'Failed to create product' });
    }
});

app.put('/api/products/:id', authenticateToken, isAdmin, upload.single('image'), async (req, res) => {
    try {
        const id = Number(req.params.id);
        const name = String(req.body.name || '').trim();
        const category_slug = req.body.category_slug || null;
        const price = Number(req.body.price || 0);
        const old_price = req.body.old_price ? Number(req.body.old_price) : null;
        const stock = Number(req.body.stock || 0);
        const description = String(req.body.description || '').trim();
        const is_best_selling =
            req.body.is_best_selling === true ||
            req.body.is_best_selling === 'true' ||
            req.body.is_best_selling === '1' ||
            req.body.is_best_selling === 1;

        const current = await queryOne('SELECT * FROM products WHERE id = ?', [id]);
        if (!current) return res.status(404).json({ error: 'Product not found' });

        const duplicate = await queryOne('SELECT id FROM products WHERE name = ? AND id != ?', [name, id]);
        if (duplicate) return res.status(400).json({ error: 'Another product already uses that name' });

        let image = current.image;
        if (req.file) image = `/uploads/${req.file.filename}`;

        await pool.query(
            `UPDATE products
             SET name = ?, category_slug = ?, price = ?, old_price = ?, stock = ?, image = ?, description = ?, is_best_selling = ?
             WHERE id = ?`,
            [name, category_slug, price, old_price, stock, image, description, is_best_selling, id]
        );

        res.json({ message: 'Product updated successfully' });
    } catch {
        res.status(500).json({ error: 'Failed to update product' });
    }
});

app.delete('/api/products/:id', authenticateToken, isAdmin, async (req, res) => {
    try {
        const id = Number(req.params.id);
        await pool.query('DELETE FROM products WHERE id = ?', [id]);
        res.json({ message: 'Product deleted successfully' });
    } catch {
        res.status(500).json({ error: 'Failed to delete product' });
    }
});

app.get('/api/categories', async (_, res) => {
    try {
        const [rows] = await pool.query('SELECT * FROM categories ORDER BY name ASC');
        res.json(rows);
    } catch {
        res.status(500).json({ error: 'Failed to load categories' });
    }
});

app.post('/api/categories', authenticateToken, isAdmin, async (req, res) => {
    try {
        const name = String(req.body.name || '').trim();
        const slug = String(req.body.slug || '').trim().toLowerCase();
        const icon = String(req.body.icon || 'fa-tag').trim();

        if (!name || !slug) return res.status(400).json({ error: 'Name and slug are required' });

        const existing = await queryOne('SELECT id FROM categories WHERE slug = ?', [slug]);
        if (existing) return res.status(400).json({ error: 'Category slug already exists' });

        await pool.query(
            'INSERT INTO categories (name, slug, icon) VALUES (?, ?, ?)',
            [name, slug, icon]
        );

        res.status(201).json({ message: 'Category created successfully' });
    } catch {
        res.status(500).json({ error: 'Failed to create category' });
    }
});

app.delete('/api/categories/:id', authenticateToken, isAdmin, async (req, res) => {
    try {
        const id = Number(req.params.id);
        await pool.query('DELETE FROM categories WHERE id = ?', [id]);
        res.json({ message: 'Category deleted successfully' });
    } catch {
        res.status(500).json({ error: 'Failed to delete category' });
    }
});

app.get('/api/cart', authenticateToken, isCustomer, async (req, res) => {
    try {
        const [rows] = await pool.query(
            `SELECT c.product_id, c.quantity, p.*
             FROM cart c
             JOIN products p ON c.product_id = p.id
             WHERE c.user_id = ?
             ORDER BY c.id DESC`,
            [req.user.id]
        );
        res.json(rows);
    } catch {
        res.status(500).json({ error: 'Failed to load cart' });
    }
});

app.post('/api/cart', authenticateToken, isCustomer, async (req, res) => {
    try {
        const product_id = Number(req.body.product_id);
        const quantity = Math.max(1, Number(req.body.quantity || 1));

        const product = await queryOne('SELECT id, stock FROM products WHERE id = ?', [product_id]);
        if (!product) return res.status(404).json({ error: 'Product not found' });

        const existing = await queryOne(
            'SELECT id, quantity FROM cart WHERE user_id = ? AND product_id = ?',
            [req.user.id, product_id]
        );

        if (existing) {
            const newQty = existing.quantity + quantity;
            if (newQty > product.stock) return res.status(400).json({ error: 'Not enough stock available' });

            await pool.query(
                'UPDATE cart SET quantity = ? WHERE id = ?',
                [newQty, existing.id]
            );
        } else {
            if (quantity > product.stock) return res.status(400).json({ error: 'Not enough stock available' });

            await pool.query(
                'INSERT INTO cart (user_id, product_id, quantity) VALUES (?, ?, ?)',
                [req.user.id, product_id, quantity]
            );
        }

        res.json({ message: 'Added to cart successfully' });
    } catch {
        res.status(500).json({ error: 'Failed to add to cart' });
    }
});

app.put('/api/cart/:productId', authenticateToken, isCustomer, async (req, res) => {
    try {
        const productId = Number(req.params.productId);
        const quantity = Math.max(1, Number(req.body.quantity || 1));

        const product = await queryOne('SELECT id, stock FROM products WHERE id = ?', [productId]);
        if (!product) return res.status(404).json({ error: 'Product not found' });
        if (quantity > product.stock) return res.status(400).json({ error: 'Not enough stock available' });

        await pool.query(
            'UPDATE cart SET quantity = ? WHERE user_id = ? AND product_id = ?',
            [quantity, req.user.id, productId]
        );

        res.json({ message: 'Cart updated successfully' });
    } catch {
        res.status(500).json({ error: 'Failed to update cart' });
    }
});

app.delete('/api/cart/:productId', authenticateToken, isCustomer, async (req, res) => {
    try {
        const productId = Number(req.params.productId);
        await pool.query('DELETE FROM cart WHERE user_id = ? AND product_id = ?', [req.user.id, productId]);
        res.json({ message: 'Removed from cart successfully' });
    } catch {
        res.status(500).json({ error: 'Failed to remove item from cart' });
    }
});

app.post('/api/orders', authenticateToken, isCustomer, async (req, res) => {
    const connection = await pool.getConnection();

    try {
        await connection.beginTransaction();

        const [cartItems] = await connection.query(
            `SELECT c.quantity, p.id, p.name, p.price, p.stock
             FROM cart c
             JOIN products p ON c.product_id = p.id
             WHERE c.user_id = ?`,
            [req.user.id]
        );

        if (cartItems.length === 0) {
            throw new Error('Your cart is empty');
        }

        let total = 0;
        for (const item of cartItems) {
            if (item.stock < item.quantity) {
                throw new Error(`Insufficient stock for ${item.name}`);
            }
            total += Number(item.price) * Number(item.quantity);
        }

        const orderNumber = `ORD${Date.now()}`;

        const [orderResult] = await connection.query(
            `INSERT INTO orders (order_number, user_id, customer_name, total)
             VALUES (?, ?, ?, ?)`,
            [orderNumber, req.user.id, req.user.name, total]
        );

        const orderId = orderResult.insertId;

        for (const item of cartItems) {
            await connection.query(
                `INSERT INTO order_items (order_id, product_id, product_name, quantity, price)
                 VALUES (?, ?, ?, ?, ?)`,
                [orderId, item.id, item.name, item.quantity, item.price]
            );

            await connection.query(
                'UPDATE products SET stock = stock - ? WHERE id = ?',
                [item.quantity, item.id]
            );
        }

        await connection.query('DELETE FROM cart WHERE user_id = ?', [req.user.id]);
        await connection.commit();

        res.status(201).json({ message: 'Order placed successfully' });
    } catch (err) {
        await connection.rollback();
        res.status(400).json({ error: err.message || 'Failed to place order' });
    } finally {
        connection.release();
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

app.put('/api/orders/:id', authenticateToken, isAdmin, async (req, res) => {
    try {
        const id = Number(req.params.id);
        const status = String(req.body.status || '').trim();

        if (!['Pending', 'Shipped', 'Delivered', 'Cancelled'].includes(status)) {
            return res.status(400).json({ error: 'Invalid order status' });
        }

        await pool.query('UPDATE orders SET status = ? WHERE id = ?', [status, id]);
        res.json({ message: 'Order status updated successfully' });
    } catch {
        res.status(500).json({ error: 'Failed to update order status' });
    }
});

app.get('/api/users', authenticateToken, isAdmin, async (_, res) => {
    try {
        const [rows] = await pool.query(
            'SELECT id, name, email, role, created_at FROM users ORDER BY created_at DESC, id DESC'
        );
        res.json(rows);
    } catch {
        res.status(500).json({ error: 'Failed to load users' });
    }
});

app.get('/api/admin/stats', authenticateToken, isAdmin, async (_, res) => {
    try {
        const totalProducts = await queryOne('SELECT COUNT(*) AS count FROM products');
        const totalCategories = await queryOne('SELECT COUNT(*) AS count FROM categories');
        const totalUsers = await queryOne('SELECT COUNT(*) AS count FROM users');
        const totalOrders = await queryOne('SELECT COUNT(*) AS count FROM orders');
        const totalRevenue = await queryOne(
            `SELECT COALESCE(SUM(total), 0) AS total
             FROM orders
             WHERE status IN ('Pending', 'Shipped', 'Delivered')`
        );
        const lowStock = await queryOne('SELECT COUNT(*) AS count FROM products WHERE stock <= 5');
        const recentOrders = await queryOne(
            `SELECT COALESCE(COUNT(*), 0) AS count
             FROM orders
             WHERE DATE(created_at) = CURDATE()`
        );

        res.json({
            totalProducts: totalProducts.count,
            totalCategories: totalCategories.count,
            totalUsers: totalUsers.count,
            totalOrders: totalOrders.count,
            totalRevenue: Number(totalRevenue.total || 0),
            lowStockProducts: lowStock.count,
            todayOrders: recentOrders.count
        });
    } catch {
        res.status(500).json({ error: 'Failed to load admin stats' });
    }
});

// Fallback for API routes
app.use('/api/*', (_, res) => {
    res.status(404).json({ error: 'API route not found' });
});

// Any other route falls back to index.html for SPA support
app.get('*', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

const PORT = process.env.PORT || 5000;

// Initialize the database, then start listening
initializeDatabase().then(() => {
    app.listen(PORT, () => {
        console.log(`Server running on port ${PORT}`);
    });
});