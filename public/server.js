const express = require('express');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');
const cors = require('cors');
require('dotenv').config();
const path = require('path');
const speakeasy = require('speakeasy');
const crypto = require('crypto');

const app = express();

// Güvenlik middleware'leri
app.use(helmet());
app.use(cors({
    origin: process.env.FRONTEND_URL,
    credentials: true
}));
app.use(express.json());

// Rate limiting
const limiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 dakika
    max: 100 // IP başına maksimum istek
});
app.use(limiter);

// Admin kimlik bilgileri (gerçek uygulamada veritabanında saklanmalı)
const ADMIN_USERNAME = process.env.ADMIN_USERNAME;
const ADMIN_PASSWORD_HASH = process.env.ADMIN_PASSWORD_HASH;

// JWT secret key
const JWT_SECRET = process.env.JWT_SECRET;

// Güvenli IP listesi
const ALLOWED_IPS = ['123.123.123.123']; // Kendi IP adresiniz

// IP kontrolü middleware
const checkIP = (req, res, next) => {
    const clientIP = req.ip;
    if (!ALLOWED_IPS.includes(clientIP)) {
        return res.status(403).json({ error: 'Access denied' });
    }
    next();
};

// Middleware - Token doğrulama
const authenticateToken = (req, res, next) => {
    const token = req.headers['authorization']?.split(' ')[1];

    if (!token) {
        return res.status(401).json({ error: 'Authentication required' });
    }

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) {
            return res.status(403).json({ error: 'Invalid or expired token' });
        }
        req.user = user;
        next();
    });
};

// 2FA secret key (güvenli bir yerde saklanmalı)
const secret = speakeasy.generateSecret({ length: 20 });

// Login işlemini güncelle
app.post('/api/admin/login', async (req, res) => {
    try {
        const { username, password, twoFactorCode } = req.body;

        // Kullanıcı adı ve şifre kontrolü
        if (username !== ADMIN_USERNAME) {
            return res.status(401).json({ error: 'Invalid credentials' });
        }

        const passwordMatch = await bcrypt.compare(password, ADMIN_PASSWORD_HASH);
        if (!passwordMatch) {
            return res.status(401).json({ error: 'Invalid credentials' });
        }

        // 2FA kontrolü
        const verified = speakeasy.totp.verify({
            secret: secret.base32,
            encoding: 'base32',
            token: twoFactorCode,
            window: 1
        });

        if (!verified) {
            return res.status(401).json({ error: 'Invalid 2FA code' });
        }

        const token = jwt.sign({ username }, JWT_SECRET, { expiresIn: '1h' });
        res.json({ token });
    } catch (error) {
        res.status(500).json({ error: 'Server error' });
    }
});

// Wallet endpoints
app.get('/api/admin/wallets', authenticateToken, (req, res) => {
    try {
        // Veritabanından cüzdanları getir
        const wallets = []; // Veritabanı sorgusu yapılacak
        res.json(wallets);
    } catch (error) {
        res.status(500).json({ error: 'Server error' });
    }
});

app.post('/api/admin/points', authenticateToken, (req, res) => {
    try {
        const { walletAddress, points } = req.body;
        // Veritabanında puan güncelle
        res.json({ success: true });
    } catch (error) {
        res.status(500).json({ error: 'Server error' });
    }
});

app.post('/api/admin/reset', authenticateToken, async (req, res) => {
    try {
        const { password } = req.body;
        const passwordMatch = await bcrypt.compare(password, ADMIN_PASSWORD_HASH);
        
        if (!passwordMatch) {
            return res.status(401).json({ error: 'Invalid password' });
        }

        // Veritabanında reset işlemi
        res.json({ success: true });
    } catch (error) {
        res.status(500).json({ error: 'Server error' });
    }
});

// Admin sayfası middleware'i
const adminAuth = (req, res, next) => {
    const token = req.headers['authorization']?.split(' ')[1] || req.cookies?.adminToken;
    const clientIP = req.ip;
    
    // IP kontrolü
    if (!ALLOWED_IPS.includes(clientIP)) {
        return res.status(403).send('Access denied');
    }

    // Token kontrolü
    if (!token || !req.session?.adminAuthenticated) {
        return res.redirect('/admin-login.html');
    }

    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        
        // Token süresi kontrolü
        const now = Math.floor(Date.now() / 1000);
        if (decoded.exp && decoded.exp < now) {
            req.session.destroy();
            return res.redirect('/admin-login.html');
        }

        next();
    } catch (error) {
        req.session.destroy();
        res.redirect('/admin-login.html');
    }
};

// Verify endpoint ekle
app.get('/api/admin/verify', adminAuth, (req, res) => {
    res.json({ status: 'ok' });
});

// exchangehub rotalarını güncelle
app.get('/exchangehub', adminAuth, (req, res) => {
    // Referrer kontrolü
    const referrer = req.get('Referrer');
    if (!referrer || !referrer.includes('/admin-login.html')) {
        return res.redirect('/admin-login.html');
    }
    
    res.sendFile(path.join(__dirname, 'private', 'exchangehub.html'));
});

app.get('/exchangehub.html', (req, res) => {
    res.redirect('/admin-login.html');
});

// Tüm exchangehub ve private erişimlerini engelle
app.use(['/exchangehub*', '/private*', '/admin*'], (req, res) => {
    res.redirect('/admin-login.html');
});

// Static dosya servisini sınırla
app.use(express.static('public', {
    setHeaders: (res, path) => {
        if (path.endsWith('.html')) {
            res.setHeader('Cache-Control', 'private, no-cache, no-store, must-revalidate');
            res.setHeader('Pragma', 'no-cache');
            res.setHeader('Expires', '-1');
        }
    }
}));

// Admin rotalarına IP kontrolü ekle
app.use('/api/admin/*', checkIP);

// Her gün değişen özel anahtar
const generateDailyKey = () => {
    const date = new Date().toISOString().split('T')[0];
    return crypto
        .createHash('sha256')
        .update(date + JWT_SECRET)
        .digest('hex')
        .substring(0, 8);
};

app.post('/api/admin/access', checkIP, async (req, res) => {
    const { accessKey } = req.body;
    const dailyKey = generateDailyKey();
    
    if (accessKey !== dailyKey) {
        return res.status(403).json({ error: 'Invalid access key' });
    }
    
    // Geçici erişim token'ı oluştur
    const tempToken = jwt.sign({ temp: true }, JWT_SECRET, { expiresIn: '5m' });
    res.json({ tempToken });
});

// Şifre doğrulama endpoint'i
app.post('/api/admin/verify-password', adminAuth, async (req, res) => {
    try {
        const { password } = req.body;
        
        if (!password) {
            return res.status(400).json({ error: 'Password required' });
        }

        const passwordMatch = await bcrypt.compare(password, ADMIN_PASSWORD_HASH);
        
        if (!passwordMatch) {
            return res.status(401).json({ error: 'Invalid password' });
        }

        res.json({ status: 'ok' });
    } catch (error) {
        res.status(500).json({ error: 'Server error' });
    }
});

// Environment variables örneği (.env dosyası)

// Server'ı başlat
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
}); 