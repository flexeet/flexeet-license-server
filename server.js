require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const helmet = require('helmet');
const compression = require('compression');
const rateLimit = require('express-rate-limit');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');

const License = require('./models/License');

const app = express();

// Middleware
app.use(helmet({
    contentSecurityPolicy: {
        directives: {
            defaultSrc: ["'self'"],
            scriptSrc: ["'self'", "'unsafe-inline'", "'unsafe-eval'"],
            scriptSrcAttr: ["'unsafe-inline'"],
            styleSrc: ["'self'", "'unsafe-inline'"],
            imgSrc: ["'self'", "data:", "https:"],
        },
    },
}));
app.use(compression());
app.use(cors({
    origin: process.env.ALLOWED_ORIGINS === '*' ? '*' : process.env.ALLOWED_ORIGINS.split(','),
    credentials: true
}));
app.use(express.json());
app.use(express.static('public'));

// Rate limiting
const limiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 100, // limit each IP to 100 requests per windowMs
    message: { success: false, error: 'Too many requests, please try again later.' }
});
app.use('/api/', limiter);

// Database connection
mongoose.connect(process.env.MONGODB_URI)
.then(() => {
    console.log('✅ Connected to MongoDB Atlas');
    console.log('📍 Database:', mongoose.connection.name);
})
.catch(err => {
    console.error('❌ MongoDB connection error:', err.message);
    process.exit(1);
});

// Utility functions
function generateLicenseKey() {
    const prefix = 'FLEX';
    const random = crypto.randomBytes(16).toString('hex').toUpperCase();
    return `${prefix}-${random.slice(0,4)}-${random.slice(4,8)}-${random.slice(8,12)}-${random.slice(12,16)}`;
}

function generateToken(licenseKey, fingerprint, tier) {
    return jwt.sign(
        {
            licenseKey,
            fingerprint,
            tier,
            iat: Math.floor(Date.now() / 1000)
        },
        process.env.JWT_SECRET,
        { expiresIn: '6h' }
    );
}

function verifyToken(token) {
    try {
        return jwt.verify(token, process.env.JWT_SECRET);
    } catch (error) {
        return null;
    }
}

function getFeatureFlags(tier) {
    const features = {
        basic: {
            autoScraping: true,
            cooldownBypass: false,
            prioritySupport: false
        },
        pro: {
            autoScraping: true,
            cooldownBypass: true,
            prioritySupport: true
        },
        enterprise: {
            autoScraping: true,
            cooldownBypass: true,
            prioritySupport: true
        }
    };
    return features[tier] || features.basic;
}

// Routes
app.get('/', (req, res) => {
    res.json({
        message: 'Flexeet License Server',
        status: 'running',
        version: '1.0.0',
        timestamp: new Date().toISOString()
    });
});

app.get('/health', (req, res) => {
    res.json({
        status: 'ok',
        database: mongoose.connection.readyState === 1 ? 'connected' : 'disconnected',
        timestamp: new Date().toISOString()
    });
});

// Validate License Key
app.post('/api/validate-license', async (req, res) => {
    try {
        const { licenseKey, fingerprint } = req.body;

        if (!licenseKey || !fingerprint) {
            return res.status(400).json({
                success: false,
                error: 'License key and fingerprint required'
            });
        }

        const license = await License.findOne({ licenseKey });

        if (!license) {
            return res.status(404).json({
                success: false,
                error: 'Invalid license key'
            });
        }

        if (license.status !== 'active') {
            return res.status(403).json({
                success: false,
                error: `License is ${license.status}`
            });
        }

        if (new Date() > new Date(license.expiryDate)) {
            license.status = 'expired';
            await license.save();
            return res.status(403).json({
                success: false,
                error: 'License has expired'
            });
        }

        // Check device limit
        const deviceIndex = license.devices.findIndex(d => d.fingerprint === fingerprint);

        if (deviceIndex === -1) {
            if (license.devices.length >= license.maxDevices) {
                return res.status(403).json({
                    success: false,
                    error: `Maximum ${license.maxDevices} devices allowed. Please deactivate a device first.`
                });
            }

            license.devices.push({
                fingerprint,
                lastUsed: new Date(),
                userAgent: req.headers['user-agent']
            });
            await license.save();
        } else {
            license.devices[deviceIndex].lastUsed = new Date();
            await license.save();
        }

        const token = generateToken(licenseKey, fingerprint, license.tier);

        res.json({
            success: true,
            token,
            license: {
                email: license.email,
                tier: license.tier,
                expiresAt: license.expiryDate,
                maxDevices: license.maxDevices,
                deviceCount: license.devices.length,
                features: getFeatureFlags(license.tier)
            }
        });

    } catch (error) {
        console.error('Validation error:', error);
        res.status(500).json({
            success: false,
            error: 'Internal server error'
        });
    }
});

// Refresh Token
app.post('/api/refresh-token', async (req, res) => {
    try {
        const { token } = req.body;

        const decoded = verifyToken(token);
        if (!decoded) {
            return res.status(401).json({
                success: false,
                error: 'Invalid or expired token'
            });
        }

        const license = await License.findOne({ licenseKey: decoded.licenseKey });

        if (!license || license.status !== 'active') {
            return res.status(403).json({
                success: false,
                error: 'License no longer valid'
            });
        }

        const newToken = generateToken(decoded.licenseKey, decoded.fingerprint, license.tier);

        res.json({
            success: true,
            token: newToken
        });

    } catch (error) {
        console.error('Refresh error:', error);
        res.status(500).json({
            success: false,
            error: 'Internal server error'
        });
    }
});

// Log Usage (Deprecated - Unlimited scraping)
app.post('/api/log-usage', async (req, res) => {
    try {
        const { token, ordersScraped } = req.body;

        const decoded = verifyToken(token);
        if (!decoded) {
            return res.status(401).json({
                success: false,
                error: 'Invalid token'
            });
        }

        const license = await License.findOne({ licenseKey: decoded.licenseKey });

        if (!license) {
            return res.status(404).json({
                success: false,
                error: 'License not found'
            });
        }

        // No usage tracking - unlimited scraping
        res.json({
            success: true,
            message: 'Unlimited scraping enabled'
        });

    } catch (error) {
        console.error('Usage log error:', error);
        res.status(500).json({
            success: false,
            error: 'Internal server error'
        });
    }
});

// Proxy to Google Sheets
app.post('/api/send-to-sheets', async (req, res) => {
    try {
        const { token, data } = req.body;

        const decoded = verifyToken(token);
        if (!decoded) {
            return res.status(401).json({
                success: false,
                error: 'Invalid token'
            });
        }

        const license = await License.findOne({ licenseKey: decoded.licenseKey });
        const sheetsUrl = license?.googleSheetsUrl;

        if (!sheetsUrl) {
            return res.status(400).json({
                success: false,
                error: 'Google Sheets URL not configured'
            });
        }

        // Forward data to Google Sheets
        const fetch = (await import('node-fetch')).default;
        const response = await fetch(sheetsUrl, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(data)
        });

        const result = await response.text();

        res.json({
            success: true,
            result
        });

    } catch (error) {
        console.error('Sheets proxy error:', error);
        res.status(500).json({
            success: false,
            error: 'Failed to send data to sheets'
        });
    }
});

// Get License Info
app.get('/api/license-info', async (req, res) => {
    try {
        const token = req.headers.authorization?.replace('Bearer ', '');

        const decoded = verifyToken(token);
        if (!decoded) {
            return res.status(401).json({
                success: false,
                error: 'Invalid token'
            });
        }

        const license = await License.findOne({ licenseKey: decoded.licenseKey });

        if (!license) {
            return res.status(404).json({
                success: false,
                error: 'License not found'
            });
        }

        res.json({
            success: true,
            license: {
                email: license.email,
                tier: license.tier,
                status: license.status,
                expiresAt: license.expiryDate,
                maxDevices: license.maxDevices,
                devices: license.devices.map(d => ({
                    fingerprint: d.fingerprint.slice(0, 8) + '...',
                    lastUsed: d.lastUsed,
                    activatedAt: d.activatedAt,
                    isCurrent: d.fingerprint === decoded.fingerprint
                }))
            }
        });

    } catch (error) {
        console.error('License info error:', error);
        res.status(500).json({
            success: false,
            error: 'Internal server error'
        });
    }
});

// Update Google Sheets URL
app.post('/api/update-sheets-url', async (req, res) => {
    try {
        const { token, sheetsUrl } = req.body;

        const decoded = verifyToken(token);
        if (!decoded) {
            return res.status(401).json({
                success: false,
                error: 'Invalid token'
            });
        }

        if (!sheetsUrl || !sheetsUrl.startsWith('https://script.google.com/')) {
            return res.status(400).json({
                success: false,
                error: 'Invalid Google Sheets URL'
            });
        }

        const license = await License.findOne({ licenseKey: decoded.licenseKey });

        if (!license) {
            return res.status(404).json({
                success: false,
                error: 'License not found'
            });
        }

        license.googleSheetsUrl = sheetsUrl;
        await license.save();

        res.json({
            success: true,
            message: 'Google Sheets URL updated'
        });

    } catch (error) {
        console.error('Update sheets URL error:', error);
        res.status(500).json({
            success: false,
            error: 'Internal server error'
        });
    }
});

// ADMIN: Create License
app.post('/api/admin/create-license', async (req, res) => {
    try {
        const { adminApiKey, email, tier, maxDevices, durationDays, freeTrialDays } = req.body;

        if (adminApiKey !== process.env.ADMIN_API_KEY) {
            return res.status(401).json({
                success: false,
                error: 'Unauthorized'
            });
        }

        if (!email || !tier) {
            return res.status(400).json({
                success: false,
                error: 'Email and tier required'
            });
        }

        const licenseKey = generateLicenseKey();
        const expiryDate = new Date();
        const totalDays = (durationDays || 30) + (freeTrialDays || 0);
        expiryDate.setDate(expiryDate.getDate() + totalDays);

        const license = await License.create({
            licenseKey,
            email,
            status: 'active',
            tier,
            expiryDate,
            maxDevices: maxDevices || 2,
            devices: []
        });

        res.json({
            success: true,
            license: {
                licenseKey,
                email,
                tier,
                expiresAt: expiryDate,
                maxDevices: maxDevices || 2,
                status: 'active'
            }
        });

    } catch (error) {
        console.error('Create license error:', error);
        res.status(500).json({
            success: false,
            error: 'Internal server error'
        });
    }
});

// ADMIN: Suspend License
app.post('/admin/suspend-license', async (req, res) => {
    try {
        const apiKey = req.headers['x-admin-key'];

        if (apiKey !== process.env.ADMIN_API_KEY) {
            return res.status(401).json({
                success: false,
                error: 'Unauthorized'
            });
        }

        const { licenseKey } = req.body;

        const license = await License.findOne({ licenseKey });

        if (!license) {
            return res.status(404).json({
                success: false,
                error: 'License not found'
            });
        }

        license.status = 'suspended';
        await license.save();

        res.json({
            success: true,
            message: 'License suspended'
        });

    } catch (error) {
        console.error('Suspend license error:', error);
        res.status(500).json({
            success: false,
            error: 'Internal server error'
        });
    }
});

// ADMIN: List all licenses
app.get('/api/admin/licenses', async (req, res) => {
    try {
        const { adminApiKey } = req.query;

        if (adminApiKey !== process.env.ADMIN_API_KEY) {
            return res.status(401).json({
                success: false,
                error: 'Unauthorized'
            });
        }

        const licenses = await License.find().sort({ createdAt: -1 });

        res.json({
            success: true,
            count: licenses.length,
            licenses: licenses.map(l => ({
                licenseKey: l.licenseKey,
                email: l.email,
                tier: l.tier,
                status: l.status,
                expiresAt: l.expiryDate,
                maxDevices: l.maxDevices,
                devices: l.devices,
                createdAt: l.createdAt
            }))
        });

    } catch (error) {
        console.error('List licenses error:', error);
        res.status(500).json({
            success: false,
            error: 'Internal server error'
        });
    }
});

// Error handler
app.use((err, req, res, next) => {
    console.error(err.stack);
    res.status(500).json({
        success: false,
        error: 'Internal server error'
    });
});

// Start server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`🚀 Flexeet License Server running on port ${PORT}`);
    console.log(`📍 Environment: ${process.env.NODE_ENV}`);
    console.log(`🌐 Server URL: http://localhost:${PORT}`);
});

module.exports = app;

// ADMIN: Reset Devices
app.post('/api/admin/reset-devices', async (req, res) => {
    try {
        const { adminApiKey, licenseKey } = req.body;

        if (adminApiKey !== process.env.ADMIN_API_KEY) {
            return res.status(401).json({
                success: false,
                error: 'Unauthorized'
            });
        }

        const license = await License.findOne({ licenseKey });

        if (!license) {
            return res.status(404).json({
                success: false,
                error: 'License not found'
            });
        }

        license.devices = [];
        await license.save();

        res.json({
            success: true,
            message: 'Devices reset successfully',
            licenseKey
        });

    } catch (error) {
        console.error('Reset devices error:', error);
        res.status(500).json({
            success: false,
            error: 'Internal server error'
        });
    }
});

// ADMIN: Extend License
app.post('/api/admin/extend-license', async (req, res) => {
    try {
        const { adminApiKey, licenseKey, additionalDays } = req.body;

        if (adminApiKey !== process.env.ADMIN_API_KEY) {
            return res.status(401).json({
                success: false,
                error: 'Unauthorized'
            });
        }

        const license = await License.findOne({ licenseKey });

        if (!license) {
            return res.status(404).json({
                success: false,
                error: 'License not found'
            });
        }

        const currentExpiry = new Date(license.expiryDate);
        const now = new Date();

        // If expired, extend from now. Otherwise extend from current expiry
        const baseDate = currentExpiry > now ? currentExpiry : now;
        baseDate.setDate(baseDate.getDate() + parseInt(additionalDays));

        license.expiryDate = baseDate;
        license.status = 'active'; // Reactivate if was expired
        await license.save();

        res.json({
            success: true,
            message: `License extended by ${additionalDays} days`,
            license: {
                licenseKey,
                expiresAt: license.expiryDate,
                status: license.status
            }
        });

    } catch (error) {
        console.error('Extend license error:', error);
        res.status(500).json({
            success: false,
            error: 'Internal server error'
        });
    }
});

// ADMIN: Get License Details
app.get('/api/admin/license-details', async (req, res) => {
    try {
        const { adminApiKey, licenseKey } = req.query;

        if (adminApiKey !== process.env.ADMIN_API_KEY) {
            return res.status(401).json({
                success: false,
                error: 'Unauthorized'
            });
        }

        const license = await License.findOne({ licenseKey });

        if (!license) {
            return res.status(404).json({
                success: false,
                error: 'License not found'
            });
        }

        res.json({
            success: true,
            license: {
                licenseKey: license.licenseKey,
                email: license.email,
                tier: license.tier,
                status: license.status,
                expiresAt: license.expiryDate,
                maxDevices: license.maxDevices,
                devices: license.devices,
                createdAt: license.createdAt,
                updatedAt: license.updatedAt
            }
        });

    } catch (error) {
        console.error('Get license details error:', error);
        res.status(500).json({
            success: false,
            error: 'Internal server error'
        });
    }
});