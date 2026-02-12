// ========================================
// SURWIPE - Node.js Express Server
// For Cloudflare Pages deployment
// ========================================

const express = require('express');
const cors = require('cors');
const path = require('path');
const fetch = require('node-fetch');

const app = express();
const PORT = process.env.PORT || 3000;

// ========================================
// Configuration from Environment Variables
// ========================================

const CONFIG = {
    // reCAPTCHA v3 Secret Key
    recaptchaSecretKey: process.env.RECAPTCHA_SECRET_KEY || '6LdJOWksAAAAALNXHCOUnznQRvskUdbekr92tycQ',
    
    // Pabbly Webhook URL
    pabblyWebhookUrl: process.env.PABBLY_WEBHOOK_URL || 'https://connect.pabbly.com/workflow/sendwebhookdata/IjU3NjcwNTZjMDYzMTA0MzY1MjY4NTUzNjUxMzMi_pc',
    
    // Minimum reCAPTCHA score (0.0 to 1.0, recommended: 0.5)
    recaptchaMinScore: parseFloat(process.env.RECAPTCHA_MIN_SCORE || '0.5'),
    
    // Rate limiting
    rateLimitWindow: 60000, // 1 minute
    rateLimitMaxRequests: 5, // 5 requests per minute per IP
};

// ========================================
// Middleware
// ========================================

// CORS configuration
app.use(cors({
    origin: process.env.ALLOWED_ORIGINS ? process.env.ALLOWED_ORIGINS.split(',') : '*',
    methods: ['GET', 'POST'],
    credentials: true
}));

// Parse JSON bodies
app.use(express.json({ limit: '10mb' }));

// Serve static files
app.use(express.static(path.join(__dirname)));

// Request logging
app.use((req, res, next) => {
    console.log(`${new Date().toISOString()} - ${req.method} ${req.path}`);
    next();
});

// ========================================
// Rate Limiting (Simple In-Memory)
// ========================================

const rateLimitStore = new Map();

function rateLimit(req, res, next) {
    const ip = req.ip || req.connection.remoteAddress;
    const now = Date.now();
    
    // Clean old entries
    for (const [key, value] of rateLimitStore.entries()) {
        if (now - value.resetTime > CONFIG.rateLimitWindow) {
            rateLimitStore.delete(key);
        }
    }
    
    // Check rate limit
    if (!rateLimitStore.has(ip)) {
        rateLimitStore.set(ip, {
            count: 1,
            resetTime: now
        });
        return next();
    }
    
    const record = rateLimitStore.get(ip);
    
    if (now - record.resetTime > CONFIG.rateLimitWindow) {
        // Reset window
        record.count = 1;
        record.resetTime = now;
        return next();
    }
    
    if (record.count >= CONFIG.rateLimitMaxRequests) {
        return res.status(429).json({
            success: false,
            error: 'Too many requests. Please try again later.'
        });
    }
    
    record.count++;
    next();
}

// ========================================
// reCAPTCHA v3 Verification
// ========================================

async function verifyRecaptcha(token, remoteIp) {
    if (!CONFIG.recaptchaSecretKey) {
        console.warn('Warning: RECAPTCHA_SECRET_KEY not configured');
        return { success: false, error: 'Server configuration error' };
    }
    
    try {
        const response = await fetch('https://www.google.com/recaptcha/api/siteverify', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded',
            },
            body: `secret=${CONFIG.recaptchaSecretKey}&response=${token}&remoteip=${remoteIp}`
        });
        
        const data = await response.json();
        
        if (!data.success) {
            console.error('reCAPTCHA verification failed:', data['error-codes']);
            return {
                success: false,
                error: 'reCAPTCHA verification failed',
                details: data['error-codes']
            };
        }
        
        // Check score for v3
        if (data.score !== undefined && data.score < CONFIG.recaptchaMinScore) {
            console.warn(`Low reCAPTCHA score: ${data.score}`);
            return {
                success: false,
                error: 'Suspicious activity detected',
                score: data.score
            };
        }
        
        console.log(`reCAPTCHA verified successfully. Score: ${data.score || 'N/A'}`);
        return {
            success: true,
            score: data.score,
            action: data.action,
            challenge_ts: data.challenge_ts
        };
        
    } catch (error) {
        console.error('reCAPTCHA verification error:', error);
        return {
            success: false,
            error: 'reCAPTCHA verification failed',
            details: error.message
        };
    }
}

// ========================================
// Send to Pabbly Webhook
// ========================================

async function sendToPabbly(payload) {
    if (!CONFIG.pabblyWebhookUrl) {
        console.warn('Warning: PABBLY_WEBHOOK_URL not configured');
        return { success: false, error: 'Webhook not configured' };
    }
    
    try {
        const response = await fetch(CONFIG.pabblyWebhookUrl, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify(payload),
            timeout: 10000 // 10 seconds
        });
        
        if (!response.ok) {
            throw new Error(`Pabbly webhook returned status ${response.status}`);
        }
        
        const responseData = await response.text();
        console.log('Pabbly webhook response:', responseData);
        
        return {
            success: true,
            statusCode: response.status,
            response: responseData
        };
        
    } catch (error) {
        console.error('Pabbly webhook error:', error);
        return {
            success: false,
            error: 'Failed to send to webhook',
            details: error.message
        };
    }
}

// ========================================
// Input Validation
// ========================================

function validateSubmission(data) {
    const errors = [];
    
    // Check required fields
    if (!data.user || typeof data.user !== 'object') {
        errors.push('Missing user data');
    } else {
        if (!data.user.first_name || data.user.first_name.trim().length < 2) {
            errors.push('Invalid first name');
        }
        if (!data.user.last_name || data.user.last_name.trim().length < 2) {
            errors.push('Invalid last name');
        }
        if (!data.user.email || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(data.user.email)) {
            errors.push('Invalid email');
        }
    }
    
    // Check answers
    if (!Array.isArray(data.answers) || data.answers.length === 0) {
        errors.push('Missing answers');
    } else {
        data.answers.forEach((answer, index) => {
            if (!answer.id || !answer.question || typeof answer.answer !== 'boolean') {
                errors.push(`Invalid answer at index ${index}`);
            }
        });
    }
    
    // Check captcha
    if (!data.captcha || !data.captcha.token) {
        errors.push('Missing captcha token');
    }
    
    // Check session ID
    if (!data.session_id) {
        errors.push('Missing session ID');
    }
    
    return {
        valid: errors.length === 0,
        errors: errors
    };
}

// ========================================
// API Routes
// ========================================

// Health check endpoint
app.get('/api/health', (req, res) => {
    res.json({
        status: 'ok',
        timestamp: new Date().toISOString(),
        configured: {
            recaptcha: !!CONFIG.recaptchaSecretKey,
            pabbly: !!CONFIG.pabblyWebhookUrl
        }
    });
});

// Main submission endpoint
app.post('/api/submit', rateLimit, async (req, res) => {
    try {
        console.log('Received submission from:', req.ip);
        
        // Validate input
        const validation = validateSubmission(req.body);
        if (!validation.valid) {
            console.error('Validation errors:', validation.errors);
            return res.status(400).json({
                success: false,
                error: 'Invalid submission data',
                details: validation.errors
            });
        }
        
        // Verify reCAPTCHA
        const recaptchaResult = await verifyRecaptcha(
            req.body.captcha.token,
            req.ip
        );
        
        if (!recaptchaResult.success) {
            return res.status(400).json({
                success: false,
                error: recaptchaResult.error,
                details: recaptchaResult.details
            });
        }
        
        // Prepare payload for Pabbly
        const pabblyPayload = {
            ...req.body,
            server_timestamp: new Date().toISOString(),
            recaptcha_score: recaptchaResult.score,
            client_ip: req.ip,
            // Add any additional server-side data
            server_meta: {
                user_agent: req.get('user-agent'),
                referer: req.get('referer') || 'direct',
                accept_language: req.get('accept-language')
            }
        };
        
        // Send to Pabbly
        const pabblyResult = await sendToPabbly(pabblyPayload);
        
        if (!pabblyResult.success) {
            console.error('Failed to send to Pabbly:', pabblyResult);
            return res.status(500).json({
                success: false,
                error: 'Failed to process submission',
                details: pabblyResult.details
            });
        }
        
        console.log('Submission processed successfully for:', req.body.user.email);
        
        // Success response
        return res.json({
            success: true,
            message: 'Submission received',
            session_id: req.body.session_id
        });
        
    } catch (error) {
        console.error('Submission error:', error);
        return res.status(500).json({
            success: false,
            error: 'Internal server error',
            details: error.message
        });
    }
});

// ========================================
// Serve the main app
// ========================================

app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'index.html'));
});

// Catch-all route for SPA
app.get('*', (req, res) => {
    res.sendFile(path.join(__dirname, 'index.html'));
});

// ========================================
// Error Handler
// ========================================

app.use((err, req, res, next) => {
    console.error('Unhandled error:', err);
    res.status(500).json({
        success: false,
        error: 'Internal server error'
    });
});

// ========================================
// Start Server
// ========================================

app.listen(PORT, () => {
    console.log(`
╔════════════════════════════════════════╗
║        SURWIPE SERVER RUNNING          ║
╚════════════════════════════════════════╝

Port: ${PORT}
Environment: ${process.env.NODE_ENV || 'development'}

Configuration:
- reCAPTCHA: ${CONFIG.recaptchaSecretKey ? '✓ Configured' : '✗ Missing'}
- Pabbly Webhook: ${CONFIG.pabblyWebhookUrl ? '✓ Configured' : '✗ Missing'}
- Min reCAPTCHA Score: ${CONFIG.recaptchaMinScore}
- Rate Limit: ${CONFIG.rateLimitMaxRequests} requests per ${CONFIG.rateLimitWindow / 1000}s

Endpoints:
- GET  /              → Main app
- GET  /api/health   → Health check
- POST /api/submit   → Submit survey

${!CONFIG.recaptchaSecretKey || !CONFIG.pabblyWebhookUrl ? '\n⚠️  Warning: Set RECAPTCHA_SECRET_KEY and PABBLY_WEBHOOK_URL environment variables!\n' : ''}
    `);
});

// Graceful shutdown
process.on('SIGTERM', () => {
    console.log('SIGTERM received, shutting down gracefully...');
    process.exit(0);
});

process.on('SIGINT', () => {
    console.log('SIGINT received, shutting down gracefully...');
    process.exit(0);
});

module.exports = app;
