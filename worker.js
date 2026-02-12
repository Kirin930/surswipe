// ========================================
// SURWIPE - Cloudflare Worker
// ========================================

import { getAssetFromKV } from '@cloudflare/kv-asset-handler';

// Rate limiting
const rateLimitStore = new Map();
const RATE_LIMIT_WINDOW = 60000;
const RATE_LIMIT_MAX = 5;

function rateLimit(ip) {
    const now = Date.now();
    for (const [key, value] of rateLimitStore.entries()) {
        if (now - value.resetTime > RATE_LIMIT_WINDOW) {
            rateLimitStore.delete(key);
        }
    }
    if (!rateLimitStore.has(ip)) {
        rateLimitStore.set(ip, { count: 1, resetTime: now });
        return true;
    }
    const record = rateLimitStore.get(ip);
    if (now - record.resetTime > RATE_LIMIT_WINDOW) {
        record.count = 1;
        record.resetTime = now;
        return true;
    }
    if (record.count >= RATE_LIMIT_MAX) return false;
    record.count++;
    return true;
}

function validateSubmission(data) {
    const errors = [];
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
    if (!Array.isArray(data.answers) || data.answers.length === 0) {
        errors.push('Missing answers');
    }
    if (!data.captcha || !data.captcha.token) {
        errors.push('Missing captcha token');
    }
    return { valid: errors.length === 0, errors };
}

async function verifyRecaptcha(token, secretKey) {
    try {
        const response = await fetch('https://www.google.com/recaptcha/api/siteverify', {
            method: 'POST',
            headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
            body: `secret=${secretKey}&response=${token}`
        });
        const data = await response.json();
        if (!data.success) {
            return { success: false, error: 'reCAPTCHA verification failed' };
        }
        if (data.score !== undefined && data.score < 0.5) {
            return { success: false, error: 'Suspicious activity detected', score: data.score };
        }
        return { success: true, score: data.score };
    } catch (error) {
        return { success: false, error: 'reCAPTCHA verification failed' };
    }
}

async function sendToPabbly(url, payload) {
    try {
        const response = await fetch(url, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(payload)
        });
        if (!response.ok) throw new Error(`Pabbly returned status ${response.status}`);
        return { success: true };
    } catch (error) {
        return { success: false, error: 'Failed to send to webhook' };
    }
}

async function handleAPISubmit(request, env) {
    const ip = request.headers.get('CF-Connecting-IP') || 'unknown';
    
    if (!rateLimit(ip)) {
        return new Response(JSON.stringify({
            success: false,
            error: 'Too many requests'
        }), {
            status: 429,
            headers: { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' }
        });
    }
    
    try {
        const data = await request.json();
        const validation = validateSubmission(data);
        
        if (!validation.valid) {
            return new Response(JSON.stringify({
                success: false,
                error: 'Invalid submission data',
                details: validation.errors
            }), {
                status: 400,
                headers: { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' }
            });
        }
        
        const recaptchaResult = await verifyRecaptcha(data.captcha.token, env.RECAPTCHA_SECRET_KEY);
        
        if (!recaptchaResult.success) {
            return new Response(JSON.stringify({
                success: false,
                error: recaptchaResult.error
            }), {
                status: 400,
                headers: { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' }
            });
        }
        
        const payload = {
            ...data,
            server_timestamp: new Date().toISOString(),
            recaptcha_score: recaptchaResult.score,
            client_ip: ip
        };
        
        const pabblyResult = await sendToPabbly(env.PABBLY_WEBHOOK_URL, payload);
        
        if (!pabblyResult.success) {
            return new Response(JSON.stringify({
                success: false,
                error: 'Failed to process submission'
            }), {
                status: 500,
                headers: { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' }
            });
        }
        
        return new Response(JSON.stringify({
            success: true,
            message: 'Submission received',
            session_id: data.session_id
        }), {
            status: 200,
            headers: { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' }
        });
        
    } catch (error) {
        console.error('Error:', error);
        return new Response(JSON.stringify({
            success: false,
            error: 'Internal server error'
        }), {
            status: 500,
            headers: { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' }
        });
    }
}

export default {
    async fetch(request, env, ctx) {
        const url = new URL(request.url);
        
        // CORS preflight
        if (request.method === 'OPTIONS') {
            return new Response(null, {
                status: 204,
                headers: {
                    'Access-Control-Allow-Origin': '*',
                    'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
                    'Access-Control-Allow-Headers': 'Content-Type',
                    'Access-Control-Max-Age': '86400'
                }
            });
        }
        
        // API endpoint
        if (url.pathname === '/api/submit' && request.method === 'POST') {
            return handleAPISubmit(request, env);
        }
        
        // Serve static files
        try {
            return await getAssetFromKV(
                {
                    request,
                    waitUntil: ctx.waitUntil.bind(ctx),
                },
                {
                    ASSET_NAMESPACE: env.__STATIC_CONTENT,
                    ASSET_MANIFEST: __STATIC_CONTENT_MANIFEST,
                }
            );
        } catch (e) {
            // 404 fallback
            return new Response('Not found', { status: 404 });
        }
    }
};
