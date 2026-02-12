// ========================================
// SURWIPE - Cloudflare Pages Function
// API Endpoint: /api/submit
// ========================================

// Rate limiting using Cloudflare KV (optional, requires KV namespace)
const RATE_LIMIT_WINDOW = 60000; // 1 minute
const RATE_LIMIT_MAX = 5; // 5 requests per minute
const DEFAULT_MIN_SCORE = 0.5;
const EXPECTED_RECAPTCHA_ACTION = 'submit';

// Simple in-memory rate limiting (resets on cold start)
const rateLimitStore = new Map();

function rateLimit(ip) {
    const now = Date.now();
    
    // Clean old entries
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
    
    if (record.count >= RATE_LIMIT_MAX) {
        return false;
    }
    
    record.count++;
    return true;
}

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
    }
    
    // Check captcha
    if (!data.captcha || !data.captcha.token) {
        errors.push('Missing captcha token');
    }
    
    return {
        valid: errors.length === 0,
        errors: errors
    };
}

async function verifyRecaptcha({ token, secretKey, remoteIp, minScore, expectedAction }) {
    if (!secretKey) {
        return {
            success: false,
            error: 'Server reCAPTCHA key is not configured'
        };
    }

    try {
        const body = new URLSearchParams({
            secret: secretKey,
            response: token
        });
        if (remoteIp && remoteIp !== 'unknown') {
            body.set('remoteip', remoteIp);
        }

        const response = await fetch('https://www.google.com/recaptcha/api/siteverify', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded',
            },
            body: body.toString()
        });
        
        const data = await response.json();
        
        if (!data.success) {
            console.error('reCAPTCHA verification failed:', data['error-codes']);
            return {
                success: false,
                error: 'reCAPTCHA verification failed'
            };
        }
        
        // Check score for v3 (0.0 to 1.0)
        if (data.score !== undefined && data.score < minScore) {
            console.warn(`Low reCAPTCHA score: ${data.score}`);
            return {
                success: false,
                error: 'Suspicious activity detected',
                score: data.score
            };
        }

        if (expectedAction && data.action !== expectedAction) {
            console.warn(`Unexpected reCAPTCHA action: ${data.action}`);
            return {
                success: false,
                error: 'Invalid reCAPTCHA action'
            };
        }
        
        console.log(`reCAPTCHA verified. Score: ${data.score || 'N/A'}`);
        return {
            success: true,
            score: data.score,
            action: data.action
        };
        
    } catch (error) {
        console.error('reCAPTCHA verification error:', error);
        return {
            success: false,
            error: 'reCAPTCHA verification failed'
        };
    }
}

async function sendToPabbly(url, payload) {
    try {
        const response = await fetch(url, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify(payload)
        });
        
        if (!response.ok) {
            throw new Error(`Pabbly returned status ${response.status}`);
        }
        
        return { success: true };
        
    } catch (error) {
        console.error('Pabbly webhook error:', error);
        return {
            success: false,
            error: 'Failed to send to webhook'
        };
    }
}

// Main handler for POST requests
export async function onRequestPost(context) {
    const { request, env } = context;
    const minScore = Number.parseFloat(env.RECAPTCHA_MIN_SCORE || `${DEFAULT_MIN_SCORE}`);
    
    // Get client IP
    const ip = request.headers.get('CF-Connecting-IP') || 
               request.headers.get('X-Forwarded-For') || 
               'unknown';
    
    console.log(`[${new Date().toISOString()}] Submission from: ${ip}`);
    
    // Rate limiting
    if (!rateLimit(ip)) {
        console.warn(`Rate limit exceeded for IP: ${ip}`);
        return new Response(JSON.stringify({
            success: false,
            error: 'Too many requests. Please try again later.'
        }), {
            status: 429,
            headers: {
                'Content-Type': 'application/json',
                'Access-Control-Allow-Origin': '*'
            }
        });
    }
    
    try {
        // Parse request body
        const data = await request.json();
        
        // Validate input
        const validation = validateSubmission(data);
        if (!validation.valid) {
            console.error('Validation errors:', validation.errors);
            return new Response(JSON.stringify({
                success: false,
                error: 'Invalid submission data',
                details: validation.errors
            }), {
                status: 400,
                headers: {
                    'Content-Type': 'application/json',
                    'Access-Control-Allow-Origin': '*'
                }
            });
        }
        
        // Verify reCAPTCHA
        const recaptchaResult = await verifyRecaptcha({
            token: data.captcha.token,
            secretKey: env.RECAPTCHA_SECRET_KEY,
            remoteIp: ip,
            minScore: Number.isFinite(minScore) ? minScore : DEFAULT_MIN_SCORE,
            expectedAction: EXPECTED_RECAPTCHA_ACTION
        });
        
        if (!recaptchaResult.success) {
            return new Response(JSON.stringify({
                success: false,
                error: recaptchaResult.error
            }), {
                status: 400,
                headers: {
                    'Content-Type': 'application/json',
                    'Access-Control-Allow-Origin': '*'
                }
            });
        }
        
        // Prepare enhanced payload
        const payload = {
            ...data,
            server_timestamp: new Date().toISOString(),
            recaptcha_score: recaptchaResult.score,
            client_ip: ip,
            server_meta: {
                user_agent: request.headers.get('user-agent'),
                referer: request.headers.get('referer') || 'direct',
                accept_language: request.headers.get('accept-language'),
                cloudflare_ray: request.headers.get('cf-ray')
            }
        };
        
        // Send to Pabbly
        if (!env.PABBLY_WEBHOOK_URL) {
            return new Response(JSON.stringify({
                success: false,
                error: 'Server webhook URL is not configured'
            }), {
                status: 500,
                headers: {
                    'Content-Type': 'application/json',
                    'Access-Control-Allow-Origin': '*'
                }
            });
        }

        const pabblyResult = await sendToPabbly(env.PABBLY_WEBHOOK_URL, payload);
        
        if (!pabblyResult.success) {
            console.error('Failed to send to Pabbly');
            return new Response(JSON.stringify({
                success: false,
                error: 'Failed to process submission'
            }), {
                status: 500,
                headers: {
                    'Content-Type': 'application/json',
                    'Access-Control-Allow-Origin': '*'
                }
            });
        }
        
        console.log(`Submission processed successfully: ${data.user.email}`);
        
        // Success response
        return new Response(JSON.stringify({
            success: true,
            message: 'Submission received',
            session_id: data.session_id
        }), {
            status: 200,
            headers: {
                'Content-Type': 'application/json',
                'Access-Control-Allow-Origin': '*'
            }
        });
        
    } catch (error) {
        console.error('Submission error:', error);
        return new Response(JSON.stringify({
            success: false,
            error: 'Internal server error'
        }), {
            status: 500,
            headers: {
                'Content-Type': 'application/json',
                'Access-Control-Allow-Origin': '*'
            }
        });
    }
}

// Handle OPTIONS requests for CORS preflight
export async function onRequestOptions(context) {
    return new Response(null, {
        status: 204,
        headers: {
            'Access-Control-Allow-Origin': '*',
            'Access-Control-Allow-Methods': 'POST, OPTIONS',
            'Access-Control-Allow-Headers': 'Content-Type',
            'Access-Control-Max-Age': '86400'
        }
    });
}
