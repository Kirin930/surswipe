// ========================================
// SURWIPE - Cloudflare Worker
// ========================================



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
    } else {
        data.answers.forEach((answer, index) => {
            if (!answer.id || !answer.question || typeof answer.answer !== 'boolean') {
                errors.push(`Invalid answer at index ${index}`);
            }
        });
    }
    if (!data.captcha || !data.captcha.token) {
        errors.push('Missing captcha token');
    }
    if (!data.session_id || typeof data.session_id !== 'string') {
        errors.push('Missing session ID');
    }
    return { valid: errors.length === 0, errors };
}

async function verifyRecaptcha(token, secretKey) {
    if (!secretKey) {
        return {
            success: false,
            error: 'Missing RECAPTCHA_SECRET_KEY'
        };
    }

    try {
        const body = new URLSearchParams({
            secret: secretKey,
            response: token
        });

        const response = await fetch('https://www.google.com/recaptcha/api/siteverify', {
            method: 'POST',
            headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
            body: body.toString()
        });
        const data = await response.json();
        if (!data.success) {
            return {
                success: false,
                error: 'reCAPTCHA verification failed',
                details: data['error-codes'] || []
            };
        }
        if (data.score !== undefined && data.score < 0.5) {
            return {
                success: false,
                error: 'Suspicious activity detected',
                score: data.score
            };
        }
        return { success: true, score: data.score };
    } catch (error) {
        return {
            success: false,
            error: 'reCAPTCHA verification failed',
            details: [error.message]
        };
    }
}

function createAnswerMap(answers) {
    return answers.reduce((map, answer) => {
        map[answer.id] = answer.answer;
        return map;
    }, {});
}

function buildSubmissionKey(receivedAt, sessionId) {
    const date = new Date(receivedAt);
    const year = String(date.getUTCFullYear());
    const month = String(date.getUTCMonth() + 1).padStart(2, '0');
    const day = String(date.getUTCDate()).padStart(2, '0');
    const safeTimestamp = receivedAt.replace(/[:.]/g, '-');
    const safeSessionId = String(sessionId)
        .replace(/[^a-zA-Z0-9_-]/g, '')
        .slice(0, 80);

    return `submissions/${year}/${month}/${day}/${safeTimestamp}_${safeSessionId}.json`;
}

function buildStoredSubmission(data, recaptchaResult, receivedAt) {
    const answers = data.answers.map((answer) => ({
        id: answer.id,
        question: answer.question,
        answer: answer.answer
    }));

    return {
        schema_version: 1,
        submitted_at: data.timestamp_iso || receivedAt,
        received_at: receivedAt,
        session_id: data.session_id,
        user: {
            first_name: data.user.first_name,
            last_name: data.user.last_name,
            email: data.user.email
        },
        answers,
        answer_map: createAnswerMap(answers),
        meta: data.meta || {},
        verification: {
            captcha_provider: data.captcha.provider || 'recaptcha',
            recaptcha_score: recaptchaResult.score ?? null,
            verified_at: receivedAt
        }
    };
}

async function saveSubmission(env, key, submission) {
    if (!env.SUBMISSIONS_BUCKET) {
        throw new Error('Missing SUBMISSIONS_BUCKET binding');
    }

    await env.SUBMISSIONS_BUCKET.put(key, JSON.stringify(submission, null, 2), {
        httpMetadata: {
            contentType: 'application/json; charset=utf-8'
        },
        customMetadata: {
            schema_version: String(submission.schema_version),
            session_id: submission.session_id,
            submitted_at: submission.submitted_at
        }
    });
}

async function handleAPIHealth(env) {
    const result = {
        status: 'ok',
        timestamp: new Date().toISOString(),
        configured: {
            assets: !!env.ASSETS,
            submissions_bucket: !!env.SUBMISSIONS_BUCKET,
            recaptcha_secret: !!env.RECAPTCHA_SECRET_KEY
        },
        storage: {
            readable: false
        }
    };

    if (!env.SUBMISSIONS_BUCKET) {
        result.status = 'error';
        result.storage.error = 'Missing SUBMISSIONS_BUCKET binding';
    } else {
        try {
            await env.SUBMISSIONS_BUCKET.list({ limit: 1 });
            result.storage.readable = true;
        } catch (error) {
            result.status = 'error';
            result.storage.error = 'Unable to access submissions bucket';
        }
    }

    return new Response(JSON.stringify(result), {
        status: result.status === 'ok' ? 200 : 500,
        headers: {
            'Content-Type': 'application/json',
            'Access-Control-Allow-Origin': '*',
            'Cache-Control': 'no-store'
        }
    });
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
                error: recaptchaResult.error,
                details: recaptchaResult.details || []
            }), {
                status: 400,
                headers: { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' }
            });
        }
        
        const receivedAt = new Date().toISOString();
        const storageKey = buildSubmissionKey(receivedAt, data.session_id);
        const storedSubmission = buildStoredSubmission(data, recaptchaResult, receivedAt);

        await saveSubmission(env, storageKey, storedSubmission);
        
        return new Response(JSON.stringify({
            success: true,
            message: 'Submission saved',
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
    async fetch(request, env) {
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
        if (url.pathname === '/api/health' && request.method === 'GET') {
            return handleAPIHealth(env);
        }

        if (url.pathname === '/api/submit' && request.method === 'POST') {
            return handleAPISubmit(request, env);
        }

        // Serve static files via Workers Assets binding (Wrangler 3+)
        return env.ASSETS.fetch(request);
    }
};
