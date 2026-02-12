# Surwipe - Cloudflare Deployment Guide

Complete guide to deploy Surwipe on Cloudflare Pages with Node.js server, reCAPTCHA v3, and Pabbly integration.

## Prerequisites

- Cloudflare account (free tier works)
- GitHub account
- Google reCAPTCHA v3 keys
- Pabbly Connect account with webhook URL

---

## Step 1: Get reCAPTCHA v3 Keys

1. Go to https://www.google.com/recaptcha/admin
2. Click "+" to create a new site
3. Configure:
   - **Label**: Surwipe
   - **reCAPTCHA type**: Score based (v3)
   - **Domains**: Add your domain (e.g., `surwipe.pages.dev` or your custom domain)
4. Click **Submit**
5. Save both keys:
   - **Site Key** (client-side, public)
   - **Secret Key** (server-side, private)

---

## Step 2: Set Up Pabbly Webhook

1. Log in to Pabbly Connect
2. Create a new workflow
3. Add trigger: **Webhook**
4. Configure the webhook trigger
5. Copy the webhook URL (looks like: `https://connect.pabbly.com/workflow/sendwebhookdata/xxxxx`)
6. Add actions for what you want to do with the data:
   - **Google Sheets**: Add row to spreadsheet
   - **Email**: Send notification
   - **CRM**: Add contact
   - etc.

### Recommended Pabbly Workflow

```
Trigger: Webhook
  ↓
Action 1: Google Sheets - Add Row
  ↓
Action 2: Email - Send Notification (optional)
  ↓
Action 3: Slack - Send Message (optional)
```

### Google Sheets Column Mapping

Map these webhook fields to your spreadsheet columns:

| Sheet Column | Webhook Field |
|-------------|---------------|
| Timestamp | timestamp_iso |
| Session ID | session_id |
| Nome | user.first_name |
| Cognome | user.last_name |
| Email | user.email |
| Q1 | answers.0.answer |
| Q2 | answers.1.answer |
| Q3 | answers.2.answer |
| Q4 | answers.3.answer |
| Q5 | answers.4.answer |
| User Agent | meta.user_agent |
| reCAPTCHA Score | recaptcha_score |

---

## Step 3: Configure Application

### Update `questions.js`

Find this section:
```javascript
const WEBHOOK_CONFIG = {
    url: '/api/submit',
    timeout: 10000,
    maxRetries: 2
};

const RECAPTCHA_CONFIG = {
    siteKey: 'YOUR_RECAPTCHA_V3_SITE_KEY_HERE'
};
```

Replace with your **reCAPTCHA v3 Site Key**:
```javascript
const RECAPTCHA_CONFIG = {
    siteKey: '6LcXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX'
};
```

---

## Step 4: Deploy to Cloudflare Pages

### Option A: Deploy via GitHub (Recommended)

1. **Create a GitHub Repository**
   ```bash
   cd your-surwipe-folder
   git init
   git add .
   git commit -m "Initial commit"
   git branch -M main
   git remote add origin https://github.com/yourusername/surwipe.git
   git push -u origin main
   ```

2. **Connect to Cloudflare Pages**
   - Go to https://dash.cloudflare.com
   - Navigate to **Pages**
   - Click **Create a project**
   - Click **Connect to Git**
   - Select your GitHub repository
   - Configure build settings:
     - **Framework preset**: None
     - **Build command**: `npm install`
     - **Build output directory**: `/`
     - **Root directory**: `/`

3. **Configure Environment Variables**
   - In Cloudflare Pages project settings
   - Go to **Settings** → **Environment Variables**
   - Add the following variables:

   | Variable Name | Value |
   |--------------|-------|
   | `RECAPTCHA_SECRET_KEY` | Your reCAPTCHA v3 Secret Key |
   | `PABBLY_WEBHOOK_URL` | Your Pabbly webhook URL |
   | `RECAPTCHA_MIN_SCORE` | `0.5` (or your preferred threshold) |
   | `NODE_ENV` | `production` |

4. **Deploy**
   - Click **Save and Deploy**
   - Wait for build to complete
   - Your site will be available at `https://your-project.pages.dev`

### Option B: Deploy via Wrangler CLI

1. **Install Wrangler**
   ```bash
   npm install -g wrangler
   ```

2. **Login to Cloudflare**
   ```bash
   wrangler login
   ```

3. **Create Pages Project**
   ```bash
   wrangler pages project create surwipe
   ```

4. **Deploy**
   ```bash
   wrangler pages publish . --project-name=surwipe
   ```

5. **Set Environment Variables**
   ```bash
   wrangler pages secret put RECAPTCHA_SECRET_KEY
   wrangler pages secret put PABBLY_WEBHOOK_URL
   ```

---

## Step 5: Configure Functions (Cloudflare Pages Functions)

Cloudflare Pages can run server-side code using Functions. We need to adapt our Express server.

Create a `functions` folder in your project:

```
surwipe/
├── functions/
│   └── api/
│       └── submit.js
├── index.html
├── styles.css
├── app.js
├── questions.js
└── package.json
```

Create `functions/api/submit.js`:

```javascript
// Cloudflare Pages Function for /api/submit endpoint

export async function onRequestPost(context) {
    const { request, env } = context;
    
    try {
        const data = await request.json();
        
        // Validate input
        if (!data.user || !data.answers || !data.captcha) {
            return new Response(JSON.stringify({
                success: false,
                error: 'Invalid submission data'
            }), {
                status: 400,
                headers: { 'Content-Type': 'application/json' }
            });
        }
        
        // Verify reCAPTCHA v3
        const captchaResponse = await fetch('https://www.google.com/recaptcha/api/siteverify', {
            method: 'POST',
            headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
            body: `secret=${env.RECAPTCHA_SECRET_KEY}&response=${data.captcha.token}`
        });
        
        const captchaResult = await captchaResponse.json();
        
        if (!captchaResult.success || captchaResult.score < 0.5) {
            return new Response(JSON.stringify({
                success: false,
                error: 'reCAPTCHA verification failed'
            }), {
                status: 400,
                headers: { 'Content-Type': 'application/json' }
            });
        }
        
        // Prepare payload for Pabbly
        const payload = {
            ...data,
            server_timestamp: new Date().toISOString(),
            recaptcha_score: captchaResult.score
        };
        
        // Send to Pabbly
        const pabblyResponse = await fetch(env.PABBLY_WEBHOOK_URL, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(payload)
        });
        
        if (!pabblyResponse.ok) {
            throw new Error('Pabbly webhook failed');
        }
        
        return new Response(JSON.stringify({
            success: true,
            message: 'Submission received'
        }), {
            status: 200,
            headers: { 'Content-Type': 'application/json' }
        });
        
    } catch (error) {
        console.error('Submission error:', error);
        return new Response(JSON.stringify({
            success: false,
            error: 'Internal server error'
        }), {
            status: 500,
            headers: { 'Content-Type': 'application/json' }
        });
    }
}
```

**Note**: With Cloudflare Pages Functions, you don't need `server.js`. The Functions automatically handle the `/api/submit` endpoint.

---

## Step 6: Add Custom Domain (Optional)

1. In Cloudflare Pages project
2. Go to **Custom domains**
3. Click **Set up a custom domain**
4. Enter your domain (e.g., `surwipe.yourdomain.com`)
5. Follow DNS instructions
6. Update reCAPTCHA domain whitelist

---

## Step 7: Test Your Deployment

### 1. Test Health Check (if using server.js)
```bash
curl https://your-project.pages.dev/api/health
```

Should return:
```json
{
  "status": "ok",
  "timestamp": "2026-02-12T...",
  "configured": {
    "recaptcha": true,
    "pabbly": true
  }
}
```

### 2. Test Complete Flow
1. Open your site on mobile
2. Complete the survey
3. Submit
4. Check Pabbly workflow execution
5. Verify data in your Google Sheet (or other destination)

---

## Troubleshooting

### reCAPTCHA Issues

**Problem**: reCAPTCHA not loading
- Check that site key is correct in both `index.html` and `questions.js`
- Verify domain is whitelisted in reCAPTCHA console
- Check browser console for errors

**Problem**: Low reCAPTCHA scores
- Adjust `RECAPTCHA_MIN_SCORE` environment variable
- Default is 0.5, try lowering to 0.3 for testing
- High traffic from same IP may lower scores

### Pabbly Webhook Issues

**Problem**: Data not reaching Pabbly
- Test webhook URL directly with curl:
  ```bash
  curl -X POST https://connect.pabbly.com/workflow/sendwebhookdata/xxxxx \
    -H "Content-Type: application/json" \
    -d '{"test": "data"}'
  ```
- Check Pabbly workflow logs
- Verify webhook URL is correct in environment variables

### Cloudflare Deployment Issues

**Problem**: Build fails
- Check `package.json` is present
- Verify Node.js version in build settings (use 16+)
- Check build logs for specific errors

**Problem**: Functions not working
- Ensure `functions` folder structure is correct
- Check environment variables are set
- Review Functions logs in Cloudflare dashboard

---

## Monitoring & Analytics

### Add Analytics (Optional)

Add to `index.html` before `</head>`:

```html
<!-- Cloudflare Web Analytics -->
<script defer src='https://static.cloudflareinsights.com/beacon.min.js' 
        data-cf-beacon='{"token": "YOUR_TOKEN_HERE"}'></script>
```

Get your token from Cloudflare Dashboard → Analytics → Web Analytics

---

## Security Checklist

- [x] reCAPTCHA v3 enabled
- [x] HTTPS enforced (automatic with Cloudflare)
- [x] Environment variables for secrets
- [x] Rate limiting (5 requests per minute)
- [x] Input validation on server
- [x] No PII in localStorage
- [x] CORS configured

---

## Maintenance

### Update Questions
1. Edit `questions.js`
2. Commit and push to GitHub
3. Cloudflare auto-deploys

### Monitor Submissions
- Check Pabbly execution history
- Review Google Sheets for new entries
- Monitor reCAPTCHA scores in logs

### Update reCAPTCHA Keys
1. Generate new keys in reCAPTCHA console
2. Update environment variables in Cloudflare
3. Update `index.html` and `questions.js`
4. Redeploy

---

## Cost Estimate

- **Cloudflare Pages**: Free (up to 500 builds/month)
- **reCAPTCHA v3**: Free (up to 1M assessments/month)
- **Pabbly Connect**: Starts at $19/month (100K tasks)
- **Total**: ~$19/month (or free if under limits)

---

## Support

For issues:
1. Check browser console for errors
2. Review Cloudflare Functions logs
3. Test Pabbly webhook independently
4. Verify environment variables

---

## Next Steps

1. ✅ Configure reCAPTCHA keys
2. ✅ Set up Pabbly webhook
3. ✅ Deploy to Cloudflare Pages
4. ✅ Test complete flow
5. ✅ Add custom domain (optional)
6. ✅ Monitor first submissions

Your Surwipe application is now live! 🎉
