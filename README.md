# Surwipe - Mobile Swipe Survey Application

A mobile-only swipe survey application built for collecting job interest data with an intuitive Tinder-like interface.

## Features

✅ **Mobile-Only Interface** - Desktop users see a friendly prompt to open on mobile
✅ **Swipe Gestures** - Natural swipe right (YES) / swipe left (NO) interactions
✅ **User Data Collection** - Collects name, surname, and email with validation
✅ **Multi-Question Survey** - Configurable questions with swipe responses
✅ **reCAPTCHA Protection** - Spam prevention before submission
✅ **Beautiful UI** - Modern gradient-driven design with smooth animations

## Quick Start

### 1. Configuration

#### Update Webhook Endpoint
Edit `questions.js` and replace the webhook URL:

```javascript
const WEBHOOK_CONFIG = {
    url: 'https://your-actual-webhook-endpoint.com/api/submit',
    timeout: 10000,
    maxRetries: 2
};
```

#### Configure reCAPTCHA
1. Get your reCAPTCHA keys from: https://www.google.com/recaptcha/admin
2. Update `questions.js`:

```javascript
const RECAPTCHA_CONFIG = {
    siteKey: 'YOUR_RECAPTCHA_SITE_KEY_HERE'
};
```

3. Update the reCAPTCHA script URL in `index.html` if using v2 invisible or v3.

#### Customize Questions
Edit the `QUESTIONS` array in `questions.js`:

```javascript
const QUESTIONS = [
    { id: "q1", question: "Your first question?" },
    { id: "q2", question: "Your second question?" },
    // Add more questions...
];
```

### 2. Deployment Options

#### Option A: Netlify (Recommended)

1. Install Netlify CLI:
```bash
npm install -g netlify-cli
```

2. Deploy:
```bash
netlify deploy --prod
```

Or use drag-and-drop deployment at https://app.netlify.com/drop

#### Option B: Vercel

1. Install Vercel CLI:
```bash
npm install -g vercel
```

2. Deploy:
```bash
vercel --prod
```

#### Option C: GitHub Pages

1. Create a new repository on GitHub
2. Push these files to the repository
3. Go to Settings → Pages
4. Select your branch and root folder
5. Your site will be published at `https://username.github.io/repo-name`

#### Option D: AWS S3 + CloudFront

1. Create an S3 bucket
2. Enable static website hosting
3. Upload all files
4. Create a CloudFront distribution (optional, for HTTPS)

## Webhook Payload Structure

Your webhook endpoint will receive the following JSON payload:

```json
{
  "version": "1.0",
  "timestamp_iso": "2026-02-12T12:34:56.000Z",
  "session_id": "uuid-v4-here",
  "user": {
    "first_name": "Mario",
    "last_name": "Rossi",
    "email": "mario.rossi@email.com"
  },
  "answers": [
    {
      "id": "q1",
      "question": "Sei interessato a lavorare in Tevel?",
      "answer": true
    },
    {
      "id": "q2",
      "question": "Sei disponibile a trasferirti?",
      "answer": false
    }
  ],
  "meta": {
    "user_agent": "Mozilla/5.0...",
    "language": "it-IT",
    "timezone": "Europe/Rome",
    "screen": { "w": 390, "h": 844 },
    "is_touch": true
  },
  "captcha": {
    "provider": "recaptcha",
    "token": "captcha-token-here"
  }
}
```

## Webhook Implementation Examples

### Example 1: Save to Google Sheets (via Zapier/Make)

1. Create a webhook trigger in Zapier or Make.com
2. Add a Google Sheets action to append a row
3. Map the JSON fields to columns
4. Use the webhook URL in `questions.js`

### Example 2: Node.js Express Server

```javascript
const express = require('express');
const app = express();

app.use(express.json());

app.post('/api/submit', async (req, res) => {
    const data = req.body;
    
    // Verify reCAPTCHA token
    const captchaValid = await verifyCaptcha(data.captcha.token);
    if (!captchaValid) {
        return res.status(400).json({ error: 'Invalid captcha' });
    }
    
    // Save to database
    await saveToDatabase(data);
    
    res.json({ success: true });
});

async function verifyCaptcha(token) {
    const response = await fetch('https://www.google.com/recaptcha/api/siteverify', {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: `secret=6LdJOWksAAAAALNXHCOUnznQRvskUdbekr92tycQ&response=${token}`
    });
    const result = await response.json();
    return result.success;
}
```

### Example 3: Save to Excel via Microsoft Power Automate

1. Create a new Flow in Power Automate
2. Add "When a HTTP request is received" trigger
3. Add "Add a row into a table" action (Excel Online)
4. Map the JSON fields from the trigger
5. Use the HTTP POST URL in `questions.js`

## Excel/Spreadsheet Column Mapping

Recommended columns for your spreadsheet:

| Column | Data Source | Type |
|--------|-------------|------|
| timestamp | timestamp_iso | DateTime |
| session_id | session_id | Text |
| nome | user.first_name | Text |
| cognome | user.last_name | Text |
| email | user.email | Email |
| q1 | answers[0].answer | Boolean/Text |
| q2 | answers[1].answer | Boolean/Text |
| q3 | answers[2].answer | Boolean/Text |
| user_agent | meta.user_agent | Text |
| language | meta.language | Text |

## Testing Checklist

See `TESTING.md` for the complete manual testing suite.

Quick tests:
- [ ] Desktop shows "Open on smartphone" message
- [ ] Mobile shows swipe interface
- [ ] Swipe right on Q1 opens form
- [ ] Form validation works (try invalid data)
- [ ] Can't proceed without valid form
- [ ] All questions appear in sequence
- [ ] reCAPTCHA appears and works
- [ ] Submit sends data to webhook
- [ ] Error handling works (disconnect network)
- [ ] Retry button functions

## Browser Compatibility

- iOS Safari 14+
- Android Chrome 90+
- Modern mobile browsers with touch support

## File Structure

```
surwipe/
├── index.html          # Main HTML structure
├── styles.css          # All styles and animations
├── app.js              # Main application logic
├── questions.js        # Configuration file
├── README.md           # This file
└── TESTING.md          # Test checklist
```

## Customization

### Colors
Edit CSS variables in `styles.css`:

```css
:root {
    --primary-gradient: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
    --yes-color: #4facfe;
    --no-color: #f5576c;
}
```

### Fonts
The app uses Google Fonts (Outfit + DM Sans). Change in `styles.css`:

```css
@import url('https://fonts.googleapis.com/css2?family=YourFont:wght@400;700&display=swap');
```

### Swipe Threshold
Adjust in `app.js`:

```javascript
const SWIPE_THRESHOLD = 80; // pixels
```

## Privacy & GDPR Compliance

The application:
- ✅ Does NOT store PII in localStorage
- ✅ Generates unique session IDs
- ✅ Includes reCAPTCHA for spam protection
- ⚠️ You should add a privacy policy link
- ⚠️ Consider adding a consent checkbox

To add privacy notice, edit `index.html` in the form section:

```html
<div class="privacy-notice">
    Inviando il form, accetti la nostra 
    <a href="/privacy">Privacy Policy</a>
</div>
```

## Troubleshooting

### reCAPTCHA not showing
- Check that the site key is correct
- Verify the domain is registered in reCAPTCHA console
- Check browser console for errors

### Webhook failing
- Verify the URL is correct and accessible
- Check CORS settings on your server
- Test with a service like webhook.site first
- Check network tab in browser dev tools

### Swipe not working
- Ensure device has touch support
- Check browser console for JavaScript errors
- Try on a different mobile browser

### Form not validating
- Check browser console for errors
- Verify all input IDs match the JavaScript

## Support & Updates

This is a standalone vanilla JavaScript application with no dependencies. To update:
1. Edit the relevant files
2. Re-deploy to your hosting platform

## License

This application was created according to the PRD specifications. Customize freely for your needs.

## Credits

Built with vanilla JavaScript, modern CSS, and attention to detail.
