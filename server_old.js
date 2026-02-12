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

// server.mjs
import { createServer } from 'node:http';

const server = createServer((req, res) => {
  res.writeHead(200, { 'Content-Type': 'text/plain' });
  res.end('Hello World!\n');
});

// starts a simple http server locally on port 3000
server.listen(3000, '127.0.0.1', () => {
  console.log('Listening on 127.0.0.1:3000');
});

// run with `node server.mjs`
