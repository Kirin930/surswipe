// ========================================
// SURWIPE - Questions Configuration
// ========================================

const QUESTIONS = [
    {
        id: "q1",
        question: "Are you interested in Tevel?"
    },
    {
        id: "q2",
        question: "Are you interested in an internship?"
    },
    {
        id: "q3",
        question: "Are you interested in developing your thesis in company?"
    },
    {
        id: "q4",
        question: "Are you interested in working at Tevel?"
    },
    {
        id: "q5",
        question: "Would you like to be contacted by us?"
    }
];

// API submission configuration
const API_CONFIG = {
    // The Worker verifies reCAPTCHA server-side and saves each submission to R2.
    url: '/api/submit',
    timeout: 10000, // 10 seconds
    maxRetries: 2
};

// reCAPTCHA configuration
const RECAPTCHA_CONFIG = {
    // Replace with your actual reCAPTCHA site key
    siteKey: '6LezIRotAAAAAOBWZDu52tf28-I4M0F6QbCXKjxg'// This is Google's test key
};
