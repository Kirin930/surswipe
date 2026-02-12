// ========================================
// SURWIPE - Main Application
// ========================================

class SurwipeApp {
    constructor() {
        this.state = {
            step: 'INIT',
            currentQuestionIndex: 0,
            user: {
                firstName: '',
                lastName: '',
                email: ''
            },
            answers: [],
            sessionId: this.generateUUID(),
            captchaToken: null,
            captchaTokenAt: null
        };

        this.swipeHandler = null;
        this.retryCount = 0;
        this.recaptchaScriptPromise = null;
        
        this.init();
    }

    init() {
        this.checkDeviceType();
        this.setupEventListeners();
        this.initRecaptcha();
    }

    // ========================================
    // Device Detection
    // ========================================

    checkDeviceType() {
        const isMobile = /Android|webOS|iPhone|iPad|iPod|BlackBerry|IEMobile|Opera Mini/i.test(navigator.userAgent);
        const isTouchDevice = 'ontouchstart' in window || navigator.maxTouchPoints > 0;
        const isSmallViewport = window.innerWidth < 768;

        if (isMobile || (isTouchDevice && isSmallViewport)) {
            this.showMobileApp();
        } else {
            this.showDesktopBlock();
        }
    }

    showDesktopBlock() {
        document.getElementById('desktop-block').classList.remove('hidden');
        document.getElementById('mobile-app').classList.add('hidden');
    }

    showMobileApp() {
        document.getElementById('desktop-block').classList.add('hidden');
        document.getElementById('mobile-app').classList.remove('hidden');
        this.showIntroScreen();
    }

    // ========================================
    // Screen Management
    // ========================================

    hideAllScreens() {
        const screens = [
            'intro-screen',
            'form-screen',
            'question-screen',
            'captcha-screen',
            'submitting-screen',
            'success-screen',
            'error-screen'
        ];
        screens.forEach(id => {
            document.getElementById(id).classList.add('hidden');
        });
    }

    showScreen(screenId) {
        this.hideAllScreens();
        document.getElementById(screenId).classList.remove('hidden');
    }

    updateProgress(percentage) {
        const progressFills = document.querySelectorAll('.progress-fill');
        progressFills.forEach(fill => {
            fill.style.width = `${percentage}%`;
        });
    }

    // ========================================
    // Intro Screen (Q1)
    // ========================================

    showIntroScreen() {
        this.showScreen('intro-screen');
        this.state.step = 'INTRO';
        this.updateProgress(0);
        
        const card = document.getElementById('intro-card');
        this.attachSwipeHandler(card, (direction) => {
            if (direction === 'right') {
                // YES - Show form
                this.state.answers.push({
                    id: QUESTIONS[0].id,
                    question: QUESTIONS[0].question,
                    answer: true
                });
                this.showFormScreen();
            } else {
                // NO - Reset and loop back
                this.resetToIntro();
            }
        });
    }

    resetToIntro() {
        // Reset state
        this.state = {
            step: 'INTRO',
            currentQuestionIndex: 0,
            user: { firstName: '', lastName: '', email: '' },
            answers: [],
            sessionId: this.generateUUID(),
            captchaToken: null,
            captchaTokenAt: null
        };
        
        // Clear form
        const form = document.getElementById('user-form');
        if (form) form.reset();
        
        // Show intro with animation
        setTimeout(() => {
            this.showIntroScreen();
        }, 300);
    }

    // ========================================
    // Form Screen
    // ========================================

    showFormScreen() {
        this.showScreen('form-screen');
        this.state.step = 'FORM';
        this.updateProgress(20);
        
        const card = document.getElementById('form-card');
        this.attachSwipeHandler(card, (direction) => {
            if (direction === 'right') {
                if (this.validateForm()) {
                    this.saveFormData();
                    this.state.currentQuestionIndex = 1; // Start from Q2
                    this.showQuestionScreen();
                } else {
                    this.showFormError();
                }
            }
        });
    }

    validateForm() {
        const firstName = document.getElementById('first-name');
        const lastName = document.getElementById('last-name');
        const email = document.getElementById('email');

        let isValid = true;

        // Validate first name
        if (firstName.value.trim().length < 2) {
            firstName.classList.add('invalid');
            isValid = false;
        } else {
            firstName.classList.remove('invalid');
        }

        // Validate last name
        if (lastName.value.trim().length < 2) {
            lastName.classList.add('invalid');
            isValid = false;
        } else {
            lastName.classList.remove('invalid');
        }

        // Validate email
        const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
        if (!emailRegex.test(email.value.trim())) {
            email.classList.add('invalid');
            isValid = false;
        } else {
            email.classList.remove('invalid');
        }

        return isValid;
    }

    showFormError() {
        const card = document.getElementById('form-card');
        
        // Vibrate if available
        if (navigator.vibrate) {
            navigator.vibrate(200);
        }
        
        // Shake animation
        card.style.animation = 'none';
        setTimeout(() => {
            card.style.animation = 'shake 0.5s';
        }, 10);
        
        // Reset card position
        card.style.transform = '';
    }

    saveFormData() {
        this.state.user = {
            firstName: document.getElementById('first-name').value.trim(),
            lastName: document.getElementById('last-name').value.trim(),
            email: document.getElementById('email').value.trim()
        };
    }

    // ========================================
    // Question Screens (Q2 onwards)
    // ========================================

    showQuestionScreen() {
        if (this.state.currentQuestionIndex >= QUESTIONS.length) {
            this.showCaptchaScreen();
            return;
        }

        this.showScreen('question-screen');
        this.state.step = `QUESTION_${this.state.currentQuestionIndex}`;
        
        const currentQuestion = QUESTIONS[this.state.currentQuestionIndex];
        const progress = 20 + ((this.state.currentQuestionIndex / QUESTIONS.length) * 60);
        this.updateProgress(progress);
        
        // Update question content
        document.getElementById('current-q-num').textContent = this.state.currentQuestionIndex + 1;
        document.getElementById('current-question').textContent = currentQuestion.question;
        
        const card = document.getElementById('question-card');
        
        // Remove old handler if exists
        if (this.swipeHandler) {
            this.swipeHandler.destroy();
        }
        
        this.attachSwipeHandler(card, (direction) => {
            const answer = direction === 'right';
            
            this.state.answers.push({
                id: currentQuestion.id,
                question: currentQuestion.question,
                answer: answer
            });
            
            this.state.currentQuestionIndex++;
            
            // Small delay before showing next question
            setTimeout(() => {
                this.showQuestionScreen();
            }, 300);
        });
    }

    // ========================================
    // Captcha Screen
    // ========================================

    showCaptchaScreen() {
        this.showScreen('captcha-screen');
        this.state.step = 'CAPTCHA';
        this.updateProgress(90);
        this.runRecaptchaV3();
    }

    initRecaptcha() {
        this.disableSubmitButton();
        this.setCaptchaStatus('Verifica automatica in corso...');
    }

    setCaptchaStatus(message) {
        const status = document.getElementById('captcha-status');
        if (status) {
            status.textContent = message;
        }
    }

    disableSubmitButton() {
        const submitBtn = document.getElementById('submit-btn');
        if (!submitBtn) return;
        submitBtn.classList.add('disabled');
        submitBtn.disabled = true;
    }

    enableSubmitButton() {
        const submitBtn = document.getElementById('submit-btn');
        if (!submitBtn) return;
        submitBtn.classList.remove('disabled');
        submitBtn.disabled = false;
    }

    async runRecaptchaV3() {
        this.disableSubmitButton();
        this.state.captchaToken = null;
        this.state.captchaTokenAt = null;
        this.setCaptchaStatus('Automatic verification in progress...');

        try {
            const token = await this.getRecaptchaToken('submit');
            if (!token) {
                throw new Error('No reCAPTCHA token received');
            }

            this.state.captchaToken = token;
            this.state.captchaTokenAt = Date.now();
            this.setCaptchaStatus('Verification completed. You can now submit.');
            this.enableSubmitButton();
        } catch (e) {
            console.warn('reCAPTCHA v3 failed:', e);
            this.setCaptchaStatus('Verification failed. Please reload the page and try again.');
            this.disableSubmitButton();
        }
    }

    async waitForRecaptcha(maxWaitMs = 8000) {
        if (typeof grecaptcha === 'undefined') {
            await this.loadRecaptchaScript();
        }

        const start = Date.now();
        while (typeof grecaptcha === 'undefined') {
            if (Date.now() - start > maxWaitMs) {
                throw new Error('grecaptcha timed out while loading');
            }
            await new Promise((resolve) => setTimeout(resolve, 200));
        }
    }

    loadRecaptchaScript() {
        if (this.recaptchaScriptPromise) {
            return this.recaptchaScriptPromise;
        }

        this.recaptchaScriptPromise = new Promise((resolve, reject) => {
            const existing = document.querySelector('script[data-recaptcha-loader="v3"]');
            if (existing) {
                existing.addEventListener('load', resolve, { once: true });
                existing.addEventListener('error', () => reject(new Error('reCAPTCHA script failed to load')), { once: true });
                if (typeof grecaptcha !== 'undefined') {
                    resolve();
                }
                return;
            }

            const script = document.createElement('script');
            script.src = `https://www.google.com/recaptcha/api.js?render=${encodeURIComponent(RECAPTCHA_CONFIG.siteKey)}`;
            script.async = true;
            script.defer = true;
            script.setAttribute('data-recaptcha-loader', 'v3');
            script.onload = () => resolve();
            script.onerror = () => reject(new Error('reCAPTCHA script failed to load'));
            document.head.appendChild(script);
        });

        return this.recaptchaScriptPromise;
    }

    async getRecaptchaToken(action) {
        await this.waitForRecaptcha();

        return new Promise((resolve, reject) => {
            const timeoutId = setTimeout(() => {
                reject(new Error('reCAPTCHA execute timeout'));
            }, 10000);

            grecaptcha.ready(() => {
                grecaptcha.execute(RECAPTCHA_CONFIG.siteKey, { action })
                    .then((token) => {
                        clearTimeout(timeoutId);
                        resolve(token);
                    })
                    .catch((error) => {
                        clearTimeout(timeoutId);
                        reject(error);
                    });
            });
        });
    }

    captchaTokenExpired() {
        if (!this.state.captchaTokenAt) return true;
        const tokenAgeMs = Date.now() - this.state.captchaTokenAt;
        return tokenAgeMs > 110000;
    }

    // ========================================
    // Submission
    // ========================================

    async submitData() {
        if (!this.state.captchaToken || this.captchaTokenExpired()) {
            this.setCaptchaStatus('Aggiornamento verifica in corso...');
            await this.runRecaptchaV3();
            if (!this.state.captchaToken) {
                alert('Verifica reCAPTCHA non disponibile. Riprova.');
                return;
            }
        }

        this.showScreen('submitting-screen');
        this.state.step = 'SUBMITTING';
        this.updateProgress(95);

        const payload = this.buildPayload();

        try {
            const response = await this.sendToWebhook(payload);
            
            if (response.ok) {
                this.showSuccessScreen();
            } else {
                throw new Error('Webhook returned error status');
            }
        } catch (error) {
            console.error('Submission error:', error);
            this.showErrorScreen();
        }
    }

    buildPayload() {
        return {
            version: "1.0",
            timestamp_iso: new Date().toISOString(),
            session_id: this.state.sessionId,
            user: {
                first_name: this.state.user.firstName,
                last_name: this.state.user.lastName,
                email: this.state.user.email
            },
            answers: this.state.answers,
            meta: {
                user_agent: navigator.userAgent,
                language: navigator.language,
                timezone: Intl.DateTimeFormat().resolvedOptions().timeZone,
                screen: {
                    w: window.screen.width,
                    h: window.screen.height
                },
                is_touch: 'ontouchstart' in window
            },
            captcha: {
                provider: "recaptcha",
                token: this.state.captchaToken
            }
        };
    }

    async sendToWebhook(payload) {
        const controller = new AbortController();
        const timeoutId = setTimeout(() => controller.abort(), WEBHOOK_CONFIG.timeout);

        try {
            const response = await fetch(WEBHOOK_CONFIG.url, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify(payload),
                signal: controller.signal
            });

            clearTimeout(timeoutId);
            return response;
        } catch (error) {
            clearTimeout(timeoutId);
            throw error;
        }
    }

    showSuccessScreen() {
        this.showScreen('success-screen');
        this.state.step = 'DONE';
        this.updateProgress(100);
    }

    showErrorScreen() {
        this.showScreen('error-screen');
        this.state.step = 'ERROR';
    }

    async retrySubmission() {
        if (this.retryCount < WEBHOOK_CONFIG.maxRetries) {
            this.retryCount++;
            await this.submitData();
        } else {
            alert('Numero massimo di tentativi raggiunto. Riprova più tardi.');
        }
    }

    // ========================================
    // Swipe Handler
    // ========================================

    attachSwipeHandler(element, onSwipe) {
        let startX = 0;
        let startY = 0;
        let currentX = 0;
        let currentY = 0;
        let isDragging = false;
        
        const SWIPE_THRESHOLD = 80; // pixels
        const VERTICAL_THRESHOLD = 50; // to distinguish from vertical scroll

        const handleStart = (e) => {
            const touch = e.type.includes('pointer') ? e : e.touches[0];
            startX = touch.clientX;
            startY = touch.clientY;
            isDragging = true;
            element.classList.add('dragging');
        };

        const handleMove = (e) => {
            if (!isDragging) return;

            const touch = e.type.includes('pointer') ? e : e.touches[0];
            currentX = touch.clientX;
            currentY = touch.clientY;

            const deltaX = currentX - startX;
            const deltaY = currentY - startY;

            // Ignore if vertical movement is dominant
            if (Math.abs(deltaY) > Math.abs(deltaX) && Math.abs(deltaY) > VERTICAL_THRESHOLD) {
                return;
            }

            // Prevent default to avoid scroll
            if (Math.abs(deltaX) > 10) {
                e.preventDefault();
            }

            // Apply transform
            element.style.transform = `translateX(${deltaX}px) rotate(${deltaX * 0.05}deg)`;

            // Show overlays
            const yesOverlay = element.querySelector('.yes-overlay');
            const noOverlay = element.querySelector('.no-overlay');

            if (deltaX > 30) {
                yesOverlay?.classList.add('active');
                noOverlay?.classList.remove('active');
            } else if (deltaX < -30) {
                noOverlay?.classList.add('active');
                yesOverlay?.classList.remove('active');
            } else {
                yesOverlay?.classList.remove('active');
                noOverlay?.classList.remove('active');
            }
        };

        const handleEnd = (e) => {
            if (!isDragging) return;

            isDragging = false;
            element.classList.remove('dragging');

            const deltaX = currentX - startX;
            const deltaY = currentY - startY;

            // Check if vertical movement was dominant
            if (Math.abs(deltaY) > Math.abs(deltaX) && Math.abs(deltaY) > VERTICAL_THRESHOLD) {
                element.style.transform = '';
                return;
            }

            // Remove overlays
            const yesOverlay = element.querySelector('.yes-overlay');
            const noOverlay = element.querySelector('.no-overlay');
            
            if (Math.abs(deltaX) > SWIPE_THRESHOLD) {
                // Valid swipe
                element.classList.add('swiping-out');
                
                const direction = deltaX > 0 ? 'right' : 'left';
                const targetX = deltaX > 0 ? window.innerWidth : -window.innerWidth;
                
                element.style.transform = `translateX(${targetX}px) rotate(${deltaX > 0 ? 30 : -30}deg)`;
                element.style.opacity = '0';

                setTimeout(() => {
                    element.classList.remove('swiping-out');
                    element.style.transform = '';
                    element.style.opacity = '';
                    yesOverlay?.classList.remove('active');
                    noOverlay?.classList.remove('active');
                    
                    onSwipe(direction);
                }, 400);
            } else {
                // Return to center
                element.style.transform = '';
                yesOverlay?.classList.remove('active');
                noOverlay?.classList.remove('active');
            }
        };

        // Use Pointer Events for better compatibility
        element.addEventListener('pointerdown', handleStart);
        element.addEventListener('pointermove', handleMove);
        element.addEventListener('pointerup', handleEnd);
        element.addEventListener('pointercancel', handleEnd);

        // Store handler for cleanup
        this.swipeHandler = {
            destroy: () => {
                element.removeEventListener('pointerdown', handleStart);
                element.removeEventListener('pointermove', handleMove);
                element.removeEventListener('pointerup', handleEnd);
                element.removeEventListener('pointercancel', handleEnd);
            }
        };
    }

    // ========================================
    // Event Listeners
    // ========================================

    setupEventListeners() {
        // Submit button
        const submitBtn = document.getElementById('submit-btn');
        submitBtn?.addEventListener('click', () => {
            this.submitData();
        });

        // Retry button
        const retryBtn = document.getElementById('retry-btn');
        retryBtn?.addEventListener('click', () => {
            this.retrySubmission();
        });

        // Form input listeners for real-time validation
        const inputs = ['first-name', 'last-name', 'email'];
        inputs.forEach(id => {
            const input = document.getElementById(id);
            input?.addEventListener('input', () => {
                input.classList.remove('invalid');
            });
        });
    }

    // ========================================
    // Utilities
    // ========================================

    generateUUID() {
        return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, function(c) {
            const r = Math.random() * 16 | 0;
            const v = c === 'x' ? r : (r & 0x3 | 0x8);
            return v.toString(16);
        });
    }
}

// ========================================
// Initialize App
// ========================================

document.addEventListener('DOMContentLoaded', () => {
    window.surwipeApp = new SurwipeApp();
});
