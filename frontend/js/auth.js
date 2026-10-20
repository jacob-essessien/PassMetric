
const Captcha = (() => {
    let sitekey = null;
    let widgetId = null;
    let token = null;
    let visible = false;

    async function loadSitekey() {
        if (sitekey !== null) return sitekey;
        try {
            const res = await fetch('/api/config', { credentials: 'include' });
            const cfg = await res.json();
            sitekey = cfg.hcaptcha_sitekey || '';
        } catch {
            sitekey = '';
        }
        return sitekey;
    }

  
    async function waitForHCaptchaLib(timeoutMs = 5000) {
        const start = Date.now();
        while (!window.hcaptcha) {
            if (Date.now() - start > timeoutMs) return false;
            await new Promise(r => setTimeout(r, 100));
        }
        return true;
    }

    async function show() {
        await loadSitekey();
        if (!sitekey) {
            // Captcha not configured on this server
            return;
        }
        const wrap = document.getElementById('captcha-wrap');
        const widget = document.getElementById('hcaptcha-widget');
        if (!wrap || !widget) return;

        if (!(await waitForHCaptchaLib())) {
            console.warn('[Captcha] hCaptcha library never loaded');
            return;
        }

        if (widgetId === null) {
            widget.setAttribute('data-sitekey', sitekey);
            widgetId = window.hcaptcha.render(widget, {
                sitekey,
                callback: (t) => { token = t; },
                'expired-callback': () => { token = null; },
                'error-callback': () => { token = null; },
            });
        }
        wrap.classList.remove('hidden');
        wrap.style.display = '';
        visible = true;
    }

    function hide() {
        const wrap = document.getElementById('captcha-wrap');
        if (wrap) {
            wrap.classList.add('hidden');
            wrap.style.display = 'none';
        }
        visible = false;
    }

    function reset() {
        token = null;
        if (widgetId !== null && window.hcaptcha) {
            try { window.hcaptcha.reset(widgetId); } catch { /* ignore */ }
        }
    }

    // Pre-check if captcha is required for this email
    async function checkRequired(email) {
        if (!email) return false;
        try {
            const data = await API.post('/auth/login-status', { email });
            if (data.captcha_required) {
                await show();
                return true;
            }
        } catch { /* ignore - fail silently */ }
        return false;
    }

    return {
        show, hide, reset, checkRequired,
        getToken: () => token,
        isVisible: () => visible,
    };
})();


// Check if already logged in
(async function checkSession() {
    try {
        await API.get('/auth/me');
        window.location.href = '/dashboard';
    } catch {
        // Not logged in - stay on auth page
    }
})();


// Switch between login/register forms
function switchForm(target) {
    document.querySelectorAll('.auth-form').forEach(f => f.classList.remove('active'));
    const form = document.getElementById(target + '-form');
    if (form) form.classList.add('active');
    document.getElementById('login-error')?.classList.add('hidden');
    document.getElementById('register-error')?.classList.add('hidden');
}


// Strength meter 
function updateStrengthMeter(password) {
    const bar = document.getElementById('strength-bar');
    const label = document.getElementById('strength-label');
    if (!bar || !label) return;

    if (!password) {
        bar.style.width = '0';
        label.textContent = '';
        return;
    }

    let score = 0;
    if (password.length >= 8)  score += 15;
    if (password.length >= 12) score += 15;
    if (password.length >= 16) score += 10;
    if (/[a-z]/.test(password)) score += 10;
    if (/[A-Z]/.test(password)) score += 10;
    if (/\d/.test(password))    score += 10;
    if (/[^a-zA-Z0-9]/.test(password)) score += 15;
    const unique = new Set(password).size;
    if (unique / password.length > 0.7) score += 15;

    score = Math.min(100, score);

    bar.style.width = score + '%';
    bar.style.background = strengthColor(score);

    if      (score >= 80) label.textContent = 'Very strong';
    else if (score >= 60) label.textContent = 'Strong';
    else if (score >= 40) label.textContent = 'Medium';
    else if (score >= 20) label.textContent = 'Weak';
    else                   label.textContent = 'Very weak';

    label.style.color = strengthColor(score);
}


//  Login 
async function handleLogin() {
    const email = document.getElementById('login-email').value.trim();
    const password = document.getElementById('login-password').value;
    const errorEl = document.getElementById('login-error');
    const btn = document.getElementById('login-btn');

    errorEl.classList.add('hidden');

    if (!email || !password) {
        errorEl.textContent = 'Please enter your email and master password.';
        errorEl.classList.remove('hidden');
        return;
    }

    
    if (Captcha.isVisible() && !Captcha.getToken()) {
        errorEl.textContent = 'Please complete the CAPTCHA.';
        errorEl.classList.remove('hidden');
        return;
    }

    btn.disabled = true;
    btn.querySelector('.btn-text').textContent = 'Unlocking...';
    btn.querySelector('.btn-loader').classList.remove('hidden');

    try {
        await API.post('/auth/login', {
            email,
            master_password: password,
            captcha_token: Captcha.getToken() || undefined,
        });
        window.location.href = '/dashboard';
    } catch (err) {
 
        if (err.data?.requires_captcha) {
            await Captcha.show();
            errorEl.textContent = err.data.error || 'Please complete the CAPTCHA and try again.';
            errorEl.classList.remove('hidden');
            return;
        }


        if (err.status === 403 && err.data?.requires_verification) {
            showUnverifiedMessage(err.data.email || email);
            return;
        }

        if (err.status === 423) {
            errorEl.textContent = err.data?.error || 'Account temporarily locked.';
            btn.disabled = true;
            const retryAfter = (err.data?.retry_after_seconds || 60) * 1000;
            setTimeout(() => { btn.disabled = false; }, retryAfter);
        } else if (err.status === 429) {
            errorEl.textContent = 'Too many requests. Please slow down.';
        } else {
            let msg = err.data?.error || 'Login failed.';
            if (err.data?.attempts_remaining !== undefined) {
                msg += ` (${err.data.attempts_remaining} attempt${err.data.attempts_remaining !== 1 ? 's' : ''} remaining)`;
            }
            errorEl.textContent = msg;

            if (err.data?.attempts_remaining !== undefined &&
                err.data.attempts_remaining <= 3) {
                Captcha.show();
            }
        }
        errorEl.classList.remove('hidden');

        // After any failure, invalidate the consumed token hCaptcha tokens are single-use
        Captcha.reset();
    } finally {
        btn.disabled = false;
        btn.querySelector('.btn-text').textContent = 'Unlock vault';
        btn.querySelector('.btn-loader').classList.add('hidden');
    }
}


// Register 
async function handleRegister(confirmWeak = false) {
    const email = document.getElementById('register-email').value.trim();
    const password = document.getElementById('register-password').value;
    const confirm = document.getElementById('register-confirm').value;
    const checkBreaches = document.getElementById('register-check-breaches')?.checked ?? true;
    const errorEl = document.getElementById('register-error');
    const btn = document.getElementById('register-btn');

    errorEl.classList.add('hidden');

    if (!email || !password) {
        errorEl.textContent = 'Please fill in all fields.';
        errorEl.classList.remove('hidden');
        return;
    }
    if (password !== confirm) {
        errorEl.textContent = 'Passwords do not match.';
        errorEl.classList.remove('hidden');
        return;
    }
    if (password.length < 12) {
        errorEl.textContent = 'Master password must be at least 12 characters.';
        errorEl.classList.remove('hidden');
        return;
    }

    btn.disabled = true;
    btn.querySelector('.btn-text').textContent = 'Creating vault...';
    btn.querySelector('.btn-loader').classList.remove('hidden');

    try {
        const data = await API.post('/auth/register', {
            email,
            master_password: password,
            check_breaches: checkBreaches,
            confirm_weak: confirmWeak,
        });

        // registration doesnt create a session.
        // Server returns { requires_verification: true }.
        if (data.requires_verification) {
            showVerificationSentScreen(email, password);
            return;
        }

        window.location.href = '/dashboard';
    } catch (err) {
        if (err.data?.requires_confirmation) {
            showWeakPasswordModal(err.data);
            return;
        }
        const msg = err.data?.error ?? err.message ?? 'Something went wrong. Please try again.';
        errorEl.textContent = msg;
        errorEl.classList.remove('hidden');
    } finally {
        btn.disabled = false;
        btn.querySelector('.btn-text').textContent = 'Create account';
        btn.querySelector('.btn-loader').classList.add('hidden');
    }
}


// "Check your email" screen after registration
function showVerificationSentScreen(email, masterPassword) {
    const wrapper = document.querySelector('.auth-form-wrapper');
    if (!wrapper) return;

    wrapper.innerHTML = `
        <div class="auth-form active" id="verify-sent-form">
            <div style="text-align:center;margin-bottom:24px;">
                <svg viewBox="0 0 24 24" width="56" height="56" fill="none"
                     stroke="#2ecc71" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                    <path d="M4 4h16c1.1 0 2 .9 2 2v12c0 1.1-.9 2-2 2H4c-1.1 0-2-.9-2-2V6c0-1.1.9-2 2-2z"/>
                    <polyline points="22,6 12,13 2,6"/>
                </svg>
            </div>
            <h2 style="text-align:center;">Check your email</h2>
            <p class="form-subtitle" style="text-align:center;">
                We've sent a verification link to<br>
                <strong id="verify-sent-email"></strong>
            </p>
            <p style="color:var(--text-secondary);font-size:13px;line-height:1.6;margin-bottom:24px;text-align:center;">
                Click the link in your email to activate your account.
                The link expires in 24 hours.
            </p>

            <div id="resend-msg" class="form-error hidden"
                 style="background:rgba(46,204,113,0.1);border-color:rgba(46,204,113,0.3);color:#2ecc71;"></div>

            <button class="btn btn-primary btn-full" id="back-to-login-btn">Back to login</button>

            <p class="form-footer">
                Didn't receive it? <a href="#" id="resend-link">Resend verification email</a>
            </p>
        </div>
    `;

    
    document.getElementById('verify-sent-email').textContent = email;

    document.getElementById('back-to-login-btn').addEventListener('click', () => {
        window.location.href = '/?email=' + encodeURIComponent(email);
    });

    const resendLink = document.getElementById('resend-link');
    const resendMsg = document.getElementById('resend-msg');
    if (resendLink && resendMsg) {
        resendLink.addEventListener('click', async (e) => {
            e.preventDefault();
            resendMsg.classList.add('hidden');
            resendMsg.textContent = '';
            resendMsg.style.background = 'rgba(46,204,113,0.1)';
            resendMsg.style.borderColor = 'rgba(46,204,113,0.3)';
            resendMsg.style.color = '#2ecc71';
            resendLink.style.pointerEvents = 'none';
            resendLink.style.opacity = '0.5';

            try {
                await API.post('/auth/resend-verification', {
                    email,
                    master_password: masterPassword,
                });
                resendMsg.textContent = 'Verification email resent. Check your inbox or spam folder.';
                resendMsg.classList.remove('hidden');
            } catch (err) {
                const message = err.data?.error || 'Could not resend verification email. Please try again later.';
                resendMsg.textContent = message;
                resendMsg.style.background = 'rgba(239,68,68,0.1)';
                resendMsg.style.borderColor = 'rgba(239,68,68,0.3)';
                resendMsg.style.color = '#ef4444';
                resendMsg.classList.remove('hidden');
            } finally {
                resendLink.style.pointerEvents = '';
                resendLink.style.opacity = '';
            }
        });
    }
}


//  Shown when someone tries to log in before verifying 
function showUnverifiedMessage(email) {
    const errorEl = document.getElementById('login-error');
    errorEl.innerHTML =
        'Please verify your email before logging in. ' +
        '<a href="#" id="inline-resend-link" style="text-decoration:underline;">Resend link</a>';
    errorEl.classList.remove('hidden');

    document.getElementById('inline-resend-link')?.addEventListener('click', async (e) => {
        e.preventDefault();
        const pwd = document.getElementById('login-password').value;
        if (!pwd) {
            errorEl.textContent = 'Enter your master password first, then click Resend.';
            return;
        }
        try {
            await API.post('/auth/resend-verification', { email, master_password: pwd });
            errorEl.textContent = 'If the account is unverified, a new link has been sent.';
            errorEl.style.color = '#2ecc71';
        } catch (err) {
            errorEl.textContent = err.data?.error || 'Could not resend. Try again later.';
        }
    });
}


// Weak and exposed Master Password modal pop up
function showWeakPasswordModal(data) {
    const modal = document.getElementById('weak-pw-modal');
    const body = document.getElementById('weak-pw-body');
    const title = document.getElementById('weak-pw-title');

    let titleText = 'Weak Master Password';
    let bodyText = 'Weak passwords can be easily guessed by attackers. ';

    if (data.is_breached && data.is_weak) {
        titleText = 'Weak and Exposed Master Password';
        bodyText = 'Weak password identified and found in a data breach. '
                 + 'Use a strong and unique password to protect your account. '
                 + 'Are you sure you want to use this password?';
    } else if (data.is_breached) {
        titleText = 'Exposed Master Password';
        bodyText = 'This password has been found in a known data breach and '
                 + 'is easy for attackers to guess. Are you sure you want to '
                 + 'use this password?';
    } else {
        bodyText += 'Use a strong and unique password to protect your account. '
                  + 'Are you sure you want to use this password?';
    }

    title.textContent = titleText;
    body.textContent = bodyText;
    modal.classList.remove('hidden');


    const yesBtn = document.getElementById('weak-pw-yes');
    const noBtn = document.getElementById('weak-pw-no');
    const newYes = yesBtn.cloneNode(true);
    const newNo = noBtn.cloneNode(true);
    yesBtn.replaceWith(newYes);
    noBtn.replaceWith(newNo);

    newYes.addEventListener('click', () => {
        modal.classList.add('hidden');
        handleRegister(true);
    });
    newNo.addEventListener('click', () => {
        modal.classList.add('hidden');
        document.getElementById('register-password').focus();
    });
}



function handleVerificationRedirect() {
    const params = new URLSearchParams(window.location.search);

    if (params.get('verified') === '1') {
        const errorEl = document.getElementById('login-error');
        if (errorEl) {
            errorEl.textContent = 'Email verified! Sign in with your master password to continue.';
            errorEl.style.background = 'rgba(46,204,113,0.1)';
            errorEl.style.borderColor = 'rgba(46,204,113,0.3)';
            errorEl.style.color = '#2ecc71';
            errorEl.classList.remove('hidden');
        }
    }

    
    const email = params.get('email');
    if (email) {
        const emailInput = document.getElementById('login-email');
        if (emailInput) {
            emailInput.value = email;
            document.getElementById('login-password')?.focus();
        }
    }

  
    if (params.has('verified') || params.has('email')) {
        window.history.replaceState({}, '', '/');
    }
}



function bindAuthEvents() {
    // Form switch links ("Create one" / "Sign in")
    document.querySelectorAll('[data-switch-form]').forEach(link => {
        link.addEventListener('click', (e) => {
            e.preventDefault();
            switchForm(link.dataset.switchForm);
        });
    });

    // Password eye-toggle buttons
    document.querySelectorAll('.toggle-password').forEach(btn => {
        btn.addEventListener('click', () => {
            const inputId = btn.dataset.toggleInput;
            if (inputId) togglePasswordVisibility(inputId, btn);
        });
    });

    // Strength meter (register password field)
    const regPw = document.getElementById('register-password');
    if (regPw) {
        regPw.addEventListener('input', (e) => updateStrengthMeter(e.target.value));
    }

    // Login and register buttons
    document.getElementById('login-btn')?.addEventListener('click', handleLogin);
    document.getElementById('register-btn')?.addEventListener('click', () => handleRegister());


    const loginEmail = document.getElementById('login-email');
    if (loginEmail) {
        loginEmail.addEventListener('blur', () => {
            const email = loginEmail.value.trim();
            if (email && /@/.test(email)) {
                Captcha.checkRequired(email);
            }
        });
    }

    // Enter-key submit
    document.addEventListener('keydown', (e) => {
        if (e.key !== 'Enter') return;
        const loginActive = document.getElementById('login-form')?.classList.contains('active');
        const registerActive = document.getElementById('register-form')?.classList.contains('active');
        if (loginActive) handleLogin();
        else if (registerActive) handleRegister();
    });

    handleVerificationRedirect();
}

if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', bindAuthEvents);
} else {
    bindAuthEvents();
}
