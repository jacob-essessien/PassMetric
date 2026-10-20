const API_BASE = '/api';
let csrfToken = null;

// Fetch CSRF token on page load
async function fetchCsrfToken() {
    try {
        const res = await fetch('/api/csrf-token', { credentials: 'include' });
        const data = await res.json();
        csrfToken = data.csrf_token;
    } catch { /* ignore */ }
}

async function api(path, options = {}) {
    if (!csrfToken) await fetchCsrfToken(); // makes sure we have a CSRF token before making requests
    const url = API_BASE + path;
    const config = {
        headers: { 'Content-Type': 'application/json', 'X-CSRFToken': csrfToken },
        credentials: 'include',
        ...options,
    };

    let res;
    try {
        res = await fetch(url, config);
        // If CSRF token is expired, refresh it and retry once
        if (res.status === 400) {
            const body = await res.clone().json();
            if (body.error && body.error.includes('CSRF')) {
                await fetchCsrfToken();
                config.headers['X-CSRFToken'] = csrfToken;
                res = await fetch(url, config);
            }
        }
    } catch (netErr) {
        // Network-level failure (server down, CORS, etc.)
        const err = new Error('Network error - could not reach server.');
        err.status = 0;
        err.data = {};
        throw err;
    }

    // Try to parse the body as JSON. If the server returned HTML (e.g. a
    // Flask debug error page), fall back to a plain-text error.
    let data;
    const contentType = res.headers.get('content-type') || '';
    if (contentType.includes('application/json')) {
        try {
            data = await res.json();
        } catch {
            data = {};
        }
    } else {
        data = { error: `Server returned a non-JSON response (${res.status}).` };
    }

    if (!res.ok) {
        const err = new Error(data.error || `Request failed (${res.status})`);
        err.status = res.status;
        err.data = data;
        throw err;
    }
    return data;
}

// Convenience methods
const API = {
    get:  (path)       => api(path, { method: 'GET' }),
    post: (path, body) => api(path, { method: 'POST', body: JSON.stringify(body) }),
    put:  (path, body) => api(path, { method: 'PUT',  body: JSON.stringify(body) }),
    del:  (path)       => api(path, { method: 'DELETE' }),
};


// Shared helpers

function togglePasswordVisibility(inputId, btn) {
    const input = document.getElementById(inputId);
    const isPassword = input.type === 'password';
    input.type = isPassword ? 'text' : 'password';
    btn.style.opacity = isPassword ? '1' : '0.5';
}

// Clipboard auto-clear 
let _clipboardClearTimer = null;

function _getClipboardClearSeconds() {
    const raw = localStorage.getItem('passmetric_clipboard_seconds');
    if (!raw || raw === 'never') return null;
    const n = parseInt(raw, 10);
    return Number.isFinite(n) && n > 0 ? n : null;
}

async function _writeToClipboard(text) {
    try {
        await navigator.clipboard.writeText(text);
    } catch {
        // Older browsers / non-HTTPS fallback
        const ta = document.createElement('textarea');
        ta.value = text;
        ta.style.position = 'fixed';
        ta.style.opacity = '0';
        document.body.appendChild(ta);
        ta.select();
        document.execCommand('copy');
        document.body.removeChild(ta);
    }
}

async function copyToClipboard(text) {
    await _writeToClipboard(text);

    // Cancel any pending clear so we don't wipe a fresher copy
    if (_clipboardClearTimer) {
        clearTimeout(_clipboardClearTimer);
        _clipboardClearTimer = null;
    }

    const secs = _getClipboardClearSeconds();
    if (secs) {
        showToast(`Copied. Clipboard clears in ${secs}s`);
        _clipboardClearTimer = setTimeout(async () => {
            // Only clears if the clipboard still contains what was put there -
            // the user may have copied something else in the meantime.
            try {
                const current = await navigator.clipboard.readText();
                if (current === text) {
                    await _writeToClipboard('');
                }
            } catch {
                await _writeToClipboard('');
            }
            _clipboardClearTimer = null;
        }, secs * 1000);
    } else {
        showToast('Copied to clipboard');
    }
}

function showToast(msg) {
    let toast = document.getElementById('toast');
    if (!toast) {
        toast = document.createElement('div');
        toast.id = 'toast';
        toast.style.cssText = `
            position: fixed; bottom: 24px; left: 50%; transform: translateX(-50%);
            background: #2ecc71; color: #fff; padding: 10px 24px;
            border-radius: 6px; font-size: 14px; font-weight: 500;
            z-index: 300; opacity: 0; transition: opacity 0.3s;
            pointer-events: none;
        `;
        document.body.appendChild(toast);
    }
    toast.textContent = msg;
    toast.style.opacity = '1';
    clearTimeout(toast._timer);
    toast._timer = setTimeout(() => { toast.style.opacity = '0'; }, 2000);
}

function strengthColor(score) {
    if (score >= 80) return 'var(--str-very-strong)';
    if (score >= 60) return 'var(--str-strong)';
    if (score >= 40) return 'var(--str-medium)';
    if (score >= 20) return 'var(--str-weak)';
    return 'var(--str-very-weak)';
}

function strengthName(str) {
    return (str || '').replace(/_/g, ' ').replace(/\b\w/g, c => c.toUpperCase());
}
