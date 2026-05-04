/* global WPKLogin */
(function () {
    'use strict';

    // ── Base64url helpers ───────────────────────────────────────────────────

    function b64urlToBuffer(input) {
        if (input instanceof ArrayBuffer) {
            return input;
        }

        if (ArrayBuffer.isView(input)) {
            return input.buffer.slice(input.byteOffset, input.byteOffset + input.byteLength);
        }

        if (Array.isArray(input)) {
            return new Uint8Array(input).buffer;
        }

        if (input && typeof input === 'object' && Array.isArray(input.data)) {
            return new Uint8Array(input.data).buffer;
        }

        if (typeof input !== 'string') {
            throw new Error('Invalid credential format. Please refresh and try again.');
        }

        var raw = input.trim().replace(/\s+/g, '');
        if (!raw) {
            throw new Error('Invalid credential format. Please refresh and try again.');
        }

        // Accept both base64url and base64 encodings from varying server/client implementations.
        var base64 = raw.replace(/-/g, '+').replace(/_/g, '/');
        var pad = base64.length % 4;
        if (pad) base64 += '='.repeat(4 - pad);

        var binary;
        try {
            binary = atob(base64);
        } catch (err) {
            throw new Error('Invalid passkey data received. Please refresh and try again.');
        }

        var bytes = new Uint8Array(binary.length);
        for (var i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
        return bytes.buffer;
    }

    function bufferToB64url(buffer) {
        var bytes = new Uint8Array(buffer);
        var binary = '';
        for (var i = 0; i < bytes.byteLength; i++) binary += String.fromCharCode(bytes[i]);
        return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
    }

    // ── DOM helpers ─────────────────────────────────────────────────────────

    function getMessageNode(btn) {
        var root = btn && btn.closest ? btn.closest('.wpk-login-passkey-wrap, .wpk-shortcode-login-wrap') : null;
        if (!root) {
            return document.getElementById('wpk-passkey-login-message');
        }
        return root.querySelector('.wpk-login-message') || document.getElementById('wpk-passkey-login-message');
    }

    function setMessage(btn, text) {
        var node = getMessageNode(btn);
        if (!node) return;
        node.textContent = text;
        node.classList.toggle('wpk-is-hidden', !text);
    }

    function relocateLoginPasskeyBlock() {
        var form = document.getElementById('loginform');
        var block = document.getElementById('wpk-login-passkey-block');
        if (!form || !block) return;

        var submitRow = form.querySelector('p.submit');
        if (submitRow && submitRow.parentNode === form) {
            submitRow.insertAdjacentElement('afterend', block);
            return;
        }

        form.appendChild(block);
    }

    function setButtonState(btn, busy) {
        if (!btn) return;
        btn.disabled = busy;
        btn.classList.toggle('wpk-btn-busy', busy);
        if (busy) {
            btn.setAttribute('data-original-html', btn.innerHTML);
            btn.textContent = WPKLogin.messages.signingIn || 'Signing in…';
        } else {
            var orig = btn.getAttribute('data-original-html');
            if (orig) btn.innerHTML = orig;
        }
    }

    function hydrateGetOptions(options) {
        var pk = options && options.publicKey ? options.publicKey : options;
        if (!pk || !pk.challenge) {
            throw new Error('Passkey options are incomplete. Please refresh and try again.');
        }

        pk.challenge = b64urlToBuffer(pk.challenge);

        if (Array.isArray(pk.allowCredentials)) {
            var hydratedAllow = [];
            pk.allowCredentials.forEach(function (item) {
                if (!item || !item.id) return;
                try {
                    item.id = b64urlToBuffer(item.id);
                    hydratedAllow.push(item);
                } catch (e) {
                    // Skip malformed credential IDs so a single legacy/bad record does not break all passkey sign-ins.
                }
            });

            if (hydratedAllow.length) {
                pk.allowCredentials = hydratedAllow;
            } else {
                delete pk.allowCredentials;
            }
        }

        options.publicKey = pk;
        return options;
    }

    function getLoginIdentifier() {
        var node = document.getElementById('user_login');
        return node ? (node.value || '').trim() : '';
    }

    function toFriendlyErrorMessage(err) {
        var msg = (err && err.message) ? String(err.message) : '';
        if (msg && /did not match the expected pattern/i.test(msg)) {
            return 'Your passkey request data was invalid. Please refresh this page and try again.';
        }
        return msg || WPKLogin.messages.genericError;
    }

    // ── AJAX ────────────────────────────────────────────────────────────────

    async function postForm(data) {
        var resp = await fetch(WPKLogin.ajaxUrl, {
            method: 'POST',
            credentials: 'same-origin',
            body: data,
        });

        var rawText = await resp.text();
        var payload;

        try {
            payload = JSON.parse(rawText);
        } catch (e) {
            throw new Error('Server returned non-JSON response. Check PHP/server logs and verify admin-ajax.php is reachable.');
        }

        if (!resp.ok) {
            throw new Error((payload && payload.data && payload.data.message) || WPKLogin.messages.genericError);
        }

        return payload;
    }

    // ── Sign-in flow ─────────────────────────────────────────────────────────

    async function signInWithPasskey(btn) {
        setMessage(btn, '');

        var beginData = new FormData();
        beginData.append('action', 'wpk_begin_login');
        beginData.append('nonce',  WPKLogin.nonce);

        var identifier = getLoginIdentifier();
        if (identifier) {
            beginData.append('login', identifier);
        }

        var beginResp = await postForm(beginData);
        if (!beginResp || !beginResp.success) {
            throw new Error((beginResp && beginResp.data && beginResp.data.message) || WPKLogin.messages.genericError);
        }

        var options    = hydrateGetOptions(beginResp.data.options);
        var credential = await navigator.credentials.get(options);

        var finishData = new FormData();
        finishData.append('action',            'wpk_finish_login');
        finishData.append('nonce',             WPKLogin.nonce);
        finishData.append('token',             beginResp.data.token);
        finishData.append('id',                bufferToB64url(credential.rawId));
        finishData.append('clientDataJSON',    bufferToB64url(credential.response.clientDataJSON));
        finishData.append('authenticatorData', bufferToB64url(credential.response.authenticatorData));
        finishData.append('signature',         bufferToB64url(credential.response.signature));

        if (credential.response.userHandle) {
            finishData.append('userHandle', bufferToB64url(credential.response.userHandle));
        }

        var finishResp = await postForm(finishData);
        if (!finishResp || !finishResp.success || !finishResp.data || !finishResp.data.redirect) {
            throw new Error((finishResp && finishResp.data && finishResp.data.message) || WPKLogin.messages.genericError);
        }

        var redirectUrl = finishResp.data.redirect;
        try {
            var parsed = new URL(redirectUrl, window.location.origin);
            if (parsed.origin !== window.location.origin) {
                throw new Error('Unexpected redirect origin');
            }
            window.location.href = parsed.href;
        } catch (e) {
            window.location.href = window.location.origin;
        }
    }

    // ── Init ────────────────────────────────────────────────────────────────

    function init() {
        relocateLoginPasskeyBlock();

        var buttons = Array.prototype.slice.call(document.querySelectorAll('#wpk-signin-passkey, [data-wpk-passkey-login-btn="1"]'));
        if (!buttons.length) return;

        // Graceful degradation for unsupported browsers
        if (!window.PublicKeyCredential || !navigator.credentials || !navigator.credentials.get) {
            buttons.forEach(function (btn) {
                btn.disabled = true;
                btn.classList.add('wpk-btn-disabled');
                btn.setAttribute('aria-disabled', 'true');
                btn.title = WPKLogin.messages.notSupported;
                setMessage(btn, WPKLogin.messages.notSupported);
            });
            return;
        }

        buttons.forEach(function (btn) {
            btn.classList.remove('wpk-btn-disabled');
            btn.removeAttribute('aria-disabled');
        });

        // Optional: auto-trigger discoverable credential prompt on page load
        // (usernameless passkey sign-in — the credential chooser appears immediately).
        // This is disabled by default to keep the UX consistent with existing flows.
        // Uncomment to enable:
        //
        // if (window.PublicKeyCredential.isConditionalMediationAvailable) {
        //     window.PublicKeyCredential.isConditionalMediationAvailable().then(function (available) {
        //         if (available) signInWithPasskey().catch(function () {});
        //     });
        // }

        buttons.forEach(function (btn) {
            btn.addEventListener('click', function (e) {
                e.preventDefault();
                setButtonState(btn, true);
                signInWithPasskey(btn)
                    .catch(function (err) {
                        // Ignore user-cancelled gestures silently
                        if (err && err.name === 'NotAllowedError') {
                            setMessage(btn, '');
                        } else {
                            setMessage(btn, toFriendlyErrorMessage(err));
                        }
                    })
                    .finally(function () {
                        setButtonState(btn, false);
                    });
                });
        });
    }

    document.addEventListener('DOMContentLoaded', init);
})();
