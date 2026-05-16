/* global ADVAPAFOLogin */
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
        var root = btn && btn.closest ? btn.closest('.advapafo-login-passkey-wrap, .advapafo-shortcode-login-wrap') : null;
        if (!root) {
            return document.getElementById('advapafo-passkey-login-message');
        }
        return root.querySelector('.advapafo-login-message') || document.getElementById('advapafo-passkey-login-message');
    }

    function isWpLoginContext(btn) {
        var form = document.getElementById('loginform');
        if (!form) {
            return false;
        }

        if (!btn || !btn.closest) {
            return true;
        }

        return !!btn.closest('#advapafo-login-passkey-block') || !!btn.closest('#loginform');
    }

    function getOrCreateWpLoginNoticeNode() {
        var loginWrap = document.getElementById('login');
        var form = document.getElementById('loginform');
        if (!loginWrap || !form || !form.parentNode) {
            return null;
        }

        var node = document.getElementById('advapafo-login-notice');
        if (!node) {
            node = document.createElement('div');
            node.id = 'advapafo-login-notice';
            node.className = 'notice notice-error';
            node.setAttribute('role', 'alert');
            node.setAttribute('aria-live', 'assertive');
            form.parentNode.insertBefore(node, form);
        }

        return node;
    }

    function setMessage(btn, text) {
        if (isWpLoginContext(btn)) {
            var wpNotice = getOrCreateWpLoginNoticeNode();
            if (!wpNotice) return;

            wpNotice.textContent = text || '';
            wpNotice.style.display = text ? '' : 'none';

            // Keep inline node empty/hidden on wp-login so messages only appear
            // in the native notice region above the form.
            var inlineNode = getMessageNode(btn);
            if (inlineNode) {
                inlineNode.textContent = '';
                inlineNode.classList.add('advapafo-is-hidden');
            }

            return;
        }

        var node = getMessageNode(btn);
        if (!node) return;
        node.textContent = text;
        node.classList.toggle('advapafo-is-hidden', !text);
    }

    function relocateLoginPasskeyBlock() {
        var form = document.getElementById('loginform');
        var block = document.getElementById('advapafo-login-passkey-block');
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
        btn.classList.toggle('advapafo-btn-busy', busy);
        if (busy) {
            btn.setAttribute('data-original-html', btn.innerHTML);
            btn.textContent = ADVAPAFOLogin.messages.signingIn || 'Signing in…';
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

    function getRedirectTarget() {
        var redirectNode = document.getElementById('redirect_to');
        if (!redirectNode) {
            return '';
        }

        var value = typeof redirectNode.value === 'string' ? redirectNode.value.trim() : '';
        return value;
    }

    function toFriendlyErrorMessage(err) {
        var msg = (err && err.message) ? String(err.message) : '';
        if (msg && /did not match the expected pattern/i.test(msg)) {
            return 'Your passkey request data was invalid. Please refresh this page and try again.';
        }
        return msg || ADVAPAFOLogin.messages.genericError;
    }

    // ── AJAX ────────────────────────────────────────────────────────────────

    async function postForm(data) {
        var resp = await fetch(ADVAPAFOLogin.ajaxUrl, {
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
            throw new Error((payload && payload.data && payload.data.message) || ADVAPAFOLogin.messages.genericError);
        }

        return payload;
    }

    // ── Sign-in flow ─────────────────────────────────────────────────────────

    async function signInWithPasskey(btn) {
        setMessage(btn, '');

        var beginData = new FormData();
        beginData.append('action', 'advapafo_begin_login');
        beginData.append('nonce',  ADVAPAFOLogin.nonce);

        var identifier = getLoginIdentifier();
        if (identifier) {
            beginData.append('login', identifier);
        }

        var beginResp = await postForm(beginData);
        if (!beginResp || !beginResp.success) {
            throw new Error((beginResp && beginResp.data && beginResp.data.message) || ADVAPAFOLogin.messages.genericError);
        }

        var options    = hydrateGetOptions(beginResp.data.options);
        var credential = await navigator.credentials.get(options);

        var finishData = new FormData();
        finishData.append('action',            'advapafo_finish_login');
        finishData.append('nonce',             ADVAPAFOLogin.nonce);
        finishData.append('token',             beginResp.data.token);
        finishData.append('id',                bufferToB64url(credential.rawId));
        finishData.append('clientDataJSON',    bufferToB64url(credential.response.clientDataJSON));
        finishData.append('authenticatorData', bufferToB64url(credential.response.authenticatorData));
        finishData.append('signature',         bufferToB64url(credential.response.signature));

        if (credential.response.userHandle) {
            finishData.append('userHandle', bufferToB64url(credential.response.userHandle));
        }

        var redirectTo = getRedirectTarget();
        if (redirectTo) {
            finishData.append('redirect_to', redirectTo);
        }

        var finishResp = await postForm(finishData);
        if (!finishResp || !finishResp.success || !finishResp.data || !finishResp.data.redirect) {
            throw new Error((finishResp && finishResp.data && finishResp.data.message) || ADVAPAFOLogin.messages.genericError);
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

        var buttons = Array.prototype.slice.call(document.querySelectorAll('#advapafo-signin-passkey, [data-advapafo-passkey-login-btn="1"]'));
        if (!buttons.length) return;

        // Graceful degradation for unsupported browsers
        if (!window.PublicKeyCredential || !navigator.credentials || !navigator.credentials.get) {
            buttons.forEach(function (btn) {
                btn.disabled = true;
                btn.classList.add('advapafo-btn-disabled');
                btn.setAttribute('aria-disabled', 'true');
                btn.title = ADVAPAFOLogin.messages.notSupported;
                setMessage(btn, ADVAPAFOLogin.messages.notSupported);
            });
            return;
        }

        buttons.forEach(function (btn) {
            btn.classList.remove('advapafo-btn-disabled');
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
