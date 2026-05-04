/* global WPKProfile */
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

    function getDefaultMessageNode() {
        return document.getElementById('wpk-passkey-profile-message') || document.querySelector('.wpk-profile-tip');
    }

    function setMessage(node, text, isError) {
        node = node || getDefaultMessageNode();
        if (!node) return;
        node.textContent = text;
        node.classList.toggle('wpk-msg-error',   !!isError);
        node.classList.toggle('wpk-msg-success',  !isError && !!text);
        node.style.display = text ? '' : 'none';
    }

    function getRegisterContext(btn) {
        var inputId = btn ? btn.getAttribute('data-wpk-passkey-input-id') : '';
        var messageId = btn ? btn.getAttribute('data-wpk-passkey-message-id') : '';

        var labelInput = inputId ? document.getElementById(inputId) : null;
        var messageNode = messageId ? document.getElementById(messageId) : null;

        if ((!labelInput || !messageNode) && btn && btn.closest) {
            var root = btn.closest('.wpk-profile-register-controls');
            if (root) {
                labelInput = labelInput || root.querySelector('.wpk-profile-label-input');
                messageNode = messageNode || root.querySelector('.wpk-profile-tip');
            }
        }

        if (!labelInput) {
            labelInput = document.getElementById('wpk-passkey-label');
        }
        if (!messageNode) {
            messageNode = getDefaultMessageNode();
        }

        return {
            labelInput: labelInput,
            messageNode: messageNode,
        };
    }

    function toFriendlyErrorMessage(err) {
        var msg = (err && err.message) ? String(err.message) : '';
        if (msg && /did not match the expected pattern/i.test(msg)) {
            return 'Your passkey request data was invalid. Please refresh this page and try again.';
        }
        return msg || WPKProfile.messages.failed;
    }

    function hydrateCreateOptions(options) {
        options.publicKey.challenge = b64urlToBuffer(options.publicKey.challenge);
        options.publicKey.user.id  = b64urlToBuffer(options.publicKey.user.id);
        if (Array.isArray(options.publicKey.excludeCredentials)) {
            options.publicKey.excludeCredentials = options.publicKey.excludeCredentials.map(function (item) {
                item.id = b64urlToBuffer(item.id);
                return item;
            });
        }
        return options;
    }

    // ── AJAX ────────────────────────────────────────────────────────────────

    async function postForm(data) {
        var resp = await fetch(WPKProfile.ajaxUrl, {
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
            throw new Error((payload && payload.data && payload.data.message) || WPKProfile.messages.failed);
        }

        return payload;
    }

    // ── Register ────────────────────────────────────────────────────────────

    async function registerPasskey(context) {
        var labelInput = context && context.labelInput ? context.labelInput : null;
        var label = labelInput ? labelInput.value.trim() : '';
        var messageNode = context && context.messageNode ? context.messageNode : null;

        setMessage(messageNode, WPKProfile.messages.starting, false);

        var beginData = new FormData();
        beginData.append('action', 'wpk_begin_registration');
        beginData.append('nonce',  WPKProfile.nonce);

        var beginResp = await postForm(beginData);
        if (!beginResp || !beginResp.success) {
            var errMsg = (beginResp && beginResp.data && beginResp.data.message) || WPKProfile.messages.failed;
            // Surface "limit reached" message specifically
            if (errMsg.toLowerCase().includes('maximum')) {
                throw new Error(WPKProfile.messages.limitReached || errMsg);
            }
            throw new Error(errMsg);
        }

        var options    = hydrateCreateOptions(beginResp.data.options);
        var credential = await navigator.credentials.create(options);

        var finishData = new FormData();
        finishData.append('action',            'wpk_finish_registration');
        finishData.append('nonce',             WPKProfile.nonce);
        finishData.append('token',             beginResp.data.token);
        finishData.append('clientDataJSON',    bufferToB64url(credential.response.clientDataJSON));
        finishData.append('attestationObject', bufferToB64url(credential.response.attestationObject));
        finishData.append('label',             label);

        if (typeof credential.response.getTransports === 'function') {
            finishData.append('transports', JSON.stringify(credential.response.getTransports()));
        }

        var finishResp = await postForm(finishData);
        if (!finishResp || !finishResp.success) {
            throw new Error((finishResp && finishResp.data && finishResp.data.message) || WPKProfile.messages.failed);
        }

        setMessage(messageNode, WPKProfile.messages.success, false);
        setTimeout(function () { window.location.reload(); }, 800);
    }

    // ── Revoke ──────────────────────────────────────────────────────────────

    async function revokePasskey(row) {
        var credentialId = row.getAttribute('data-credential-id');
        if (!credentialId) return;

        var data = new FormData();
        data.append('action',       'wpk_revoke_credential');
        data.append('nonce',        WPKProfile.nonce);
        data.append('credentialId', credentialId);

        var resp = await postForm(data);
        if (!resp || !resp.success) {
            throw new Error((resp && resp.data && resp.data.message) || WPKProfile.messages.revokeFailed);
        }
        window.location.reload();
    }

    function wireSetupNoticeDismiss() {
        var notice = document.querySelector('.wpk-setup-notice');
        if (!notice) return;

        notice.addEventListener('click', function (e) {
            if (!e.target || !e.target.classList.contains('notice-dismiss')) return;

            var nonce = notice.getAttribute('data-nonce');
            var ajaxUrl = (window.WPKProfile && WPKProfile.ajaxUrl) ? WPKProfile.ajaxUrl : (window.ajaxurl || '');
            if (!nonce || !ajaxUrl) return;

            var data = new FormData();
            data.append('action', 'wpk_dismiss_notice');
            data.append('nonce', nonce);

            fetch(ajaxUrl, {
                method: 'POST',
                credentials: 'same-origin',
                body: data,
            }).catch(function () {
                // No-op: dismissal state can be retried next page load.
            });
        });
    }

    // ── Event binding ───────────────────────────────────────────────────────

    function init() {
        wireSetupNoticeDismiss();

        // Check WebAuthn support
        var registerButtons = Array.prototype.slice.call(document.querySelectorAll('#wpk-passkey-register, [data-wpk-passkey-register="1"]'));
        if (registerButtons.length) {
            if (!window.PublicKeyCredential || !navigator.credentials || !navigator.credentials.create) {
                registerButtons.forEach(function (btn) {
                    var context = getRegisterContext(btn);
                    btn.disabled = true;
                    setMessage(context.messageNode, WPKProfile.messages.notSupported, true);
                });
                return;
            }

            registerButtons.forEach(function (registerBtn) {
                registerBtn.addEventListener('click', function (e) {
                    e.preventDefault();
                    var context = getRegisterContext(registerBtn);
                    registerBtn.disabled = true;
                    registerPasskey(context)
                        .catch(function (err) {
                            setMessage(context.messageNode, toFriendlyErrorMessage(err), true);
                        })
                        .finally(function () {
                            registerBtn.disabled = false;
                        });
                });
            });
        }

        // Revoke buttons
        document.querySelectorAll('.wpk-passkey-revoke').forEach(function (btn) {
            btn.addEventListener('click', function (e) {
                e.preventDefault();
                if (!window.confirm(WPKProfile.messages.confirmRevoke)) return;
                var row = btn.closest('tr');
                if (!row) return;
                btn.disabled = true;
                revokePasskey(row).catch(function (err) {
                    setMessage(getDefaultMessageNode(), (err && err.message) || WPKProfile.messages.revokeFailed, true);
                    btn.disabled = false;
                });
            });
        });
    }

    document.addEventListener('DOMContentLoaded', init);
})();
