/* global ADVAPAFOProfile */
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
        return document.getElementById('advapafo-passkey-profile-message') || document.querySelector('.advapafo-profile-tip');
    }

    function setMessage(node, text, isError) {
        node = node || getDefaultMessageNode();
        if (!node) return;
        node.textContent = text;
        node.classList.toggle('advapafo-msg-error',   !!isError);
        node.classList.toggle('advapafo-msg-success',  !isError && !!text);
        node.style.display = text ? '' : 'none';
    }

    function getRegisterContext(btn) {
        var inputId = btn ? btn.getAttribute('data-advapafo-passkey-input-id') : '';
        var messageId = btn ? btn.getAttribute('data-advapafo-passkey-message-id') : '';

        var labelInput = inputId ? document.getElementById(inputId) : null;
        var messageNode = messageId ? document.getElementById(messageId) : null;

        if ((!labelInput || !messageNode) && btn && btn.closest) {
            var root = btn.closest('.advapafo-profile-register-controls');
            if (root) {
                labelInput = labelInput || root.querySelector('.advapafo-profile-label-input');
                messageNode = messageNode || root.querySelector('.advapafo-profile-tip');
            }
        }

        if (!labelInput) {
            labelInput = document.getElementById('advapafo-passkey-label');
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
        return msg || ADVAPAFOProfile.messages.failed;
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
        var resp = await fetch(ADVAPAFOProfile.ajaxUrl, {
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
            throw new Error((payload && payload.data && payload.data.message) || ADVAPAFOProfile.messages.failed);
        }

        return payload;
    }

    // ── Register ────────────────────────────────────────────────────────────

    async function registerPasskey(context) {
        var labelInput = context && context.labelInput ? context.labelInput : null;
        var label = labelInput ? labelInput.value.trim() : '';
        var messageNode = context && context.messageNode ? context.messageNode : null;

        setMessage(messageNode, ADVAPAFOProfile.messages.starting, false);

        var beginData = new FormData();
        beginData.append('action', 'advapafo_begin_registration');
        beginData.append('nonce',  ADVAPAFOProfile.nonce);

        var beginResp = await postForm(beginData);
        if (!beginResp || !beginResp.success) {
            var errMsg = (beginResp && beginResp.data && beginResp.data.message) || ADVAPAFOProfile.messages.failed;
            // Surface "limit reached" message specifically
            if (errMsg.toLowerCase().includes('maximum')) {
                throw new Error(ADVAPAFOProfile.messages.limitReached || errMsg);
            }
            throw new Error(errMsg);
        }

        var options    = hydrateCreateOptions(beginResp.data.options);
        var credential = await navigator.credentials.create(options);

        var finishData = new FormData();
        finishData.append('action',            'advapafo_finish_registration');
        finishData.append('nonce',             ADVAPAFOProfile.nonce);
        finishData.append('token',             beginResp.data.token);
        finishData.append('clientDataJSON',    bufferToB64url(credential.response.clientDataJSON));
        finishData.append('attestationObject', bufferToB64url(credential.response.attestationObject));
        finishData.append('label',             label);

        if (typeof credential.response.getTransports === 'function') {
            finishData.append('transports', JSON.stringify(credential.response.getTransports()));
        }

        var finishResp = await postForm(finishData);
        if (!finishResp || !finishResp.success) {
            throw new Error((finishResp && finishResp.data && finishResp.data.message) || ADVAPAFOProfile.messages.failed);
        }

        setMessage(messageNode, ADVAPAFOProfile.messages.success, false);
        setTimeout(function () { window.location.reload(); }, 800);
    }

    // ── Revoke ──────────────────────────────────────────────────────────────

    async function revokePasskey(row) {
        var credentialId = row.getAttribute('data-credential-id');
        if (!credentialId) return;

        var data = new FormData();
        data.append('action',       'advapafo_revoke_credential');
        data.append('nonce',        ADVAPAFOProfile.nonce);
        data.append('credentialId', credentialId);

        var resp = await postForm(data);
        if (!resp || !resp.success) {
            throw new Error((resp && resp.data && resp.data.message) || ADVAPAFOProfile.messages.revokeFailed);
        }
        window.location.reload();
    }

    function wireSetupNoticeDismiss() {
        var notice = document.querySelector('.advapafo-setup-notice');
        if (!notice) return;

        notice.addEventListener('click', function (e) {
            if (!e.target || !e.target.classList.contains('notice-dismiss')) return;

            var nonce = notice.getAttribute('data-nonce');
            var ajaxUrl = (window.ADVAPAFOProfile && ADVAPAFOProfile.ajaxUrl) ? ADVAPAFOProfile.ajaxUrl : (window.ajaxurl || '');
            if (!nonce || !ajaxUrl) return;

            var data = new FormData();
            data.append('action', 'advapafo_dismiss_notice');
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
        var registerButtons = Array.prototype.slice.call(document.querySelectorAll('#advapafo-passkey-register, [data-advapafo-passkey-register="1"]'));
        if (registerButtons.length) {
            if (!window.PublicKeyCredential || !navigator.credentials || !navigator.credentials.create) {
                registerButtons.forEach(function (btn) {
                    var context = getRegisterContext(btn);
                    btn.disabled = true;
                    setMessage(context.messageNode, ADVAPAFOProfile.messages.notSupported, true);
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
        document.querySelectorAll('.advapafo-passkey-revoke').forEach(function (btn) {
            btn.addEventListener('click', function (e) {
                e.preventDefault();
                if (!window.confirm(ADVAPAFOProfile.messages.confirmRevoke)) return;
                var row = btn.closest('tr');
                if (!row) return;
                btn.disabled = true;
                revokePasskey(row).catch(function (err) {
                    setMessage(getDefaultMessageNode(), (err && err.message) || ADVAPAFOProfile.messages.revokeFailed, true);
                    btn.disabled = false;
                });
            });
        });
    }

    document.addEventListener('DOMContentLoaded', init);
})();
