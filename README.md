# PasskeyFlow for Secure Login

**Passwordless passkey login for WordPress — powered by WebAuthn / FIDO2.**

[![WordPress tested up to 6.9](https://img.shields.io/badge/WordPress-6.9-3858e9?logo=wordpress&logoColor=white)](https://wordpress.org)
[![PHP 8.0+](https://img.shields.io/badge/PHP-8.0%2B-777bb4?logo=php&logoColor=white)](https://php.net)
[![License: GPL v2](https://img.shields.io/badge/License-GPL_v2-blue.svg)](https://www.gnu.org/licenses/gpl-2.0.html)
[![Version](https://img.shields.io/badge/version-1.1.2-success)](readme.txt)

---

## Overview

PasskeyFlow for Secure Login replaces passwords with passkeys — cryptographic credentials stored in your device's Secure Enclave, Windows Hello, or a hardware key like a YubiKey. Users authenticate with Face ID, Touch ID, fingerprint, or PIN: no password required.

**PasskeyFlow Pro** (coming soon at [wppasskey.com](https://wppasskey.com)) adds passkey-only enforcement, device health analytics, audit exports, and agency tooling.

---

## Features

- Passkey registration and authentication via the **WebAuthn Level 2** spec
- Works with **Face ID, Touch ID, Windows Hello, Android biometrics, YubiKey** and any FIDO2 authenticator
- Drop-in passkey button on `wp-login.php` — no template edits required
- `[wpk_login_button]` and `[wpk_register_button]` shortcodes for front-end placement
- Integration-aware passkey modules for **WooCommerce, Easy Digital Downloads, MemberPress, Ultimate Member, LearnDash, BuddyBoss, Gravity Forms, and Paid Memberships Pro**
- Integration shortcodes and Gutenberg blocks auto-register when supported plugins are active
- Per-role eligibility control — grant passkeys to admins only, or all users
- Configurable per-user passkey limit (or no limit)
- Passkey management in the **user profile** (rename, revoke, capacity indicator)
- Dismissible admin notice prompting eligible users to register their first passkey
- **Users list column** showing each user's passkey count
- Tabbed settings page — Settings, Advanced, Shortcodes reference
- Rate limiting on login and revoke endpoints
- Daily cron cleanup of expired rate-limit rows and activity logs
- Challenge TTL, login redirect URL, RP name, and log retention are all configurable
- Fully translatable — `.pot` file included, `passkeyflow` text domain

---

## Requirements

| Requirement | Minimum |
|-------------|---------|
| PHP | 8.0 |
| WordPress | 6.0 |
| HTTPS | Required (WebAuthn mandates a secure context) |
| Browser | Any modern browser (Chrome 67+, Safari 14+, Firefox 60+, Edge 18+) |

---

## Installation

### From the WordPress admin

1. Upload the `passkeyflow` folder to `/wp-content/plugins/`.
2. Activate via **Plugins → Installed Plugins**.
3. Go to **Settings → PasskeyFlow for Secure Login** and enable passkeys.
4. Visit **Your Profile** and register your first passkey.
5. Sign out and click **Sign in with Passkey** on the login page.

### From source (development)

```bash
git clone https://github.com/mbuiux/passkeyflow.git
cd passkeyflow
composer install
```

Then symlink or copy the folder into your WordPress plugins directory and activate.

---

## Project Structure

```
passkeyflow/
├── admin/
│   ├── css/
│   │   └── wpk-admin.css          # All admin + login UI styles
│   └── js/
│       ├── wpk-login.js           # Login page WebAuthn flow
│       ├── wpk-profile.js         # Profile page registration + revoke flow
│       └── wpk-gutenberg-blocks.js # Integration block registration in editor
├── includes/
│   ├── class-wpk-passkeys.php     # Core WebAuthn engine, AJAX handlers, rate limiting
│   ├── class-wpk-settings.php     # Settings page, tabs, field renderers
│   ├── class-wpk-login-form.php   # Injects passkey button on wp-login.php
│   ├── class-wpk-shortcodes.php   # [wpk_login_button] and [wpk_register_button]
│   └── class-wpk-integration-manager.php # Integration modules, shortcodes, and blocks
├── languages/                     # Translation files (.pot)
├── vendor/                        # Composer dependencies
├── composer.json
├── composer.lock
├── index.php                      # Silence is golden
├── readme.txt                     # WordPress.org readme
├── uninstall.php                  # Drops all custom tables on uninstall
└── passkeyflow.php               # Plugin entry point
```

---

## Database Tables

The plugin creates three tables on activation (prefix respects `$wpdb->prefix`):

| Table | Purpose |
|-------|---------|
| `wp_wpk_credentials` | Passkey credential records (public key, counter, transports, label, timestamps) |
| `wp_wpk_rate_limits` | IP-based rate limit buckets for login and revoke endpoints |
| `wp_wpk_logs` | Activity log — registration, authentication, revoke events |

All three tables are dropped on plugin uninstall via `uninstall.php`.

---

## PHP Constant Overrides

Add any of these to `wp-config.php` to override database settings at the server level:

```php
define( 'WPK_CHALLENGE_TTL',  120 );          // Challenge timeout in seconds (default: 300)
define( 'WPK_ENABLE_LOGGING', true );          // Enable activity logging to wp_wpk_logs
define( 'WPK_RP_ID',          'example.com' ); // Override the WebAuthn Relying Party ID
define( 'WPK_RP_NAME',        'My Site' );     // Override the RP display name
define( 'WPK_ALLOW_HTTP',     true );          // Allow passkeys over HTTP (dev only — never in production)
```

---

## Shortcodes

### `[wpk_login_button]`

Renders the passkey sign-in button for logged-out visitors.

| Attribute | Default | Description |
|-----------|---------|-------------|
| `label` | "Sign in with Passkey" | Button text |
| `redirect_to` | _(Login Redirect setting)_ | URL to redirect after login |
| `class` | — | Extra CSS class(es) on the wrapper |

```
[wpk_login_button label="Sign in with your passkey" redirect_to="/dashboard"]
```

### `[wpk_register_button]`

Renders the passkey registration button for logged-in eligible users.

| Attribute | Default | Description |
|-----------|---------|-------------|
| `label` | "Register a Passkey" | Button text |
| `class` | — | Extra CSS class(es) on the wrapper |

```
[wpk_register_button label="Add a passkey to your account"]
```

---

## Development

### Running tests

```bash
composer install
./vendor/bin/phpunit
```

### Coding standards

The project targets **WordPress Coding Standards** (PHPCS). To check:

```bash
composer require --dev squizlabs/php_codesniffer wp-coding-standards/wpcs
./vendor/bin/phpcs --standard=WordPress includes/ admin/ passkeyflow.php
```

### Generating a release zip (local)

```bash
PLUGIN_SLUG="passkeyflow"
DIST_DIR="dist"
BUILD_ROOT="${DIST_DIR}/${PLUGIN_SLUG}"
rm -rf "${DIST_DIR}"
mkdir -p "${BUILD_ROOT}"
cp -R admin includes languages vendor "${BUILD_ROOT}/"
cp index.php passkeyflow.php readme.txt uninstall.php composer.json composer.lock "${BUILD_ROOT}/"
(cd "${DIST_DIR}" && zip -r "${PLUGIN_SLUG}.zip" "${PLUGIN_SLUG}")
```

The GitHub release workflow uses the same packaging structure and produces a single installable `passkeyflow.zip`.

---

## Security

- All AJAX endpoints validate a **WordPress nonce** (`check_ajax_referer`).
- All capability checks use `current_user_can()`.
- IP addresses are sanitised with `filter_var( $ip, FILTER_VALIDATE_IP )`.
- Rate limiting uses an atomic SQL `UPDATE … WHERE` pattern to prevent race conditions.
- Login redirect URLs are validated with `wp_validate_redirect()` / `wp_safe_redirect()` and re-validated after filters.
- No sensitive data (private keys, passwords) is ever stored or logged.
- The WebAuthn library (`lbuchs/webauthn`) handles all cryptographic operations.

---

## Changelog

See [readme.txt](readme.txt) for the full changelog in WordPress.org format.

### 1.1.0
- Users list passkey-count column
- Dismissible admin notice for eligible users with no passkeys
- Daily cron cleanup (expired rate limits + old log entries)
- Challenge TTL setting (30–600 s)
- Login redirect URL setting
- `[wpk_login_button]` and `[wpk_register_button]` shortcodes

### 1.0.0
- Initial release

---

## License

Licensed under the [GNU General Public License v2 or later](https://www.gnu.org/licenses/gpl-2.0.html).
