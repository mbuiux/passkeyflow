# Advanced Passkeys for Secure Login

**Passwordless passkey login for WordPress — powered by WebAuthn / FIDO2.**

[![WordPress tested up to 6.9](https://img.shields.io/badge/WordPress-6.9-3858e9?logo=wordpress&logoColor=white)](https://wordpress.org)
[![PHP 8.0+](https://img.shields.io/badge/PHP-8.0%2B-777bb4?logo=php&logoColor=white)](https://php.net)
[![License: GPL v2](https://img.shields.io/badge/License-GPL_v2-blue.svg)](https://www.gnu.org/licenses/gpl-2.0.html)
[![Version](https://img.shields.io/badge/version-1.1.4-success)](readme.txt)

---

## Overview

Advanced Passkeys for Secure Login replaces passwords with passkeys — cryptographic credentials stored in your device's Secure Enclave, Windows Hello, or a hardware key like a YubiKey. Users authenticate with Face ID, Touch ID, fingerprint, or PIN: no password required.

---

## Features

- Passkey registration and authentication via the **WebAuthn Level 2** spec
- Works with **Face ID, Touch ID, Windows Hello, Android biometrics, YubiKey** and any FIDO2 authenticator
- Drop-in passkey button on `wp-login.php` — no template edits required
- `[pkflow_login_button]` and `[pkflow_register_button]` shortcodes for front-end placement
- `[pkflow_passkey_profile]` shortcode for logged-in passkey management UI
- `[pkflow_passkey_prompt]` shortcode for conditional passkey enrollment prompts
- Integration-aware passkey modules for **WooCommerce, Easy Digital Downloads, MemberPress, Ultimate Member, LearnDash, BuddyBoss, Gravity Forms, and PMPro**
- Integration shortcodes and Gutenberg blocks auto-register when supported plugins are active
- Integration modules also auto-inject passkey entry points into supported login and checkout surfaces when enabled
- Dashboard tab with an **Authenticator Overview** card for provider distribution and usage insights
- Dashboard tab with a **Last Login** activity card for quick, at-a-glance sign-in visibility
- Per-role eligibility control — grant passkeys to admins only, or all users
- Configurable per-user passkey limit (or no limit)
- Passkey management in the **user profile** (rename, revoke, capacity indicator)
- Dismissible admin notice prompting eligible users to register their first passkey
- **Users list column** showing each user's passkey count
- Tabbed settings page — Dashboard, Settings, Advanced, Shortcodes reference
- Rate limiting on login and revoke endpoints
- Daily cron cleanup of expired rate-limit rows and activity logs
- Challenge TTL, login redirect URL, RP name, and log retention are all configurable
- Multisite-aware activation and provisioning for newly created network sites
- Fully translatable — `.pot` file included, `advanced-passkey-login` text domain

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

1. Upload the `advanced-passkey-login` folder to `/wp-content/plugins/`.
2. Activate via **Plugins → Installed Plugins**.
3. Go to **Settings → Advanced Passkeys for Secure Login** and enable passkeys.
4. Visit **Your Profile** and register your first passkey.
5. Sign out and click **Sign in with Passkey** on the login page.

### From source (development)

```bash
git clone https://github.com/mbuiux/advanced-passkey-login.git
cd advanced-passkey-login
composer install
```

Then symlink or copy the folder into your WordPress plugins directory and activate.

---

## Project Structure

```
advanced-passkey-login/
├── admin/
│   ├── css/
│   │   └── pkflow-admin.css          # All admin + login UI styles
│   └── js/
│       ├── pkflow-login.js           # Login page WebAuthn flow
│       ├── pkflow-profile.js         # Profile page registration + revoke flow
│       ├── pkflow-dashboard.js       # Dashboard tab charts and activity rendering
│       └── pkflow-gutenberg-blocks.js # Integration block registration in editor
├── includes/
│   ├── class-pkflow-passkeys.php     # Core WebAuthn engine, AJAX handlers, rate limiting
│   ├── class-pkflow-settings.php     # Settings page, tabs, field renderers
│   ├── class-pkflow-login-form.php   # Injects passkey button on wp-login.php
│   ├── class-pkflow-shortcodes.php   # [pkflow_login_button] and [pkflow_register_button]
│   └── class-pkflow-integration-manager.php # Integration modules, shortcodes, and blocks
├── languages/                     # Translation files (.pot)
├── vendor/                        # Composer dependencies
├── composer.json
├── composer.lock
├── index.php                      # Silence is golden
├── readme.txt                     # WordPress.org readme
├── uninstall.php                  # Drops all custom tables on uninstall
└── advanced-passkey-login.php               # Plugin entry point
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
define( 'PKFLOW_CHALLENGE_TTL',  120 );          // Challenge timeout in seconds (default: 300)
define( 'PKFLOW_ENABLE_LOGGING', true );          // Enable activity logging to wp_wpk_logs
define( 'PKFLOW_RP_ID',          'example.com' ); // Override the WebAuthn Relying Party ID
define( 'PKFLOW_RP_NAME',        'My Site' );     // Override the RP display name
define( 'PKFLOW_ALLOW_HTTP',     true );          // Allow passkeys over HTTP (dev only — never in production)
```

---

## Shortcodes

### `[pkflow_login_button]`

Renders the passkey sign-in button for logged-out visitors.

| Attribute | Default | Description |
|-----------|---------|-------------|
| `label` | "Sign in with Passkey" | Button text |
| `redirect_to` | _(Login Redirect setting)_ | URL to redirect after login |
| `class` | — | Extra CSS class(es) on the wrapper |

```
[pkflow_login_button label="Sign in with your passkey" redirect_to="/dashboard"]
```

### `[pkflow_register_button]`

Renders the passkey registration button for logged-in eligible users.

| Attribute | Default | Description |
|-----------|---------|-------------|
| `label` | "Register a Passkey" | Button text |
| `class` | — | Extra CSS class(es) on the wrapper |

```
[pkflow_register_button label="Add a passkey to your account"]
```

### `[pkflow_passkey_profile]`

Renders passkey profile management for logged-in, eligible users.

```text
[pkflow_passkey_profile]
```

### `[pkflow_passkey_prompt]`

Renders a conditional passkey setup prompt for logged-in, eligible users.

Supported attributes:
- `title`
- `message`
- `button_label`
- `class`
- `force_show`

```text
[pkflow_passkey_prompt title="Secure your account" button_label="Set up passkey"]
```

### Integration Shortcodes

These are registered only when the related plugin is active and its module is enabled:

- `[pkflow_woocommerce_login]`
- `[pkflow_edd_login]`
- `[pkflow_memberpress_login]`
- `[pkflow_ultimate_member_login]`
- `[pkflow_learndash_login]`
- `[pkflow_buddyboss_login]`
- `[pkflow_gravityforms_login]`
- `[pkflow_pmp_login]`

### Integration Gutenberg Blocks

These are registered only when the related plugin is active and its module is enabled:

- `advanced-passkey-login/woocommerce-login-card`
- `advanced-passkey-login/edd-login-card`
- `advanced-passkey-login/memberpress-login-card`
- `advanced-passkey-login/ultimate-member-login-card`
- `advanced-passkey-login/learndash-login-card`
- `advanced-passkey-login/buddyboss-login-card`
- `advanced-passkey-login/gravityforms-login-card`
- `advanced-passkey-login/pmp-login-card`

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
./vendor/bin/phpcs --standard=WordPress includes/ admin/ advanced-passkey-login.php
```

### Generating a release zip (local)

```bash
PLUGIN_SLUG="advanced-passkey-login"
DIST_DIR="dist"
BUILD_ROOT="${DIST_DIR}/${PLUGIN_SLUG}"
rm -rf "${DIST_DIR}"
mkdir -p "${BUILD_ROOT}"
cp -R admin includes languages vendor "${BUILD_ROOT}/"
cp index.php advanced-passkey-login.php readme.txt uninstall.php composer.json composer.lock "${BUILD_ROOT}/"
(cd "${DIST_DIR}" && zip -r "${PLUGIN_SLUG}.zip" "${PLUGIN_SLUG}")
```

The GitHub release workflow uses the same packaging structure and produces a single installable `advanced-passkey-login.zip`.

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

### Unreleased
- Added Dashboard tab with an Authenticator Overview card
- Added Last Login activity card in the Dashboard tab

### 1.1.0
- Users list passkey-count column
- Dismissible admin notice for eligible users with no passkeys
- Daily cron cleanup (expired rate limits + old log entries)
- Challenge TTL setting (30–600 s)
- Login redirect URL setting
- `[pkflow_login_button]` and `[pkflow_register_button]` shortcodes

### 1.0.0
- Initial release

---

## License

Licensed under the [GNU General Public License v2 or later](https://www.gnu.org/licenses/gpl-2.0.html).
