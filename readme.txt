=== WP Passkey ===
Contributors: markbest
Tags: passkeys, webauthn, fido2, passwordless, authentication, login, security, biometric
Requires at least: 6.0
Tested up to: 6.8
Stable tag: 1.1.0
Requires PHP: 8.0
License: GPLv2 or later
License URI: https://www.gnu.org/licenses/gpl-2.0.html

Free / Lite version — let users sign in with Face ID, Touch ID, Windows Hello, or a security key, no password required. Upgrade to [WP Passkey Pro](https://wppasskey.com/pro) for unlimited passkeys, WooCommerce integration, audit logs, and more.

== Description ==

**WP Passkey** brings the FIDO2 / WebAuthn passkey standard to WordPress. Users register a passkey once — using their device's biometric sensor (Face ID, Touch ID, fingerprint) or a hardware security key — and then sign in instantly with no password needed.

Passkeys are phishing-resistant by design. There is no password to steal, no credential to replay, and no username/password form to brute-force.

= Key features (Lite) =

* One-click "Sign in with Passkey" button on the WordPress login screen
* Register and manage passkeys from your user profile page
* Supports Face ID, Touch ID, Windows Hello, YubiKey, iCloud Keychain, and Google Password Manager
* Per-user passkey cap (up to 5 in Lite)
* Configurable eligible roles (default: administrators)
* Built-in brute-force protection with configurable rate limiting
* Clean uninstall — no orphaned tables or options left behind

= WP Passkey Pro =

[WP Passkey Pro](https://wppasskey.com/pro) removes all Lite limits and adds:

* Unlimited passkeys per user
* Passkey-only mode by role (require passkeys, disallow passwords)
* Magic link account recovery flow
* WooCommerce checkout passkey support
* Gutenberg & Elementor shortcode/block
* Device health dashboard
* Full audit log with CSV export
* Conditional access rules (enforce by role, page, or IP range)
* WP-CLI commands
* White-label & agency tools

= Requirements =

* PHP 8.0 or higher
* PHP extensions: `openssl`, `mbstring`, `json` (standard on most hosts)
* HTTPS is required in production (the WebAuthn specification mandates it)

= How it works =

1. A user visits their profile and clicks **Register New Passkey**
2. Their browser prompts them to authenticate with Face ID / Touch ID / Windows Hello / security key
3. A public key is stored in WordPress — no password, no secret is kept on the server
4. On the next login the user clicks **Sign in with Passkey** — verified in milliseconds

== Installation ==

= Automatic installation =

1. In your WordPress admin, go to **Plugins > Add New**
2. Search for **WP Passkey**
3. Click **Install Now** then **Activate**
4. Go to **Settings > WP Passkey** and enable passkeys

= Manual installation =

1. Download the plugin ZIP from WordPress.org
2. Go to **Plugins > Add New > Upload Plugin** and upload the ZIP
3. Click **Activate**
4. Go to **Settings > WP Passkey** and enable passkeys

= After activation =

1. Go to **Settings > WP Passkey** — verify passkeys are enabled and select which roles may use them
2. Visit **Users > Your Profile** and register your first passkey
3. Sign out and confirm the **Sign in with Passkey** button appears on the login page
4. Register a backup passkey on a second device to avoid lockout

= HTTPS requirement =

Passkeys require a secure (HTTPS) connection. The plugin will display a warning and refuse to serve passkey flows over plain HTTP. If you are testing locally without HTTPS you can add `define( 'WPK_ALLOW_HTTP', true );` to `wp-config.php` — **never use this in production**.

== Frequently Asked Questions ==

= Does this replace passwords entirely? =

No — in Lite, passkeys are an *additional* sign-in method. Users can still use their password. WP Passkey Pro adds an optional "passkey-only" mode per role.

= Which browsers and devices are supported? =

Any browser that supports WebAuthn (all major browsers since 2022): Chrome, Firefox, Safari, Edge. Devices: iPhone / iPad (Face ID / Touch ID), Mac (Touch ID), Android (fingerprint / face), Windows (Windows Hello), and any FIDO2 / U2F hardware security key (YubiKey, Google Titan, etc.).

= Is HTTPS required? =

Yes, in production. The WebAuthn specification only allows passkey operations over a secure context. See the Installation section for local dev instructions.

= What PHP extensions do I need? =

`openssl`, `mbstring`, and `json`. These are enabled by default on every mainstream managed WordPress host.

= Can I control which user roles can use passkeys? =

Yes — in **Settings > WP Passkey > Eligible Roles**. By default only Administrators. WP Passkey Pro extends this to any role including custom ones.

= What happens if I deactivate or delete the plugin? =

Deactivation leaves all data intact. Deletion (uninstall) drops the `wp_wpk_credentials`, `wp_wpk_rate_limits`, and `wp_wpk_logs` tables and removes all `wpk_*` options.

= Is the plugin multisite compatible? =

Tables are created per-site (using `$wpdb->prefix`). Network-wide activation is not officially supported in Lite but each sub-site can activate it independently.

= Can I use a custom RP ID for subdomain setups? =

Yes — add `define( 'WPK_RP_ID', 'example.com' );` to `wp-config.php`.

== Screenshots ==

1. The passkey sign-in button on the WordPress login screen
2. Registering a new passkey from the user profile page
3. The registered passkeys table with revoke action
4. The WP Passkey settings page

== Changelog ==

= 1.1.0 =
* Added: dismissible "set up your passkey" nudge notice for eligible users
* Added: Passkeys column in the admin Users list showing count per user
* Added: Scheduled daily cleanup of expired rate-limit rows and old log entries
* Added: Challenge timeout setting in Settings > WP Passkey > Advanced
* Added: Login redirect URL field in settings (fallback after passkey login)
* Added: `[wpk_login_button]` and `[wpk_register_button]` shortcodes
* Added: Log retention period setting (days)
* Improved: `get_challenge_ttl()` now reads from the settings UI

= 1.0.0 =
* Initial release

== Upgrade Notice ==

= 1.0.0 =
Initial release — no upgrade steps required.
