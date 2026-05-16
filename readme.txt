=== Advanced Passkeys for Secure Login ===
Contributors: wppasskey, mbuiux
Tags: passkeys, webauthn, passwordless, login, security
Requires at least: 6.0
Tested up to: 6.9
Stable tag: 1.1.5
Requires PHP: 8.0
License: GPLv2 or later
License URI: https://www.gnu.org/licenses/gpl-2.0.html

Passwordless passkey login for WordPress using Face ID, Touch ID, Windows Hello, and security keys.

== Description ==

**Advanced Passkeys for Secure Login** brings the FIDO2 / WebAuthn passkey standard to WordPress. Users register a passkey once — using their device's biometric sensor (Face ID, Touch ID, fingerprint) or a hardware security key — and then sign in instantly with no password needed.

Passkeys are phishing-resistant by design. There is no password to steal, no credential to replay, and no username/password form to brute-force.

= Key features =

* One-click "Sign in with Passkey" button on the WordPress login screen
* Register and manage passkeys from your user profile page
* Supports Face ID, Touch ID, Windows Hello, YubiKey, iCloud Keychain, and Google Password Manager
* Includes `[advapafo_passkey_profile]` shortcode for logged-in passkey management UI
* Includes `[advapafo_passkey_prompt]` shortcode for conditional passkey enrollment prompts
* Includes plugin-aware integration modules for WooCommerce, Easy Digital Downloads, MemberPress, Ultimate Member, LearnDash, BuddyBoss, Gravity Forms, and PMPro
* Integration-specific shortcodes and Gutenberg blocks are registered automatically when supported plugins are active
* Integration modules can auto-inject passkey entry points on supported login and checkout surfaces
* Dashboard tab with an Authenticator Overview card for quick visibility into authenticator usage
* Dashboard tab with a Last Login card to surface recent sign-in activity at a glance
* Configurable per-user passkey limit (or no limit)
* Configurable eligible roles (default: administrators)
* Built-in brute-force protection with configurable rate limiting
* Multisite-aware activation and provisioning for newly created network sites
* Clean uninstall — no orphaned tables or options left behind

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
2. Search for **Advanced Passkeys for Secure Login**
3. Click **Install Now** then **Activate**
4. Go to **Settings > Advanced Passkeys for Secure Login** and enable passkeys

= Manual installation =

1. Download the plugin ZIP from WordPress.org
2. Go to **Plugins > Add New > Upload Plugin** and upload the ZIP
3. Click **Activate**
4. Go to **Settings > Advanced Passkeys for Secure Login** and enable passkeys

= After activation =

1. Go to **Settings > Advanced Passkeys for Secure Login** — verify passkeys are enabled and select which roles may use them
2. Visit **Users > Your Profile** and register your first passkey
3. Sign out and confirm the **Sign in with Passkey** button appears on the login page
4. Register a backup passkey on a second device to avoid lockout

= HTTPS requirement =

Passkeys require a secure (HTTPS) connection. The plugin will display a warning and refuse to serve passkey flows over plain HTTP. If you are testing locally without HTTPS you can add `define( 'ADVAPAFO_ALLOW_HTTP', true );` to `wp-config.php` — **never use this in production**.

== Frequently Asked Questions ==

= Does this replace passwords entirely? =

No — passkeys are an *additional* sign-in method. Users can still use their password.

= Which browsers and devices are supported? =

Any browser that supports WebAuthn (all major browsers since 2022): Chrome, Firefox, Safari, Edge. Devices: iPhone / iPad (Face ID / Touch ID), Mac (Touch ID), Android (fingerprint / face), Windows (Windows Hello), and any FIDO2 / U2F hardware security key (YubiKey, Google Titan, etc.).

= Is HTTPS required? =

Yes, in production. The WebAuthn specification only allows passkey operations over a secure context. See the Installation section for local dev instructions.

= What PHP extensions do I need? =

`openssl`, `mbstring`, and `json`. These are enabled by default on every mainstream managed WordPress host.

= Can I control which user roles can use passkeys? =

Yes — in **Settings > Advanced Passkeys for Secure Login > Eligible Roles**. By default, only Administrators are selected, and you can enable passkeys for any WordPress role, including custom roles.

= Which shortcodes are available? =

Core shortcodes:
* `[advapafo_login_button]`
* `[advapafo_register_button]`
* `[advapafo_passkey_profile]`
* `[advapafo_passkey_prompt]`

Integration shortcodes (registered when the related plugin is active and the module is enabled):
* `[advapafo_woocommerce_login]`
* `[advapafo_edd_login]`
* `[advapafo_memberpress_login]`
* `[advapafo_ultimate_member_login]`
* `[advapafo_learndash_login]`
* `[advapafo_buddyboss_login]`
* `[advapafo_gravityforms_login]`
* `[advapafo_pmp_login]`

= Which integration Gutenberg blocks are available? =

When a supported integration plugin is active and enabled, Advanced Passkeys for Secure Login can register:
* `advanced-passkey-login/woocommerce-login-card`
* `advanced-passkey-login/edd-login-card`
* `advanced-passkey-login/memberpress-login-card`
* `advanced-passkey-login/ultimate-member-login-card`
* `advanced-passkey-login/learndash-login-card`
* `advanced-passkey-login/buddyboss-login-card`
* `advanced-passkey-login/gravityforms-login-card`
* `advanced-passkey-login/pmp-login-card`

= What happens if I deactivate or delete the plugin? =

Deactivation leaves all data intact. Deletion (uninstall) drops the `wp_wpk_credentials`, `wp_wpk_rate_limits`, and `wp_wpk_logs` tables and removes all `advapafo_*` options.

= Is the plugin multisite compatible? =

Yes. Tables are created per-site (using `$wpdb->prefix`) and network activation provisions each site. New sites created on a network are automatically provisioned when the plugin is network-active.

= Can I use a custom RP ID for subdomain setups? =

Yes — add `define( 'ADVAPAFO_RP_ID', 'example.com' );` to `wp-config.php`.

== Screenshots ==

1. The passkey sign-in button on the WordPress login screen
2. Registering a new passkey from the user profile page
3. The registered passkeys table with revoke action
4. The Advanced Passkeys for Secure Login settings page

== Changelog ==

= 1.1.5 =
* Improved: sanitize-early handling for transports and credential request inputs
* Improved: stricter nonce-gated debug query handling in settings
* Improved: output escaping hardening for integration-rendered markup and dynamic admin classes
* Improved: release and quality workflow validation guardrails (actionlint gate)

= 1.1.4 =
* Added: Dashboard tab with an Authenticator Overview card
* Added: Last Login activity card in the Dashboard tab
* Improved: nonce and capability enforcement across sensitive request handlers
* Improved: release packaging workflow with strict file allowlist validation
* Fixed: release automation now publishes real GitHub releases with attached installable ZIP

= 1.1.2 =
* Added: integration manager for popular ecosystem plugins with dependency-aware module loading
* Added: integration-specific shortcodes and Gutenberg blocks
* Added: integration controls in settings with installed/not installed indicators
* Added: shortcode quick-start helper and improved shortcode documentation in admin UI
* Changed: removed legacy shortcode alias registrations and related legacy copy
* Changed: refreshed docs and translation template strings for current shortcode names

= 1.1.1 =
* Updated: plugin name and user-facing references to "Advanced Passkeys for Secure Login"
* Updated: settings/UI copy to use the full plugin name

= 1.1.0 =
* Added: dismissible "set up your passkey" nudge notice for eligible users
* Added: Passkeys column in the admin Users list showing count per user
* Added: Scheduled daily cleanup of expired rate-limit rows and old log entries
* Added: Challenge timeout setting in Settings > Advanced Passkeys for Secure Login > Advanced
* Added: Login redirect URL field in settings (fallback after passkey login)
* Added: `[advapafo_login_button]` and `[advapafo_register_button]` shortcodes
* Added: Log retention period setting (days)
* Improved: `get_challenge_ttl()` now reads from the settings UI

= 1.0.0 =
* Initial release

== Upgrade Notice ==

= 1.1.5 =
Recommended update: strengthens sanitize/validate/escape protections and improves CI workflow safety checks.

= 1.1.4 =
Recommended update: adds dashboard visibility, hardens request validation, and improves release packaging quality gates.

= 1.1.2 =
Recommended update: adds integration module controls, Gutenberg block support, and shortcode UX improvements.
