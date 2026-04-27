<?php
/**
 * Plugin Name: WP Passkey
 * Plugin URI:  https://wppasskey.com
 * Description: Passwordless passkey login for WordPress (free / Lite). Supports Face ID, Touch ID, Windows Hello, YubiKey, and more. Upgrade to WP Passkey Pro for unlimited passkeys, WooCommerce support, audit logs, and advanced access controls.
 * Version:     1.1.0
 * Author:      WP Passkey
 * Author URI:  https://wppasskey.com
 * License:     GPL v2 or later
 * License URI: https://www.gnu.org/licenses/gpl-2.0.html
 * Text Domain: wp-passkeys
 * Domain Path: /languages
 * Requires at least: 6.0
 * Tested up to: 6.8
 * Requires PHP: 8.0
 */

if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

define( 'WPK_VERSION',     '1.1.0' );
define( 'WPK_PLUGIN_FILE', __FILE__ );
define( 'WPK_PLUGIN_DIR',  plugin_dir_path( __FILE__ ) );
define( 'WPK_PLUGIN_URL',  plugin_dir_url( __FILE__ ) );

// Allow env-based constant injection (same pattern used in planning-center-sso).
foreach ( array( 'WPK_ALLOW_HTTP', 'WPK_RP_ID', 'WPK_RP_NAME', 'WPK_CHALLENGE_TTL', 'WPK_USER_VERIFICATION',
                 'WPK_RATE_WINDOW', 'WPK_RATE_MAX_ATTEMPTS', 'WPK_RATE_LOCKOUT', 'WPK_ENABLE_LOGGING' ) as $_wpk_const ) {
    if ( ! defined( $_wpk_const ) ) {
        $v = getenv( $_wpk_const );
        if ( $v !== false && $v !== '' ) {
            define( $_wpk_const, $v );
        }
    }
}
unset( $_wpk_const, $v );

// ──────────────────────────────────────────────────────────────
// Composer autoload (lbuchs/webauthn)
// ──────────────────────────────────────────────────────────────
$_wpk_autoload = WPK_PLUGIN_DIR . 'vendor/autoload.php';
if ( PHP_VERSION_ID >= 80000 && file_exists( $_wpk_autoload ) ) {
    require_once $_wpk_autoload;
}
unset( $_wpk_autoload );

// ──────────────────────────────────────────────────────────────
// Load classes
// ──────────────────────────────────────────────────────────────
require_once WPK_PLUGIN_DIR . 'includes/class-wpk-passkeys.php';
require_once WPK_PLUGIN_DIR . 'includes/class-wpk-settings.php';
require_once WPK_PLUGIN_DIR . 'includes/class-wpk-login-form.php';
require_once WPK_PLUGIN_DIR . 'includes/class-wpk-shortcodes.php';

// ──────────────────────────────────────────────────────────────
// Bootstrap
// ──────────────────────────────────────────────────────────────
function wpk_init() {
    load_plugin_textdomain( 'wp-passkeys', false, dirname( plugin_basename( WPK_PLUGIN_FILE ) ) . '/languages' );

    new WPK_Passkeys();
    new WPK_Login_Form();
    new WPK_Shortcodes();

    if ( is_admin() ) {
        new WPK_Settings();
    }
}
add_action( 'plugins_loaded', 'wpk_init' );

/**
 * Detect whether the plugin is network-activated.
 */
function wpk_is_network_active(): bool {
    if ( ! is_multisite() ) {
        return false;
    }

    $active = (array) get_site_option( 'active_sitewide_plugins', array() );
    return isset( $active[ plugin_basename( WPK_PLUGIN_FILE ) ] );
}

/**
 * Run a callback for current site or across the whole network.
 */
function wpk_for_each_site( bool $network_wide, callable $callback ): void {
    if ( ! is_multisite() || ! $network_wide ) {
        $callback();
        return;
    }

    $original_blog_id = get_current_blog_id();

    $page     = 1;
    $per_page = 200;

    do {
        $site_ids = get_sites( array(
            'fields' => 'ids',
            'number' => $per_page,
            'paged'  => $page,
        ) );

        foreach ( $site_ids as $site_id ) {
            switch_to_blog( (int) $site_id );
            $callback();
            restore_current_blog();
        }

        $page++;
    } while ( ! empty( $site_ids ) );

    if ( get_current_blog_id() !== (int) $original_blog_id ) {
        switch_to_blog( (int) $original_blog_id );
        restore_current_blog();
    }
}

// ──────────────────────────────────────────────────────────────
// Activation / deactivation
// ──────────────────────────────────────────────────────────────
register_activation_hook( __FILE__, 'wpk_activate' );
register_deactivation_hook( __FILE__, 'wpk_deactivate' );

function wpk_activate( bool $network_wide = false ) {
    if ( version_compare( PHP_VERSION, '8.0', '<' ) ) {
        deactivate_plugins( plugin_basename( WPK_PLUGIN_FILE ) );
        wp_die( esc_html__( 'WP Passkey requires PHP 8.0 or higher. Please upgrade PHP before activating this plugin.', 'wp-passkeys' ) );
    }
    if ( version_compare( $GLOBALS['wp_version'], '6.0', '<' ) ) {
        deactivate_plugins( plugin_basename( WPK_PLUGIN_FILE ) );
        wp_die( esc_html__( 'WP Passkey requires WordPress 6.0 or higher. Please update WordPress before activating this plugin.', 'wp-passkeys' ) );
    }

    require_once WPK_PLUGIN_DIR . 'includes/class-wpk-passkeys.php';

    wpk_for_each_site( $network_wide, static function (): void {
        WPK_Passkeys::create_tables();
        WPK_Passkeys::schedule_cron();
    } );

    flush_rewrite_rules();
}

function wpk_deactivate( bool $network_wide = false ) {
    require_once WPK_PLUGIN_DIR . 'includes/class-wpk-passkeys.php';

    wpk_for_each_site( $network_wide, static function (): void {
        WPK_Passkeys::unschedule_cron();
    } );

    // Nothing else to tear down on deactivation; tables are preserved until uninstall.
}

/**
 * Provision plugin tables/cron when a new site is created on multisite.
 */
function wpk_multisite_initialize_site( WP_Site $new_site ): void {
    if ( ! wpk_is_network_active() ) {
        return;
    }

    require_once WPK_PLUGIN_DIR . 'includes/class-wpk-passkeys.php';

    switch_to_blog( (int) $new_site->blog_id );
    WPK_Passkeys::create_tables();
    WPK_Passkeys::schedule_cron();
    restore_current_blog();
}
add_action( 'wp_initialize_site', 'wpk_multisite_initialize_site' );

// ──────────────────────────────────────────────────────────────
// Settings link on Plugins page
// ──────────────────────────────────────────────────────────────
add_filter( 'plugin_action_links_' . plugin_basename( __FILE__ ), function ( $links ) {
    $url  = admin_url( 'options-general.php?page=wp-passkeys' );
    array_unshift( $links, sprintf( '<a href="%s">%s</a>', esc_url( $url ), esc_html__( 'Settings', 'wp-passkeys' ) ) );
    return $links;
} );

// ──────────────────────────────────────────────────────────────
// Security notice for dev-only flags
// ──────────────────────────────────────────────────────────────
add_action( 'admin_notices', function () {
    if ( ! is_admin() || ! current_user_can( 'manage_options' ) ) {
        return;
    }
    $warnings = array();
    if ( defined( 'WPK_ALLOW_HTTP' ) && WPK_ALLOW_HTTP ) {
        $warnings[] = '<strong>WPK_ALLOW_HTTP</strong> is enabled — insecure transport is allowed. Disable in production.';
    }
    if ( empty( $warnings ) ) {
        return;
    }
    echo '<div class="notice notice-error"><p><strong>WP Passkey security warning:</strong></p><ul>';
    foreach ( $warnings as $w ) {
        echo '<li>' . wp_kses( $w, array( 'strong' => array() ) ) . '</li>';
    }
    echo '</ul></div>';
} );
