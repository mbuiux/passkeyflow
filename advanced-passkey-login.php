<?php
/**
 * Plugin Name: Advanced Passkeys for Secure Login
 * Plugin URI:  https://wordpress.org/plugins/advanced-passkey-login/
 * Description: Advanced Passkeys for Secure Login enables passwordless passkey login for WordPress. Supports Face ID, Touch ID, Windows Hello, YubiKey, and more.
 * Version:     1.1.4
 * Author:      mbuiux
 * Author URI:  https://profiles.wordpress.org/mbuiux/
 * License:     GPL v2 or later
 * License URI: https://www.gnu.org/licenses/gpl-2.0.html
 * Text Domain: advanced-passkey-login
 * Domain Path: /languages
 * Requires at least: 6.0
 * Tested up to: 6.9
 * Requires PHP: 8.0
 *
 * @package PKFLOW
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

define( 'PKFLOW_VERSION', '1.1.4' );
define( 'PKFLOW_PLUGIN_FILE', __FILE__ );
define( 'PKFLOW_PLUGIN_DIR', plugin_dir_path( __FILE__ ) );
define( 'PKFLOW_PLUGIN_URL', plugin_dir_url( __FILE__ ) );

// Allow env-based constant injection (same pattern used in planning-center-sso).
// phpcs:disable WordPress.NamingConventions.PrefixAllGlobals.VariableConstantNameFound -- dynamic constant names are constrained to PKFLOW_* entries in this allowlist.
foreach ( array(
	'PKFLOW_ALLOW_HTTP',
	'PKFLOW_RP_ID',
	'PKFLOW_RP_NAME',
	'PKFLOW_CHALLENGE_TTL',
	'PKFLOW_USER_VERIFICATION',
	'PKFLOW_RATE_WINDOW',
	'PKFLOW_RATE_MAX_ATTEMPTS',
	'PKFLOW_RATE_LOCKOUT',
	'PKFLOW_ENABLE_LOGGING',
) as $pkflow_env_const ) {
	if ( ! defined( $pkflow_env_const ) ) {
		$pkflow_env_value = getenv( $pkflow_env_const );
		if ( false !== $pkflow_env_value && '' !== $pkflow_env_value ) {
			define( $pkflow_env_const, $pkflow_env_value );
		}
	}
}
// phpcs:enable WordPress.NamingConventions.PrefixAllGlobals.VariableConstantNameFound
unset( $pkflow_env_const, $pkflow_env_value );

// ──────────────────────────────────────────────────────────────
// Composer autoload (lbuchs/webauthn)
// ──────────────────────────────────────────────────────────────
$pkflow_autoload = PKFLOW_PLUGIN_DIR . 'vendor/autoload.php';
if ( PHP_VERSION_ID >= 80000 && file_exists( $pkflow_autoload ) ) {
	$pkflow_should_load_autoloader = true;

	$pkflow_autoload_real = PKFLOW_PLUGIN_DIR . 'vendor/composer/autoload_real.php';
	if ( file_exists( $pkflow_autoload_real ) ) {
		$pkflow_autoload_real_src = file_get_contents( $pkflow_autoload_real ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents -- local filesystem read for composer class detection.
		if ( is_string( $pkflow_autoload_real_src ) && preg_match( '/class\s+(ComposerAutoloaderInit[0-9a-fA-F_]+)/', $pkflow_autoload_real_src, $m ) ) {
			if ( ! empty( $m[1] ) && class_exists( (string) $m[1], false ) ) {
				$pkflow_should_load_autoloader = false;
			}
		}
	}

	if ( $pkflow_should_load_autoloader ) {
		require_once $pkflow_autoload;
	}
}
unset( $pkflow_autoload, $pkflow_should_load_autoloader, $pkflow_autoload_real, $pkflow_autoload_real_src );

/**
 * Run one-time option normalization tasks for pkflow_* keys.
 */
function pkflow_migrate_legacy_options_once(): void {
	if ( (int) get_option( 'pkflow_legacy_options_migrated_v1', 0 ) === 1 ) {
		return;
	}

	// Legacy free builds commonly stored a default cap of 5; move to unlimited.
	$legacy_cap = (int) get_option( 'pkflow_max_passkeys_per_user', 0 );
	if ( 5 === $legacy_cap ) {
		update_option( 'pkflow_max_passkeys_per_user', 0 );
	}

	update_option( 'pkflow_legacy_options_migrated_v1', 1, false );
}

/**
 * Ensure passkey cap defaults to unlimited for existing installs migrated earlier.
 */
function pkflow_remove_legacy_passkey_cap_once(): void {
	if ( (int) get_option( 'pkflow_cap_migrated_v1', 0 ) === 1 ) {
		return;
	}

	if ( (int) get_option( 'pkflow_max_passkeys_per_user', 0 ) === 5 ) {
		update_option( 'pkflow_max_passkeys_per_user', 0 );
	}

	update_option( 'pkflow_cap_migrated_v1', 1, false );
}

// ──────────────────────────────────────────────────────────────
// Load classes
// ──────────────────────────────────────────────────────────────
require_once PKFLOW_PLUGIN_DIR . 'includes/class-pkflow-passkeys.php';
require_once PKFLOW_PLUGIN_DIR . 'includes/class-pkflow-settings.php';
require_once PKFLOW_PLUGIN_DIR . 'includes/class-pkflow-login-form.php';
require_once PKFLOW_PLUGIN_DIR . 'includes/class-pkflow-shortcodes.php';
require_once PKFLOW_PLUGIN_DIR . 'includes/class-pkflow-integration-manager.php';

// ──────────────────────────────────────────────────────────────
// Bootstrap
// ──────────────────────────────────────────────────────────────
/**
 * Initialize plugin services after core/plugin load.
 */
function pkflow_init() {
	pkflow_migrate_legacy_options_once();
	pkflow_remove_legacy_passkey_cap_once();

	new PKFLOW_Passkeys();
	new PKFLOW_Login_Form();
	new PKFLOW_Shortcodes();
	new PKFLOW_Integration_Manager();

	if ( is_admin() ) {
		new PKFLOW_Settings();
	}
}
add_action( 'plugins_loaded', 'pkflow_init' );

/**
 * Detect whether the plugin is network-activated.
 */
function pkflow_is_network_active(): bool {
	if ( ! is_multisite() ) {
		return false;
	}

	$active = (array) get_site_option( 'active_sitewide_plugins', array() );
	return isset( $active[ plugin_basename( PKFLOW_PLUGIN_FILE ) ] );
}

/**
 * Run a callback for current site or across the whole network.
 *
 * @param bool     $network_wide Whether the plugin is network-activated.
 * @param callable $callback     Callback to run for each relevant site.
 */
function pkflow_for_each_site( bool $network_wide, callable $callback ): void {
	if ( ! is_multisite() || ! $network_wide ) {
		$callback();
		return;
	}

	$original_blog_id = get_current_blog_id();

	$page     = 1;
	$per_page = 200;

	do {
		$site_ids = get_sites(
			array(
				'fields' => 'ids',
				'number' => $per_page,
				'paged'  => $page,
			)
		);

		foreach ( $site_ids as $site_id ) {
			switch_to_blog( (int) $site_id );
			$callback();
			restore_current_blog();
		}

		++$page;
	} while ( ! empty( $site_ids ) );

	if ( get_current_blog_id() !== (int) $original_blog_id ) {
		switch_to_blog( (int) $original_blog_id );
		restore_current_blog();
	}
}

// ──────────────────────────────────────────────────────────────
// Activation / deactivation
// ──────────────────────────────────────────────────────────────
register_activation_hook( __FILE__, 'pkflow_activate' );
register_deactivation_hook( __FILE__, 'pkflow_deactivate' );

/**
 * Activation routine.
 *
 * @param bool $network_wide Whether plugin is being activated network-wide.
 */
function pkflow_activate( bool $network_wide = false ) {
	if ( version_compare( PHP_VERSION, '8.0', '<' ) ) {
		deactivate_plugins( plugin_basename( PKFLOW_PLUGIN_FILE ) );
		wp_die( esc_html__( 'Advanced Passkeys for Secure Login requires PHP 8.0 or higher. Please upgrade PHP before activating this plugin.', 'advanced-passkey-login' ) );
	}
	if ( version_compare( $GLOBALS['wp_version'], '6.0', '<' ) ) {
		deactivate_plugins( plugin_basename( PKFLOW_PLUGIN_FILE ) );
		wp_die( esc_html__( 'Advanced Passkeys for Secure Login requires WordPress 6.0 or higher. Please update WordPress before activating this plugin.', 'advanced-passkey-login' ) );
	}

	require_once PKFLOW_PLUGIN_DIR . 'includes/class-pkflow-passkeys.php';

	pkflow_for_each_site(
		$network_wide,
		static function (): void {
			PKFLOW_Passkeys::create_tables();
			PKFLOW_Passkeys::schedule_cron();
		}
	);

	flush_rewrite_rules();
}

/**
 * Deactivation routine.
 *
 * @param bool $network_wide Whether plugin is being deactivated network-wide.
 */
function pkflow_deactivate( bool $network_wide = false ) {
	require_once PKFLOW_PLUGIN_DIR . 'includes/class-pkflow-passkeys.php';

	pkflow_for_each_site(
		$network_wide,
		static function (): void {
			PKFLOW_Passkeys::unschedule_cron();
		}
	);

	// Nothing else to tear down on deactivation; tables are preserved until uninstall.
}

/**
 * Provision plugin tables/cron when a new site is created on multisite.
 *
 * @param WP_Site $new_site The newly provisioned site.
 */
function pkflow_multisite_initialize_site( WP_Site $new_site ): void {
	if ( ! pkflow_is_network_active() ) {
		return;
	}

	require_once PKFLOW_PLUGIN_DIR . 'includes/class-pkflow-passkeys.php';

	switch_to_blog( (int) $new_site->blog_id );
	PKFLOW_Passkeys::create_tables();
	PKFLOW_Passkeys::schedule_cron();
	restore_current_blog();
}
add_action( 'wp_initialize_site', 'pkflow_multisite_initialize_site' );

// ──────────────────────────────────────────────────────────────
// Settings link on Plugins page
// ──────────────────────────────────────────────────────────────
add_filter(
	'plugin_action_links_' . plugin_basename( __FILE__ ),
	function ( $links ) {
		$url = admin_url( 'options-general.php?page=advanced-passkey-login' );
		array_unshift( $links, sprintf( '<a href="%s">%s</a>', esc_url( $url ), esc_html__( 'Settings', 'advanced-passkey-login' ) ) );
		return $links;
	}
);

add_filter(
	'plugin_row_meta',
	function ( $links, $file ) {
		if ( plugin_basename( __FILE__ ) !== $file ) {
			return $links;
		}

		$links[] = sprintf(
			'<a href="%s" target="_blank" rel="noopener noreferrer">%s</a>',
			esc_url( 'https://profiles.wordpress.org/mbuiux/' ),
			esc_html__( 'Author: mbuiux', 'advanced-passkey-login' )
		);
		$links[] = sprintf(
			'<a href="%s" target="_blank" rel="noopener noreferrer">%s</a>',
			esc_url( 'https://wordpress.org/plugins/advanced-passkey-login/' ),
			esc_html__( 'Plugin Page', 'advanced-passkey-login' )
		);

		return $links;
	},
	10,
	2
);

// ──────────────────────────────────────────────────────────────
// Security notice for dev-only flags
// ──────────────────────────────────────────────────────────────
add_action(
	'admin_notices',
	function () {
		if ( ! is_admin() || ! current_user_can( 'manage_options' ) ) {
			return;
		}
		$warnings = array();
		if ( defined( 'PKFLOW_ALLOW_HTTP' ) && PKFLOW_ALLOW_HTTP ) {
			$warnings[] = '<strong>PKFLOW_ALLOW_HTTP</strong> is enabled — insecure transport is allowed. Disable in production.';
		}
		if ( empty( $warnings ) ) {
			return;
		}
		echo '<div class="notice notice-error"><p><strong>Advanced Passkeys for Secure Login security warning:</strong></p><ul>';
		foreach ( $warnings as $w ) {
			echo '<li>' . wp_kses( $w, array( 'strong' => array() ) ) . '</li>';
		}
		echo '</ul></div>';
	}
);
