<?php
/**
 * Runs when the plugin is deleted from the WordPress admin (Plugins > Delete).
 * Removes all plugin data: DB tables and wp_options entries.
 *
 * This file is only executed when the user explicitly deletes the plugin and
 * has opted in via the standard WordPress uninstall process.
 *
 * @package ADVAPAFO
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

if ( ! defined( 'WP_UNINSTALL_PLUGIN' ) ) {
	exit;
}

global $wpdb;

/**
 * Remove all plugin data from the current blog context.
 */
function advapafo_uninstall_cleanup_current_blog(): void {
	global $wpdb;

	// Drop custom tables.
	$wpdb->query( 'DROP TABLE IF EXISTS ' . $wpdb->prefix . 'advapafo_credentials' ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery
	$wpdb->query( 'DROP TABLE IF EXISTS ' . $wpdb->prefix . 'advapafo_rate_limits' );    // phpcs:ignore WordPress.DB.DirectDatabaseQuery
	$wpdb->query( 'DROP TABLE IF EXISTS ' . $wpdb->prefix . 'advapafo_logs' );        // phpcs:ignore WordPress.DB.DirectDatabaseQuery

	// Remove all plugin options.
	$options = array(
		'advapafo_enabled',
		'advapafo_show_separator',
		'advapafo_show_setup_notice',
		'advapafo_eligible_roles',
		'advapafo_max_passkeys_per_user',
		'advapafo_user_verification',
		'advapafo_rp_id',
		'advapafo_rate_limit_window',
		'advapafo_rate_limit_max_failures',
		'advapafo_rate_limit_lockout',
		'advapafo_rate_window',
		'advapafo_rate_max_attempts',
		'advapafo_rate_lockout',
		'advapafo_challenge_ttl',
		'advapafo_login_challenge_ttl',
		'advapafo_registration_challenge_ttl',
		'advapafo_login_redirect',
		'advapafo_log_retention_days',
		'advapafo_rp_name',
		'advapafo_credentials_schema_v2',
	);

	foreach ( $options as $option ) {
		delete_option( $option );
	}

	// Remove per-user dismissed-notice meta.
	$wpdb->query( // phpcs:ignore WordPress.DB.DirectDatabaseQuery
		"DELETE FROM {$wpdb->usermeta} WHERE meta_key LIKE 'advapafo\_notice\_dismissed\_%'"
	);

	// Remove any transients left behind.
	$wpdb->query( // phpcs:ignore WordPress.DB.DirectDatabaseQuery
		"DELETE FROM {$wpdb->options} WHERE option_name LIKE '_transient_advapafo_%' OR option_name LIKE '_transient_timeout_advapafo_%'"
	);
}

if ( is_multisite() ) {
	$advapafo_current_blog_id = get_current_blog_id();

	$advapafo_site_page     = 1;
	$advapafo_site_per_page = 200;

	do {
		$advapafo_site_ids = get_sites(
			array(
				'fields' => 'ids',
				'number' => $advapafo_site_per_page,
				'paged'  => $advapafo_site_page,
			)
		);

		foreach ( $advapafo_site_ids as $advapafo_site_id ) {
			switch_to_blog( (int) $advapafo_site_id );
			advapafo_uninstall_cleanup_current_blog();
			restore_current_blog();
		}

			++$advapafo_site_page;
	} while ( ! empty( $advapafo_site_ids ) );

	if ( get_current_blog_id() !== (int) $advapafo_current_blog_id ) {
		switch_to_blog( (int) $advapafo_current_blog_id );
		restore_current_blog();
	}
} else {
	advapafo_uninstall_cleanup_current_blog();
}
