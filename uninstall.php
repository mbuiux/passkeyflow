<?php
/**
 * Runs when the plugin is deleted from the WordPress admin (Plugins > Delete).
 * Removes all plugin data: DB tables and wp_options entries.
 *
 * This file is only executed when the user explicitly deletes the plugin and
 * has opted in via the standard WordPress uninstall process.
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
function pkflow_uninstall_cleanup_current_blog(): void {
    global $wpdb;

    // Drop custom tables
    $wpdb->query( 'DROP TABLE IF EXISTS ' . $wpdb->prefix . 'pkflow_credentials' ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery
    $wpdb->query( 'DROP TABLE IF EXISTS ' . $wpdb->prefix . 'pkflow_rate_limits' );    // phpcs:ignore WordPress.DB.DirectDatabaseQuery
    $wpdb->query( 'DROP TABLE IF EXISTS ' . $wpdb->prefix . 'pkflow_logs' );        // phpcs:ignore WordPress.DB.DirectDatabaseQuery

    // Remove all plugin options
    $options = array(
        'pkflow_enabled',
        'pkflow_show_separator',
        'pkflow_show_setup_notice',
        'pkflow_eligible_roles',
        'pkflow_max_passkeys_per_user',
        'pkflow_user_verification',
        'pkflow_rp_id',
        'pkflow_rate_limit_window',
        'pkflow_rate_limit_max_failures',
        'pkflow_rate_limit_lockout',
        'pkflow_rate_window',
        'pkflow_rate_max_attempts',
        'pkflow_rate_lockout',
        'pkflow_challenge_ttl',
        'pkflow_login_challenge_ttl',
        'pkflow_registration_challenge_ttl',
        'pkflow_login_redirect',
        'pkflow_log_retention_days',
        'pkflow_rp_name',
        'pkflow_credentials_schema_v2',
    );

    foreach ( $options as $option ) {
        delete_option( $option );
        // Remove legacy option keys from earlier prefixing as well.
        if ( str_starts_with( $option, 'pkflow_' ) ) {
            delete_option( 'wpk_' . substr( $option, 7 ) );
        }
    }

    // Remove per-user dismissed-notice meta
    $wpdb->query( // phpcs:ignore WordPress.DB.DirectDatabaseQuery
        "DELETE FROM {$wpdb->usermeta} WHERE meta_key LIKE 'pkflow\_notice\_dismissed\_%' OR meta_key LIKE 'wpk\_notice\_dismissed\_%'"
    );

    // Remove any transients left behind
    $wpdb->query( // phpcs:ignore WordPress.DB.DirectDatabaseQuery
        "DELETE FROM {$wpdb->options} WHERE option_name LIKE '_transient_pkflow_%' OR option_name LIKE '_transient_timeout_pkflow_%' OR option_name LIKE '_transient_wpk_%' OR option_name LIKE '_transient_timeout_wpk_%'"
    );
}

if ( is_multisite() ) {
    $pkflow_current_blog_id = get_current_blog_id();

    $page     = 1;
    $per_page = 200;

    do {
        $pkflow_site_ids = get_sites( array(
            'fields' => 'ids',
            'number' => $per_page,
            'paged'  => $page,
        ) );

        foreach ( $pkflow_site_ids as $pkflow_site_id ) {
            switch_to_blog( (int) $pkflow_site_id );
            pkflow_uninstall_cleanup_current_blog();
            restore_current_blog();
        }

        $page++;
    } while ( ! empty( $pkflow_site_ids ) );

    if ( get_current_blog_id() !== (int) $pkflow_current_blog_id ) {
        switch_to_blog( (int) $pkflow_current_blog_id );
        restore_current_blog();
    }
} else {
    pkflow_uninstall_cleanup_current_blog();
}
