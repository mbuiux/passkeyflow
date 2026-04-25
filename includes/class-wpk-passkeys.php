<?php
/**
 * WPK_Passkeys — core WebAuthn engine.
 *
 * Handles:
 *  - DB table creation (credentials + rate limits)
 *  - AJAX endpoints for registration, login, revocation
 *  - Rate limiting
 *  - User eligibility (configurable by role; Pro-extensible via filter)
 *  - Per-user passkey cap (Lite: max 5; Pro: extend via filter)
 *
 * Pro extension points (filters / actions):
 *  - Filter  wpk_is_eligible_user          ( bool, WP_User )
 *  - Filter  wpk_max_passkeys_per_user      ( int,  WP_User )
 *  - Filter  wpk_login_redirect             ( string redirect_url, WP_User )
 *  - Action  wpk_passkey_registered         ( int user_id, string credential_hash )
 *  - Action  wpk_passkey_login_success      ( int user_id, string credential_hash, string device_info )
 *  - Action  wpk_passkey_revoked            ( int user_id, int credential_id )
 */

if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

use lbuchs\WebAuthn\Binary\ByteBuffer;
use lbuchs\WebAuthn\WebAuthn;

class WPK_Passkeys {

    const TABLE_CREDENTIALS = 'wpk_credentials';
    const TABLE_RATE_LIMITS  = 'wpk_rate_limits';
    const LITE_MAX_PASSKEYS  = 5;

    // ──────────────────────────────────────────────────────────
    // Boot
    // ──────────────────────────────────────────────────────────

    public static function is_enabled(): bool {
        if ( defined( 'WPK_ENABLED' ) ) {
            return (bool) WPK_ENABLED;
        }
        return (int) get_option( 'wpk_enabled', 1 ) === 1;
    }

    /**
     * Public static wrapper so shortcodes and external code can check eligibility
     * without instantiating the full class.
     */
    public static function user_is_eligible( WP_User $user ): bool {
        $allowed_roles = (array) get_option( 'wpk_eligible_roles', array( 'administrator' ) );
        $eligible      = apply_filters( 'wpk_is_eligible_user', null, $user );
        if ( $eligible !== null ) {
            return (bool) $eligible;
        }
        return ! empty( array_intersect( (array) $user->roles, $allowed_roles ) );
    }

    public function __construct() {
        if ( ! self::is_enabled() ) {
            return;
        }

        if ( ! class_exists( 'lbuchs\\WebAuthn\\WebAuthn' ) ) {
            add_action( 'admin_notices', array( $this, 'render_missing_dependency_notice' ) );
            return;
        }

        // Profile hooks
        add_action( 'show_user_profile', array( $this, 'render_profile_section' ) );
        add_action( 'edit_user_profile', array( $this, 'render_profile_section' ) );
        add_action( 'admin_enqueue_scripts', array( $this, 'enqueue_profile_assets' ) );

        // Login hooks
        add_action( 'login_enqueue_scripts', array( $this, 'enqueue_login_assets' ) );

        // Admin: Users list column
        add_filter( 'manage_users_columns',       array( $this, 'users_column_header' ) );
        add_filter( 'manage_users_custom_column', array( $this, 'users_column_content' ), 10, 3 );
        add_filter( 'manage_users_sortable_columns', array( $this, 'users_column_sortable' ) );

        // Admin: passkey setup nudge notice
        add_action( 'admin_notices', array( $this, 'render_setup_notice' ) );
        add_action( 'wp_ajax_wpk_dismiss_notice', array( $this, 'ajax_dismiss_notice' ) );

        // Cron: scheduled cleanup
        add_action( 'wpk_scheduled_cleanup', array( $this, 'run_scheduled_cleanup' ) );

        // AJAX — authenticated (registration + revocation)
        add_action( 'wp_ajax_wpk_begin_registration',   array( $this, 'ajax_begin_registration' ) );
        add_action( 'wp_ajax_wpk_finish_registration',  array( $this, 'ajax_finish_registration' ) );
        add_action( 'wp_ajax_wpk_revoke_credential',    array( $this, 'ajax_revoke_credential' ) );

        // AJAX — public + authenticated (login)
        add_action( 'wp_ajax_nopriv_wpk_begin_login',  array( $this, 'ajax_begin_login' ) );
        add_action( 'wp_ajax_wpk_begin_login',          array( $this, 'ajax_begin_login' ) );
        add_action( 'wp_ajax_nopriv_wpk_finish_login', array( $this, 'ajax_finish_login' ) );
        add_action( 'wp_ajax_wpk_finish_login',         array( $this, 'ajax_finish_login' ) );
    }

    // ──────────────────────────────────────────────────────────
    // Database
    // ──────────────────────────────────────────────────────────

    public static function create_tables(): void {
        global $wpdb;
        $charset = $wpdb->get_charset_collate();

        $cred = $wpdb->prefix . self::TABLE_CREDENTIALS;
        $rate = $wpdb->prefix . self::TABLE_RATE_LIMITS;

        $sql_credentials = "CREATE TABLE $cred (
            id                   BIGINT(20) UNSIGNED NOT NULL AUTO_INCREMENT,
            user_id              BIGINT(20) UNSIGNED NOT NULL,
            credential_id        VARCHAR(512) NOT NULL,
            credential_id_hash   CHAR(64) NOT NULL,
            credential_public_key LONGTEXT NOT NULL,
            sign_count           BIGINT(20) UNSIGNED DEFAULT 0,
            transports           VARCHAR(191) DEFAULT NULL,
            credential_label     VARCHAR(191) DEFAULT 'Passkey',
            aaguid               VARCHAR(191) DEFAULT NULL,
            backed_up            TINYINT(1) DEFAULT 0,
            created_at           DATETIME NOT NULL,
            last_used_at         DATETIME DEFAULT NULL,
            revoked_at           DATETIME DEFAULT NULL,
            PRIMARY KEY  (id),
            UNIQUE KEY credential_id_hash (credential_id_hash),
            KEY user_id (user_id),
            KEY revoked_at (revoked_at)
        ) $charset;";

        $sql_rate = "CREATE TABLE $rate (
            bucket_key        VARCHAR(191) NOT NULL,
            failure_count     INT(10) UNSIGNED NOT NULL DEFAULT 0,
            window_expires_at DATETIME DEFAULT NULL,
            lock_expires_at   DATETIME DEFAULT NULL,
            updated_at        DATETIME NOT NULL,
            PRIMARY KEY (bucket_key),
            KEY lock_expires_at (lock_expires_at),
            KEY window_expires_at (window_expires_at)
        ) $charset;";

        $logs     = $wpdb->prefix . 'wpk_logs';
        $sql_logs = "CREATE TABLE $logs (
            id             BIGINT(20) UNSIGNED NOT NULL AUTO_INCREMENT,
            event_type     VARCHAR(64) NOT NULL,
            log_timestamp  DATETIME NOT NULL,
            user_agent     VARCHAR(512) DEFAULT NULL,
            log_data       LONGTEXT DEFAULT NULL,
            PRIMARY KEY  (id),
            KEY event_type (event_type),
            KEY log_timestamp (log_timestamp)
        ) $charset;";

        require_once ABSPATH . 'wp-admin/includes/upgrade.php';
        dbDelta( $sql_credentials );
        dbDelta( $sql_rate );
        dbDelta( $sql_logs );
    }

    public static function drop_tables(): void {
        global $wpdb;
        // Only called from uninstall.php when user explicitly removes the plugin.
        $wpdb->query( 'DROP TABLE IF EXISTS ' . $wpdb->prefix . self::TABLE_CREDENTIALS ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery
        $wpdb->query( 'DROP TABLE IF EXISTS ' . $wpdb->prefix . self::TABLE_RATE_LIMITS );  // phpcs:ignore WordPress.DB.DirectDatabaseQuery
    }

    // ──────────────────────────────────────────────────────────
    // Admin notices
    // ──────────────────────────────────────────────────────────

    public function render_missing_dependency_notice(): void {
        if ( ! current_user_can( 'manage_options' ) ) {
            return;
        }
        echo '<div class="notice notice-error"><p>' .
            esc_html__( 'WP Passkeys: The WebAuthn library is missing. Run composer install in the wp-passkeys plugin directory.', 'wp-passkeys' ) .
            '</p></div>';
    }

    // ──────────────────────────────────────────────────────────
    // Admin: passkey setup nudge notice
    // ──────────────────────────────────────────────────────────

    public function render_setup_notice(): void {
        if ( ! (int) get_option( 'wpk_show_setup_notice', 1 ) ) {
            return;
        }

        $user = wp_get_current_user();
        if ( ! $this->is_eligible_user( $user ) ) {
            return;
        }

        $dismissed_key = 'wpk_notice_dismissed_' . (int) $user->ID;
        if ( get_user_meta( (int) $user->ID, $dismissed_key, true ) ) {
            return;
        }

        if ( $this->count_user_credentials( (int) $user->ID ) > 0 ) {
            return;
        }

        $profile_url = admin_url( 'profile.php#wpk-profile-section' );
        $nonce       = wp_create_nonce( 'wpk_dismiss_notice' );
        ?>
        <div class="notice notice-info is-dismissible wpk-setup-notice" data-nonce="<?php echo esc_attr( $nonce ); ?>">
            <p>
                <strong><?php esc_html_e( 'Set up a passkey for faster, more secure sign-ins.', 'wp-passkeys' ); ?></strong>
                <?php
                printf(
                    wp_kses(
                        /* translators: %s profile URL */
                        __( ' <a href="%s">Register a passkey now</a> — sign in with Face ID, Touch ID, or a security key, no password needed.', 'wp-passkeys' ),
                        array( 'a' => array( 'href' => array() ) )
                    ),
                    esc_url( $profile_url )
                );
                ?>
            </p>
        </div>
        <script>
        (function(){
            var notice = document.querySelector('.wpk-setup-notice');
            if ( ! notice ) return;
            notice.addEventListener('click', function(e){
                if ( ! e.target.classList.contains('notice-dismiss') ) return;
                var fd = new FormData();
                fd.append('action', 'wpk_dismiss_notice');
                fd.append('nonce',  notice.dataset.nonce);
                fetch(<?php echo wp_json_encode( admin_url( 'admin-ajax.php' ) ); ?>, {
                    method: 'POST', credentials: 'same-origin', body: fd
                });
            });
        })();
        </script>
        <?php
    }

    public function ajax_dismiss_notice(): void {
        if ( ! check_ajax_referer( 'wpk_dismiss_notice', 'nonce', false ) ) {
            wp_send_json_error( null, 403 );
        }
        $user_id = get_current_user_id();
        if ( $user_id ) {
            update_user_meta( $user_id, 'wpk_notice_dismissed_' . $user_id, 1 );
        }
        wp_send_json_success();
    }

    // ──────────────────────────────────────────────────────────
    // Admin: Users list passkey column
    // ──────────────────────────────────────────────────────────

    public function users_column_header( array $columns ): array {
        $columns['wpk_passkeys'] = __( 'Passkeys', 'wp-passkeys' );
        return $columns;
    }

    public function users_column_content( string $output, string $column_name, int $user_id ): string {
        if ( $column_name !== 'wpk_passkeys' ) {
            return $output;
        }

        $user  = get_user_by( 'id', $user_id );
        if ( ! $user || ! $this->is_eligible_user( $user ) ) {
            return '<span style="color:#aaa;">—</span>';
        }

        $count = $this->count_user_credentials( $user_id );
        if ( $count === 0 ) {
            return '<span style="color:#aaa;">0</span>';
        }

        $url = add_query_arg(
            array( 'user_id' => $user_id, 'anchor' => 'wpk-profile-section' ),
            admin_url( 'user-edit.php' )
        );
        return sprintf(
            '<a href="%s" title="%s">%d</a>',
            esc_url( $url ),
            esc_attr( sprintf(
                /* translators: %d passkey count, %s username */
                __( '%1$d passkey(s) for %2$s — click to manage', 'wp-passkeys' ),
                $count,
                $user->user_login
            ) ),
            $count
        );
    }

    public function users_column_sortable( array $columns ): array {
        $columns['wpk_passkeys'] = 'wpk_passkeys';
        return $columns;
    }

    // ──────────────────────────────────────────────────────────
    // Cron: scheduled cleanup
    // ──────────────────────────────────────────────────────────

    public static function schedule_cron(): void {
        if ( ! wp_next_scheduled( 'wpk_scheduled_cleanup' ) ) {
            wp_schedule_event( time(), 'daily', 'wpk_scheduled_cleanup' );
        }
    }

    public static function unschedule_cron(): void {
        $timestamp = wp_next_scheduled( 'wpk_scheduled_cleanup' );
        if ( $timestamp ) {
            wp_unschedule_event( $timestamp, 'wpk_scheduled_cleanup' );
        }
    }

    public function run_scheduled_cleanup(): void {
        global $wpdb;

        // Purge expired rate-limit rows.
        $rate_table = $wpdb->prefix . self::TABLE_RATE_LIMITS;
        $wpdb->query( // phpcs:ignore WordPress.DB.DirectDatabaseQuery
            "DELETE FROM {$rate_table} WHERE (lock_expires_at IS NULL OR lock_expires_at <= UTC_TIMESTAMP()) AND (window_expires_at IS NULL OR window_expires_at <= UTC_TIMESTAMP())" // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
        );

        // Purge log rows older than the configured retention window.
        $keep_days = max( 7, (int) get_option( 'wpk_log_retention_days', 90 ) );
        $log_table = $wpdb->prefix . 'wpk_logs';
        $wpdb->query( $wpdb->prepare( // phpcs:ignore WordPress.DB.DirectDatabaseQuery
            "DELETE FROM {$log_table} WHERE log_timestamp < DATE_SUB(UTC_TIMESTAMP(), INTERVAL %d DAY)", // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
            $keep_days
        ) );
    }

    // ──────────────────────────────────────────────────────────
    // Asset enqueuing
    // ──────────────────────────────────────────────────────────

    public function enqueue_profile_assets( string $hook ): void {
        if ( $hook !== 'profile.php' && $hook !== 'user-edit.php' ) {
            return;
        }

        $screen_uid  = isset( $_GET['user_id'] ) ? absint( $_GET['user_id'] ) : get_current_user_id();
        $target_user = get_user_by( 'id', $screen_uid );

        if ( ! $target_user || ! $this->is_eligible_user( $target_user ) ) {
            return;
        }

        wp_enqueue_script(
            'wpk-profile',
            WPK_PLUGIN_URL . 'admin/js/wpk-profile.js',
            array(),
            WPK_VERSION,
            true
        );

        wp_localize_script( 'wpk-profile', 'WPKProfile', array(
            'ajaxUrl'  => admin_url( 'admin-ajax.php' ),
            'nonce'    => wp_create_nonce( 'wpk_profile' ),
            'messages' => array(
                'labelPlaceholder' => __( 'e.g. iPhone 15, YubiKey 5', 'wp-passkeys' ),
                'starting'         => __( 'Starting passkey registration…', 'wp-passkeys' ),
                'success'          => __( 'Passkey registered successfully.', 'wp-passkeys' ),
                'failed'           => __( 'Passkey registration failed. Try again.', 'wp-passkeys' ),
                'notSupported'     => __( 'This browser does not support passkeys.', 'wp-passkeys' ),
                'mobileHint'       => __( 'Tip: open this page on your phone to save a passkey to iCloud Keychain or Google Password Manager.', 'wp-passkeys' ),
                'confirmRevoke'    => __( 'Revoke this passkey? You will need to re-register to use it again.', 'wp-passkeys' ),
                'revokeFailed'     => __( 'Failed to revoke passkey.', 'wp-passkeys' ),
                'limitReached'     => __( 'You have reached the maximum number of passkeys. Revoke an existing one to add a new one.', 'wp-passkeys' ),
            ),
        ) );

        wp_enqueue_style( 'wpk-admin', WPK_PLUGIN_URL . 'admin/css/wpk-admin.css', array(), WPK_VERSION );
    }

    public function enqueue_login_assets(): void {
        wp_enqueue_script(
            'wpk-login',
            WPK_PLUGIN_URL . 'admin/js/wpk-login.js',
            array(),
            WPK_VERSION,
            true
        );

        wp_localize_script( 'wpk-login', 'WPKLogin', array(
            'ajaxUrl'  => admin_url( 'admin-ajax.php' ),
            'nonce'    => wp_create_nonce( 'wpk_login' ),
            'messages' => array(
                'notSupported' => __( 'Passkeys are not supported in this browser.', 'wp-passkeys' ),
                'genericError' => __( 'Passkey sign-in failed. Please try again or use your password.', 'wp-passkeys' ),
                'signingIn'    => __( 'Signing in…', 'wp-passkeys' ),
            ),
        ) );

        wp_enqueue_style( 'wpk-login', WPK_PLUGIN_URL . 'admin/css/wpk-admin.css', array(), WPK_VERSION );
    }

    // ──────────────────────────────────────────────────────────
    // Profile section UI
    // ──────────────────────────────────────────────────────────

    public function render_profile_section( WP_User $user ): void {
        if ( ! $this->is_eligible_user( $user ) ) {
            return;
        }

        if ( (int) $user->ID !== (int) get_current_user_id() && ! current_user_can( 'edit_users' ) ) {
            return;
        }

        $credentials  = $this->get_user_credentials_meta( (int) $user->ID );
        $max_passkeys = $this->get_max_passkeys_per_user( $user );
        $at_limit     = count( $credentials ) >= $max_passkeys;
        ?>
        <div class="wpk-profile-section">
            <h2><?php esc_html_e( 'Passkeys', 'wp-passkeys' ); ?></h2>
            <p class="description">
                <?php esc_html_e( 'Sign in with your fingerprint, face, or a hardware security key — no password needed.', 'wp-passkeys' ); ?>
            </p>

            <table class="form-table wpk-profile-table" role="presentation">
                <tr>
                    <th><label for="wpk-passkey-label"><?php esc_html_e( 'Register Passkey', 'wp-passkeys' ); ?></label></th>
                    <td>
                        <div class="wpk-register-wrap">
                        <?php if ( $at_limit ) : ?>
                            <p class="description wpk-notice-warning">
                                <?php
                                printf(
                                    /* translators: %d number of passkeys */
                                    esc_html__( 'You have registered the maximum of %d passkeys. Revoke one to add another.', 'wp-passkeys' ),
                                    esc_html( $max_passkeys )
                                );
                                ?>
                                <?php do_action( 'wpk_profile_limit_reached_cta', $user ); ?>
                            </p>
                        <?php else : ?>
                            <input type="text"
                                   id="wpk-passkey-label"
                                   class="wpk-label-input"
                                   placeholder="<?php esc_attr_e( 'Device label (optional)', 'wp-passkeys' ); ?>"
                                   maxlength="100" />
                            <div class="wpk-register-actions">
                                <button type="button" class="button button-primary" id="wpk-passkey-register">
                                    <?php esc_html_e( 'Register New Passkey', 'wp-passkeys' ); ?>
                                </button>
                                <p id="wpk-passkey-profile-message" class="wpk-inline-message" aria-live="polite"></p>
                            </div>
                        <?php endif; ?>
                        </div>
                    </td>
                </tr>

                <?php if ( ! empty( $credentials ) ) : ?>
                <tr>
                    <th><?php esc_html_e( 'Registered Passkeys', 'wp-passkeys' ); ?></th>
                    <td>
                        <table class="widefat wpk-credentials-table">
                            <thead>
                                <tr>
                                    <th><?php esc_html_e( 'Label', 'wp-passkeys' ); ?></th>
                                    <th><?php esc_html_e( 'Registered', 'wp-passkeys' ); ?></th>
                                    <th><?php esc_html_e( 'Last Used', 'wp-passkeys' ); ?></th>
                                    <?php do_action( 'wpk_profile_table_header', $user ); ?>
                                    <th class="wpk-col-action"><?php esc_html_e( 'Action', 'wp-passkeys' ); ?></th>
                                </tr>
                            </thead>
                            <tbody>
                                <?php foreach ( $credentials as $cred ) : ?>
                                    <tr data-credential-id="<?php echo esc_attr( (string) $cred->id ); ?>">
                                        <td class="wpk-col-label"><?php echo esc_html( $cred->credential_label ?: 'Passkey' ); ?></td>
                                        <td><?php echo esc_html( mysql2date( get_option( 'date_format' ) . ' ' . get_option( 'time_format' ), $cred->created_at ) ); ?></td>
                                        <td><?php echo $cred->last_used_at ? esc_html( mysql2date( get_option( 'date_format' ) . ' ' . get_option( 'time_format' ), $cred->last_used_at ) ) : esc_html__( 'Never', 'wp-passkeys' ); ?></td>
                                        <?php do_action( 'wpk_profile_table_row', $cred, $user ); ?>
                                        <td class="wpk-col-action">
                                            <button class="button-link-delete wpk-passkey-revoke" type="button">
                                                <?php esc_html_e( 'Revoke', 'wp-passkeys' ); ?>
                                            </button>
                                        </td>
                                    </tr>
                                <?php endforeach; ?>
                            </tbody>
                        </table>

                        <?php if ( count( $credentials ) === 1 ) : ?>
                            <p class="description wpk-notice-warning" style="margin-top:8px;max-width:560px;">
                                <?php esc_html_e( '⚠ You only have one passkey registered. Add a backup passkey on another device to avoid getting locked out.', 'wp-passkeys' ); ?>
                            </p>
                        <?php endif; ?>
                    </td>
                </tr>
                <?php endif; ?>
            </table>
        </div>
        <?php
    }

    // ──────────────────────────────────────────────────────────
    // AJAX: Begin Registration
    // ──────────────────────────────────────────────────────────

    public function ajax_begin_registration(): void {
        if ( ! is_user_logged_in() ) {
            wp_send_json_error( array( 'message' => 'Unauthorized' ), 403 );
        }

        $ip = $this->get_client_ip();
        if ( $this->is_locked_out( 'reg_begin_ip', $ip ) ) {
            wp_send_json_error( array( 'message' => 'Too many attempts. Please wait and try again.' ), 429 );
        }

        if ( ! $this->is_secure_context() ) {
            $this->record_failure( 'reg_begin_ip', $ip );
            wp_send_json_error( array( 'message' => 'Passkeys require HTTPS.' ), 400 );
        }

        if ( ! check_ajax_referer( 'wpk_profile', 'nonce', false ) ) {
            $this->record_failure( 'reg_begin_ip', $ip );
            wp_send_json_error( array( 'message' => 'Invalid request.' ), 403 );
        }

        $user = wp_get_current_user();

        if ( $this->is_locked_out( 'reg_begin_user', (int) $user->ID ) ) {
            wp_send_json_error( array( 'message' => 'Too many attempts. Please wait and try again.' ), 429 );
        }

        if ( ! $this->is_eligible_user( $user ) ) {
            $this->record_failure( 'reg_begin_ip', $ip );
            wp_send_json_error( array( 'message' => 'Your account is not eligible for passkeys.' ), 403 );
        }

        if ( ! current_user_can( 'edit_user', (int) $user->ID ) ) {
            $this->record_failure( 'reg_begin_ip', $ip );
            wp_send_json_error( array( 'message' => 'Unauthorized' ), 403 );
        }

        // Enforce per-user passkey cap
        $max   = $this->get_max_passkeys_per_user( $user );
        $count = $this->count_user_credentials( (int) $user->ID );
        if ( $count >= $max ) {
            $this->record_failure( 'reg_begin_ip', $ip );
            wp_send_json_error( array( 'message' => 'You have reached the maximum number of passkeys for your account.' ), 400 );
        }

        try {
            $web_authn   = $this->new_webauthn();
            $exclude_ids = $this->get_credential_ids_binary( (int) $user->ID );

            $create_args = $web_authn->getCreateArgs(
                'wp-user-' . (string) $user->ID,
                (string) $user->user_login,
                (string) $user->display_name,
                60,
                true,
                $this->get_user_verification(),
                null,
                $exclude_ids
            );

            $token  = wp_generate_password( 32, false, false );
            set_transient(
                'wpk_reg_' . $token,
                array(
                    'user_id'   => (int) $user->ID,
                    'challenge' => base64_encode( $web_authn->getChallenge()->getBinaryString() ),
                ),
                $this->get_challenge_ttl()
            );

            $this->clear_failures( 'reg_begin_ip', $ip );
            $this->clear_failures( 'reg_begin_user', (int) $user->ID );

            wp_send_json_success( array( 'options' => $create_args, 'token' => $token ) );

        } catch ( \Throwable $e ) {
            $this->record_failure( 'reg_begin_ip', $ip );
            $this->record_failure( 'reg_begin_user', (int) $user->ID );
            $this->log_event( 'registration_begin_failed', array( 'message' => $e->getMessage() ) );
            wp_send_json_error( array( 'message' => 'Could not start passkey registration.' ), 500 );
        }
    }

    // ──────────────────────────────────────────────────────────
    // AJAX: Finish Registration
    // ──────────────────────────────────────────────────────────

    public function ajax_finish_registration(): void {
        if ( ! is_user_logged_in() ) {
            wp_send_json_error( array( 'message' => 'Unauthorized' ), 403 );
        }

        $ip = $this->get_client_ip();
        if ( $this->is_locked_out( 'reg_finish_ip', $ip ) ) {
            wp_send_json_error( array( 'message' => 'Too many attempts. Please wait and try again.' ), 429 );
        }

        if ( ! $this->is_secure_context() ) {
            $this->record_failure( 'reg_finish_ip', $ip );
            wp_send_json_error( array( 'message' => 'Passkeys require HTTPS.' ), 400 );
        }

        if ( ! check_ajax_referer( 'wpk_profile', 'nonce', false ) ) {
            $this->record_failure( 'reg_finish_ip', $ip );
            wp_send_json_error( array( 'message' => 'Invalid request.' ), 403 );
        }

        $user = wp_get_current_user();
        if ( $this->is_locked_out( 'reg_finish_user', (int) $user->ID ) ) {
            wp_send_json_error( array( 'message' => 'Too many attempts. Please wait and try again.' ), 429 );
        }

        if ( ! $this->is_eligible_user( $user ) ) {
            $this->record_failure( 'reg_finish_ip', $ip );
            wp_send_json_error( array( 'message' => 'Your account is not eligible for passkeys.' ), 403 );
        }

        $token = isset( $_POST['token'] ) ? sanitize_text_field( wp_unslash( $_POST['token'] ) ) : '';
        if ( empty( $token ) || ! preg_match( '/\A[a-zA-Z0-9]{20,64}\z/', $token ) ) {
            $this->record_failure( 'reg_finish_ip', $ip );
            wp_send_json_error( array( 'message' => 'Registration session expired.' ), 400 );
        }

        $state = get_transient( 'wpk_reg_' . $token );
        if ( ! $state || empty( $state['challenge'] ) || (int) $state['user_id'] !== (int) $user->ID ) {
            $this->record_failure( 'reg_finish_ip', $ip );
            $this->record_failure( 'reg_finish_user', (int) $user->ID );
            wp_send_json_error( array( 'message' => 'Registration session expired.' ), 400 );
        }

        delete_transient( 'wpk_reg_' . $token );

        $client_data  = isset( $_POST['clientDataJSON'] )   ? sanitize_text_field( wp_unslash( $_POST['clientDataJSON'] ) )   : '';
        $attestation  = isset( $_POST['attestationObject'] ) ? sanitize_text_field( wp_unslash( $_POST['attestationObject'] ) ) : '';
        $label_raw    = isset( $_POST['label'] )             ? sanitize_text_field( wp_unslash( $_POST['label'] ) )             : '';
        $label        = $label_raw !== '' ? substr( $label_raw, 0, 100 ) : 'Passkey';

        // Validate transports: decode JSON, allowlist known values, re-encode.
        $transports = '';
        if ( ! empty( $_POST['transports'] ) ) {
            $raw_transports = json_decode( wp_unslash( $_POST['transports'] ), true );
            if ( is_array( $raw_transports ) ) {
                $allowed_transports = array( 'usb', 'nfc', 'ble', 'internal', 'hybrid', 'cable', 'smart-card' );
                $clean_transports   = array_values( array_intersect( array_map( 'sanitize_key', $raw_transports ), $allowed_transports ) );
                $transports         = (string) wp_json_encode( $clean_transports );
            }
        }

        if ( $client_data === '' || $attestation === '' ) {
            $this->record_failure( 'reg_finish_ip', $ip );
            $this->record_failure( 'reg_finish_user', (int) $user->ID );
            wp_send_json_error( array( 'message' => 'Incomplete passkey response.' ), 400 );
        }

        try {
            $web_authn = $this->new_webauthn();
            $challenge = base64_decode( $state['challenge'], true );
            if ( $challenge === false ) {
                throw new \RuntimeException( 'Challenge decode failed' );
            }

            $result = $web_authn->processCreate(
                $this->decode_b64url( $client_data ),
                $this->decode_b64url( $attestation ),
                $challenge,
                $this->get_user_verification() === 'required',
                true,
                false
            );

            $cred_id   = $this->encode_b64url( $result->credentialId );
            $cred_hash = hash( 'sha256', $cred_id );

            global $wpdb;
            $table = $wpdb->prefix . self::TABLE_CREDENTIALS;

            $wpdb->insert(
                $table,
                array(
                    'user_id'              => (int) $user->ID,
                    'credential_id'        => $cred_id,
                    'credential_id_hash'   => $cred_hash,
                    'credential_public_key'=> (string) $result->credentialPublicKey,
                    'sign_count'           => (int) ( $result->signatureCounter ?: 0 ),
                    'transports'           => $transports,
                    'credential_label'     => $label,
                    'aaguid'               => ! empty( $result->AAGUID ) ? bin2hex( (string) $result->AAGUID ) : null,
                    'backed_up'            => ! empty( $result->isBackedUp ) ? 1 : 0,
                    'created_at'           => current_time( 'mysql' ),
                    'last_used_at'         => null,
                    'revoked_at'           => null,
                ),
                array( '%d', '%s', '%s', '%s', '%d', '%s', '%s', '%s', '%d', '%s', '%s', '%s' )
            );

            if ( $wpdb->last_error ) {
                throw new \RuntimeException( $wpdb->last_error );
            }

            $this->log_event( 'registered', array( 'user_id' => (int) $user->ID, 'credential_hash' => $cred_hash ) );

            /**
             * Fires after a passkey is successfully registered.
             *
             * @param int    $user_id         WordPress user ID.
             * @param string $credential_hash SHA-256 hash of the credential ID.
             */
            do_action( 'wpk_passkey_registered', (int) $user->ID, $cred_hash );

            $this->clear_failures( 'reg_finish_ip', $ip );
            $this->clear_failures( 'reg_finish_user', (int) $user->ID );

            wp_send_json_success( array( 'message' => 'Passkey registered.' ) );

        } catch ( \Throwable $e ) {
            $this->record_failure( 'reg_finish_ip', $ip );
            $this->record_failure( 'reg_finish_user', (int) $user->ID );
            $this->log_event( 'registration_failed', array( 'user_id' => (int) $user->ID, 'message' => $e->getMessage() ) );
            wp_send_json_error( array( 'message' => 'Passkey registration failed.' ), 400 );
        }
    }

    // ──────────────────────────────────────────────────────────
    // AJAX: Revoke Credential
    // ──────────────────────────────────────────────────────────

    public function ajax_revoke_credential(): void {
        if ( ! is_user_logged_in() ) {
            wp_send_json_error( array( 'message' => 'Unauthorized' ), 403 );
        }

        $ip = $this->get_client_ip();
        if ( $this->is_locked_out( 'revoke_ip', $ip ) ) {
            wp_send_json_error( array( 'message' => 'Too many attempts. Please wait and try again.' ), 429 );
        }

        if ( ! $this->is_secure_context() ) {
            $this->record_failure( 'revoke_ip', $ip );
            wp_send_json_error( array( 'message' => 'Passkeys require HTTPS.' ), 400 );
        }

        if ( ! check_ajax_referer( 'wpk_profile', 'nonce', false ) ) {
            $this->record_failure( 'revoke_ip', $ip );
            wp_send_json_error( array( 'message' => 'Invalid request.' ), 403 );
        }

        $user          = wp_get_current_user();
        $cred_row_id   = isset( $_POST['credentialId'] ) ? absint( $_POST['credentialId'] ) : 0;

        if ( $cred_row_id < 1 ) {
            wp_send_json_error( array( 'message' => 'Invalid credential.' ), 400 );
        }

        global $wpdb;
        $table = $wpdb->prefix . self::TABLE_CREDENTIALS;

        $cred = $wpdb->get_row( $wpdb->prepare(
            "SELECT id, user_id FROM {$table} WHERE id = %d AND revoked_at IS NULL LIMIT 1", // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
            $cred_row_id
        ) );

        if ( ! $cred ) {
            wp_send_json_error( array( 'message' => 'Credential not found.' ), 404 );
        }

        // Users may only revoke their own passkeys; admins can revoke any user's.
        if ( (int) $cred->user_id !== (int) $user->ID && ! current_user_can( 'edit_users' ) ) {
            wp_send_json_error( array( 'message' => 'Unauthorized' ), 403 );
        }

        $wpdb->update(
            $table,
            array( 'revoked_at' => current_time( 'mysql' ) ),
            array( 'id' => $cred_row_id ),
            array( '%s' ),
            array( '%d' )
        );

        $this->log_event( 'revoked', array( 'user_id' => (int) $cred->user_id, 'credential_id' => $cred_row_id ) );

        /**
         * Fires after a passkey is revoked.
         *
         * @param int $user_id       WordPress user ID.
         * @param int $credential_id DB row ID of the revoked credential.
         */
        do_action( 'wpk_passkey_revoked', (int) $cred->user_id, $cred_row_id );

        wp_send_json_success( array( 'message' => 'Passkey revoked.' ) );
    }

    // ──────────────────────────────────────────────────────────
    // AJAX: Begin Login
    // ──────────────────────────────────────────────────────────

    public function ajax_begin_login(): void {
        $ip = $this->get_client_ip();

        if ( $this->is_locked_out( 'login_begin_ip', $ip ) ) {
            wp_send_json_error( array( 'message' => 'Too many attempts. Please wait and try again.' ), 429 );
        }

        if ( ! $this->is_secure_context() ) {
            $this->record_failure( 'login_begin_ip', $ip );
            wp_send_json_error( array( 'message' => 'Passkeys require HTTPS.' ), 400 );
        }

        if ( ! check_ajax_referer( 'wpk_login', 'nonce', false ) ) {
            $this->record_failure( 'login_begin_ip', $ip );
            wp_send_json_error( array( 'message' => 'Invalid request.' ), 403 );
        }

        $login        = isset( $_POST['login'] ) ? sanitize_text_field( wp_unslash( $_POST['login'] ) ) : '';
        $login_key    = '';
        $state_uid    = 0;
        $cred_rows    = array();
        $generic_err  = 'Passkey sign-in could not be started. Please try again.';

        // Optional: username-based flow (non-discoverable / legacy credentials).
        if ( $login !== '' ) {
            $login_key = strtolower( $login );

            if ( $this->is_locked_out( 'login_begin_acct', $login_key ) ) {
                wp_send_json_error( array( 'message' => 'Too many attempts. Please wait and try again.' ), 429 );
            }

            $user = $this->resolve_user( $login );
            if ( ! $user || ! $this->is_eligible_user( $user ) ) {
                $this->record_failure( 'login_begin_ip',   $ip );
                $this->record_failure( 'login_begin_acct', $login_key );
                wp_send_json_error( array( 'message' => $generic_err ), 400 );
            }

            $cred_rows = $this->get_user_credentials( (int) $user->ID );
            if ( empty( $cred_rows ) ) {
                $this->record_failure( 'login_begin_ip',   $ip );
                $this->record_failure( 'login_begin_acct', $login_key );
                wp_send_json_error( array( 'message' => $generic_err ), 400 );
            }

            $state_uid = (int) $user->ID;
        }

        try {
            $web_authn   = $this->new_webauthn();
            $cred_ids    = array_map( fn( $r ) => $this->decode_b64url( $r->credential_id ), $cred_rows );

            $get_args = $web_authn->getGetArgs(
                $cred_ids,
                60,
                true, true, true, true, true,
                $this->get_user_verification()
            );

            $token = wp_generate_password( 32, false, false );
            set_transient(
                'wpk_login_' . $token,
                array(
                    'user_id'   => $state_uid,
                    'challenge' => base64_encode( $web_authn->getChallenge()->getBinaryString() ),
                ),
                $this->get_challenge_ttl()
            );

            $this->clear_failures( 'login_begin_ip', $ip );
            if ( $login_key !== '' ) {
                $this->clear_failures( 'login_begin_acct', $login_key );
            }

            wp_send_json_success( array( 'options' => $get_args, 'token' => $token ) );

        } catch ( \Throwable $e ) {
            $this->record_failure( 'login_begin_ip', $ip );
            if ( $login_key !== '' ) {
                $this->record_failure( 'login_begin_acct', $login_key );
            }
            $this->log_event( 'login_begin_failed', array( 'message' => $e->getMessage() ) );
            wp_send_json_error( array( 'message' => 'Could not start passkey sign-in.' ), 500 );
        }
    }

    // ──────────────────────────────────────────────────────────
    // AJAX: Finish Login
    // ──────────────────────────────────────────────────────────

    public function ajax_finish_login(): void {
        $ip = $this->get_client_ip();

        if ( $this->is_locked_out( 'login_finish_ip', $ip ) ) {
            wp_send_json_error( array( 'message' => 'Too many attempts. Please wait and try again.' ), 429 );
        }

        if ( ! $this->is_secure_context() ) {
            $this->record_failure( 'login_finish_ip', $ip );
            wp_send_json_error( array( 'message' => 'Passkeys require HTTPS.' ), 400 );
        }

        if ( ! check_ajax_referer( 'wpk_login', 'nonce', false ) ) {
            $this->record_failure( 'login_finish_ip', $ip );
            wp_send_json_error( array( 'message' => 'Invalid request.' ), 403 );
        }

        $token = isset( $_POST['token'] ) ? sanitize_text_field( wp_unslash( $_POST['token'] ) ) : '';
        if ( $token === '' || ! preg_match( '/\A[a-zA-Z0-9]{20,64}\z/', $token ) ) {
            $this->record_failure( 'login_finish_ip', $ip );
            wp_send_json_error( array( 'message' => 'Login session expired.' ), 400 );
        }

        $state = get_transient( 'wpk_login_' . $token );
        if ( ! $state || empty( $state['challenge'] ) || ! isset( $state['user_id'] ) ) {
            $this->record_failure( 'login_finish_ip', $ip );
            wp_send_json_error( array( 'message' => 'Login session expired.' ), 400 );
        }

        $state_uid = (int) $state['user_id'];

        if ( $state_uid > 0 && $this->is_locked_out( 'login_finish_user', $state_uid ) ) {
            wp_send_json_error( array( 'message' => 'Too many attempts. Please wait and try again.' ), 429 );
        }

        delete_transient( 'wpk_login_' . $token );

        $cred_id       = isset( $_POST['id'] )               ? sanitize_text_field( wp_unslash( $_POST['id'] ) )               : '';
        $client_data   = isset( $_POST['clientDataJSON'] )   ? sanitize_text_field( wp_unslash( $_POST['clientDataJSON'] ) )   : '';
        $auth_data     = isset( $_POST['authenticatorData'] ) ? sanitize_text_field( wp_unslash( $_POST['authenticatorData'] ) ) : '';
        $signature     = isset( $_POST['signature'] )        ? sanitize_text_field( wp_unslash( $_POST['signature'] ) )        : '';
        $user_handle   = isset( $_POST['userHandle'] )       ? sanitize_text_field( wp_unslash( $_POST['userHandle'] ) )       : '';

        if ( $cred_id === '' || $client_data === '' || $auth_data === '' || $signature === '' ) {
            $this->record_failure( 'login_finish_ip', $ip );
            if ( $state_uid > 0 ) {
                $this->record_failure( 'login_finish_user', $state_uid );
            }
            wp_send_json_error( array( 'message' => 'Incomplete passkey response.' ), 400 );
        }

        global $wpdb;
        $table     = $wpdb->prefix . self::TABLE_CREDENTIALS;
        $cred_hash = hash( 'sha256', $cred_id );

        if ( $state_uid === 0 && $this->is_locked_out( 'login_finish_cred', $cred_hash ) ) {
            wp_send_json_error( array( 'message' => 'Too many attempts. Please wait and try again.' ), 429 );
        }

        // Fetch stored credential.
        if ( $state_uid > 0 ) {
            $cred = $wpdb->get_row( $wpdb->prepare(
                "SELECT * FROM {$table} WHERE credential_id_hash = %s AND user_id = %d AND revoked_at IS NULL LIMIT 1", // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
                $cred_hash, $state_uid
            ) );
        } else {
            $cred = $wpdb->get_row( $wpdb->prepare(
                "SELECT * FROM {$table} WHERE credential_id_hash = %s AND revoked_at IS NULL LIMIT 1", // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
                $cred_hash
            ) );
        }

        if ( ! $cred ) {
            $this->record_failure( 'login_finish_ip', $ip );
            if ( $state_uid > 0 ) {
                $this->record_failure( 'login_finish_user', $state_uid );
            } else {
                $this->record_failure( 'login_finish_cred', $cred_hash );
            }
            $this->log_event( 'login_credential_mismatch', array( 'hash' => $cred_hash ) );
            wp_send_json_error( array( 'message' => 'Passkey sign-in failed.' ), 400 );
        }

        if ( $this->is_locked_out( 'login_finish_user', (int) $cred->user_id ) ) {
            wp_send_json_error( array( 'message' => 'Too many attempts. Please wait and try again.' ), 429 );
        }

        try {
            $web_authn = $this->new_webauthn();
            $challenge = base64_decode( $state['challenge'], true );
            if ( $challenge === false ) {
                throw new \RuntimeException( 'Challenge decode failed' );
            }

            $web_authn->processGet(
                $this->decode_b64url( $client_data ),
                $this->decode_b64url( $auth_data ),
                $this->decode_b64url( $signature ),
                $cred->credential_public_key,
                $challenge,
                is_null( $cred->sign_count ) ? null : (int) $cred->sign_count,
                $this->get_user_verification() === 'required',
                true
            );

            // Verify user handle (discoverable credential).
            if ( $user_handle !== '' ) {
                $decoded_handle   = $this->decode_b64url( $user_handle );
                $expected_handle  = 'wp-user-' . (string) ( (int) $cred->user_id );
                if ( ! hash_equals( $expected_handle, (string) $decoded_handle ) ) {
                    throw new \RuntimeException( 'User handle mismatch' );
                }
            }

            $user = get_user_by( 'id', (int) $cred->user_id );
            if ( ! $user ) {
                throw new \RuntimeException( 'User not found' );
            }

            if ( ! $this->is_eligible_user( $user ) ) {
                throw new \RuntimeException( 'User is not eligible for passkey login' );
            }

            wp_set_current_user( (int) $user->ID );
            wp_set_auth_cookie( (int) $user->ID, true );
            do_action( 'wp_login', $user->user_login, $user );

            // Update sign count and last-used timestamp.
            $next_count = $web_authn->getSignatureCounter();
            $wpdb->update(
                $table,
                array(
                    'sign_count'  => is_null( $next_count ) ? (int) $cred->sign_count : (int) $next_count,
                    'last_used_at'=> current_time( 'mysql' ),
                ),
                array( 'id' => (int) $cred->id ),
                array( '%d', '%s' ),
                array( '%d' )
            );

            $this->log_event( 'login_success', array( 'user_id' => (int) $user->ID, 'credential_hash' => $cred_hash ) );

            /**
             * Fires after a successful passkey login.
             *
             * @param int    $user_id         WordPress user ID.
             * @param string $credential_hash SHA-256 hash of the credential ID.
             * @param string $user_agent       Raw User-Agent string.
             */
            do_action( 'wpk_passkey_login_success', (int) $user->ID, $cred_hash, sanitize_text_field( wp_unslash( $_SERVER['HTTP_USER_AGENT'] ?? '' ) ) );

            $this->clear_failures( 'login_finish_ip', $ip );
            $this->clear_failures( 'login_finish_user', (int) $user->ID );
            $this->clear_failures( 'login_finish_cred', $cred_hash );

            // Determine redirect target.
            $redirect = isset( $_REQUEST['redirect_to'] )
                ? $this->safe_redirect( wp_unslash( $_REQUEST['redirect_to'] ) )
                : '';

            if ( $redirect === '' && isset( $_COOKIE['wpk_redirect_to'] ) ) {
                $redirect = $this->safe_redirect( wp_unslash( $_COOKIE['wpk_redirect_to'] ) );
            }

            $this->clear_redirect_cookie();

            // Fall back to the settings-page redirect URL.
            if ( $redirect === '' ) {
                $settings_redirect = (string) get_option( 'wpk_login_redirect', '' );
                if ( $settings_redirect !== '' ) {
                    $redirect = $this->safe_redirect( $settings_redirect );
                }
            }

            if ( $redirect === '' ) {
                $default  = apply_filters( 'login_redirect', admin_url(), '', $user );
                $redirect = $this->safe_redirect( $default, admin_url() );
            }

            /**
             * Filters the URL the user is sent to after a successful passkey login.
             *
             * @param string  $redirect Redirect URL.
             * @param WP_User $user     Logged-in user.
             */
            // Re-validate after filter to prevent open-redirect via third-party hooks.
            $redirect = $this->safe_redirect( (string) apply_filters( 'wpk_login_redirect', $redirect, $user ), admin_url() );

            wp_send_json_success( array( 'redirect' => $redirect ) );

        } catch ( \Throwable $e ) {
            $this->record_failure( 'login_finish_ip', $ip );
            $this->record_failure( 'login_finish_user', (int) $cred->user_id );
            $this->record_failure( 'login_finish_cred', $cred_hash );
            $this->log_event( 'login_failed', array( 'user_id' => (int) $cred->user_id, 'message' => $e->getMessage() ) );
            wp_send_json_error( array( 'message' => 'Passkey sign-in failed. Please use another login method.' ), 400 );
        }
    }

    // ──────────────────────────────────────────────────────────
    // Private helpers — WebAuthn
    // ──────────────────────────────────────────────────────────

    private function new_webauthn(): WebAuthn {
        return new WebAuthn(
            $this->get_rp_name(),
            $this->get_rp_id(),
            array( 'none', 'packed', 'apple', 'fido-u2f', 'tpm', 'android-key', 'android-safetynet' ),
            true
        );
    }

    private function get_rp_id(): string {
        if ( defined( 'WPK_RP_ID' ) && WPK_RP_ID ) {
            return (string) WPK_RP_ID;
        }
        return (string) wp_parse_url( home_url(), PHP_URL_HOST );
    }

    private function get_rp_name(): string {
        if ( defined( 'WPK_RP_NAME' ) && WPK_RP_NAME ) {
            return (string) WPK_RP_NAME;
        }
        $name = get_option( 'wpk_rp_name', '' );
        return $name !== '' ? (string) $name : (string) get_bloginfo( 'name' );
    }

    private function get_challenge_ttl(): int {
        if ( defined( 'WPK_CHALLENGE_TTL' ) && (int) WPK_CHALLENGE_TTL > 30 ) {
            return (int) WPK_CHALLENGE_TTL;
        }
        $opt = (int) get_option( 'wpk_challenge_ttl', 0 );
        if ( $opt >= 30 ) {
            return min( 600, $opt );
        }
        return 300;
    }

    private function get_user_verification(): string {
        $opt = strtolower( (string) get_option( 'wpk_user_verification', '' ) );
        if ( in_array( $opt, array( 'required', 'preferred', 'discouraged' ), true ) ) {
            return $opt;
        }
        if ( defined( 'WPK_USER_VERIFICATION' ) ) {
            $v = strtolower( (string) WPK_USER_VERIFICATION );
            if ( in_array( $v, array( 'required', 'preferred', 'discouraged' ), true ) ) {
                return $v;
            }
        }
        return 'required';
    }

    private function decode_b64url( string $value ): string {
        return ByteBuffer::fromBase64Url( $value )->getBinaryString();
    }

    private function encode_b64url( string $value ): string {
        return rtrim( strtr( base64_encode( $value ), '+/', '-_' ), '=' );
    }

    // ──────────────────────────────────────────────────────────
    // Private helpers — User
    // ──────────────────────────────────────────────────────────

    private function is_eligible_user( WP_User $user ): bool {
        /**
         * Filters whether a user may register/use passkeys.
         * Pro add-on can hook here to expand eligibility (e.g. WooCommerce customers).
         *
         * @param bool    $eligible Whether the user is eligible.
         * @param WP_User $user     The user in question.
         */
        $eligible = apply_filters( 'wpk_is_eligible_user', null, $user );
        if ( $eligible !== null ) {
            return (bool) $eligible;
        }

        $allowed_roles = (array) get_option( 'wpk_eligible_roles', array( 'administrator' ) );
        return ! empty( array_intersect( (array) $user->roles, $allowed_roles ) );
    }

    private function get_max_passkeys_per_user( WP_User $user ): int {
        /**
         * Filters the max number of passkeys a user may hold.
         * Pro add-on can return PHP_INT_MAX to remove the cap.
         *
         * @param int     $max  Current cap.
         * @param WP_User $user The user.
         */
        $filtered = apply_filters( 'wpk_max_passkeys_per_user', null, $user );
        if ( $filtered !== null ) {
            return max( 1, (int) $filtered );
        }

        $setting = (int) get_option( 'wpk_max_passkeys_per_user', self::LITE_MAX_PASSKEYS );
        return max( 1, min( self::LITE_MAX_PASSKEYS, $setting ) );
    }

    private function resolve_user( string $login ): ?WP_User {
        $user = is_email( $login ) ? get_user_by( 'email', $login ) : false;
        if ( ! $user ) {
            $user = get_user_by( 'login', $login );
        }
        return $user instanceof WP_User ? $user : null;
    }

    private function get_user_credentials( int $user_id ): array {
        global $wpdb;
        $table = $wpdb->prefix . self::TABLE_CREDENTIALS;
        return (array) $wpdb->get_results( $wpdb->prepare( // phpcs:ignore WordPress.DB.DirectDatabaseQuery
            "SELECT * FROM {$table} WHERE user_id = %d AND revoked_at IS NULL ORDER BY created_at DESC", // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
            $user_id
        ) );
    }

    /**
     * Fetch display-only metadata for a user's passkeys.
     * Does NOT load credential_public_key — use get_user_credentials() for authentication.
     */
    private function get_user_credentials_meta( int $user_id ): array {
        global $wpdb;
        $table = $wpdb->prefix . self::TABLE_CREDENTIALS;
        return (array) $wpdb->get_results( $wpdb->prepare( // phpcs:ignore WordPress.DB.DirectDatabaseQuery
            "SELECT id, credential_label, created_at, last_used_at FROM {$table} WHERE user_id = %d AND revoked_at IS NULL ORDER BY created_at DESC", // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
            $user_id
        ) );
    }

    /**
     * Return the count of active (non-revoked) passkeys for a user.
     * Avoids loading full credential rows just for a count check.
     */
    private function count_user_credentials( int $user_id ): int {
        global $wpdb;
        $table = $wpdb->prefix . self::TABLE_CREDENTIALS;
        return (int) $wpdb->get_var( $wpdb->prepare( // phpcs:ignore WordPress.DB.DirectDatabaseQuery
            "SELECT COUNT(*) FROM {$table} WHERE user_id = %d AND revoked_at IS NULL", // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
            $user_id
        ) );
    }

    private function get_credential_ids_binary( int $user_id ): array {
        return array_map(
            fn( $r ) => $this->decode_b64url( $r->credential_id ),
            $this->get_user_credentials( $user_id )
        );
    }

    // ──────────────────────────────────────────────────────────
    // Private helpers — Redirect / Cookie
    // ──────────────────────────────────────────────────────────

    private function safe_redirect( string $target, string $fallback = '' ): string {
        return $target !== '' ? (string) wp_validate_redirect( $target, $fallback ) : $fallback;
    }

    private function clear_redirect_cookie(): void {
        setcookie( 'wpk_redirect_to', '', array(
            'expires'  => time() - 3600,
            'path'     => defined( 'COOKIEPATH' )   ? (string) COOKIEPATH   : '/',
            'domain'   => defined( 'COOKIE_DOMAIN' ) ? (string) COOKIE_DOMAIN : '',
            'secure'   => is_ssl(),
            'httponly' => true,
            'samesite' => 'Lax',
        ) );
    }

    // ──────────────────────────────────────────────────────────
    // Private helpers — Rate limiting
    // ──────────────────────────────────────────────────────────

    private function get_rate_window(): int {
        $opt = (int) get_option( 'wpk_rate_window', 0 );
        if ( $opt >= 60 ) {
            return min( 3600, $opt );
        }
        if ( defined( 'WPK_RATE_WINDOW' ) && (int) WPK_RATE_WINDOW >= 60 ) {
            return (int) WPK_RATE_WINDOW;
        }
        return 300;
    }

    private function get_rate_max_attempts(): int {
        $opt = (int) get_option( 'wpk_rate_max_attempts', 0 );
        if ( $opt >= 1 ) {
            return min( 50, $opt );
        }
        if ( defined( 'WPK_RATE_MAX_ATTEMPTS' ) && (int) WPK_RATE_MAX_ATTEMPTS >= 1 ) {
            return (int) WPK_RATE_MAX_ATTEMPTS;
        }
        return 8;
    }

    private function get_rate_lockout(): int {
        $opt = (int) get_option( 'wpk_rate_lockout', 0 );
        if ( $opt >= 60 ) {
            return min( 86400, $opt );
        }
        if ( defined( 'WPK_RATE_LOCKOUT' ) && (int) WPK_RATE_LOCKOUT >= 60 ) {
            return (int) WPK_RATE_LOCKOUT;
        }
        return 900;
    }

    private function bucket_key( string $prefix, string $identifier ): string {
        return 'wpk_' . md5( $prefix . '|' . $identifier );
    }

    private function is_locked_out( string $prefix, $identifier ): bool {
        global $wpdb;
        $table  = $wpdb->prefix . self::TABLE_RATE_LIMITS;
        $key    = $this->bucket_key( $prefix, (string) $identifier );
        $until  = $wpdb->get_var( $wpdb->prepare( // phpcs:ignore WordPress.DB.DirectDatabaseQuery
            "SELECT lock_expires_at FROM {$table} WHERE bucket_key = %s LIMIT 1", // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
            $key
        ) );
        return $until && strtotime( (string) $until ) > time();
    }

    private function record_failure( string $prefix, $identifier ): void {
        global $wpdb;
        $table   = $wpdb->prefix . self::TABLE_RATE_LIMITS;
        $key     = $this->bucket_key( $prefix, (string) $identifier );
        $window  = $this->get_rate_window();
        $max     = $this->get_rate_max_attempts();
        $lockout = $this->get_rate_lockout();

        $wpdb->query( $wpdb->prepare( // phpcs:ignore WordPress.DB.DirectDatabaseQuery
            "INSERT IGNORE INTO {$table} (bucket_key, failure_count, window_expires_at, lock_expires_at, updated_at) VALUES (%s, 0, NULL, NULL, UTC_TIMESTAMP())", // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
            $key
        ) );

        $wpdb->query( $wpdb->prepare( // phpcs:ignore WordPress.DB.DirectDatabaseQuery
            "UPDATE {$table} SET
                failure_count = IF(window_expires_at IS NULL OR window_expires_at <= UTC_TIMESTAMP(), 1, failure_count + 1),
                window_expires_at = IF(window_expires_at IS NULL OR window_expires_at <= UTC_TIMESTAMP(), DATE_ADD(UTC_TIMESTAMP(), INTERVAL %d SECOND), window_expires_at),
                lock_expires_at = IF(
                    IF(window_expires_at IS NULL OR window_expires_at <= UTC_TIMESTAMP(), 1, failure_count + 1) >= %d,
                    DATE_ADD(UTC_TIMESTAMP(), INTERVAL %d SECOND),
                    IF(lock_expires_at IS NOT NULL AND lock_expires_at <= UTC_TIMESTAMP(), NULL, lock_expires_at)
                ),
                updated_at = UTC_TIMESTAMP()
            WHERE bucket_key = %s", // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
            $window, $max, $lockout, $key
        ) );

        if ( random_int( 1, 100 ) === 1 ) {
            $this->cleanup_rate_table();
        }
    }

    private function clear_failures( string $prefix, $identifier ): void {
        global $wpdb;
        $table = $wpdb->prefix . self::TABLE_RATE_LIMITS;
        $key   = $this->bucket_key( $prefix, (string) $identifier );
        $wpdb->query( $wpdb->prepare( // phpcs:ignore WordPress.DB.DirectDatabaseQuery
            "DELETE FROM {$table} WHERE bucket_key = %s", // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
            $key
        ) );
    }

    private function cleanup_rate_table(): void {
        global $wpdb;
        $table = $wpdb->prefix . self::TABLE_RATE_LIMITS;
        $wpdb->query( // phpcs:ignore WordPress.DB.DirectDatabaseQuery
            "DELETE FROM {$table} WHERE (lock_expires_at IS NULL OR lock_expires_at <= UTC_TIMESTAMP()) AND (window_expires_at IS NULL OR window_expires_at <= UTC_TIMESTAMP())" // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
        );
    }

    // ──────────────────────────────────────────────────────────
    // Private helpers — Misc
    // ──────────────────────────────────────────────────────────

    private function is_secure_context(): bool {
        return is_ssl() || ( defined( 'WPK_ALLOW_HTTP' ) && WPK_ALLOW_HTTP );
    }

    private function get_client_ip(): string {
        $ip = isset( $_SERVER['REMOTE_ADDR'] ) ? (string) $_SERVER['REMOTE_ADDR'] : '';
        if ( $ip === '' || false === filter_var( $ip, FILTER_VALIDATE_IP ) ) {
            return '0.0.0.0';
        }
        return $ip;
    }

    private function log_event( string $event, array $data = array() ): void {
        if ( ! defined( 'WPK_ENABLE_LOGGING' ) || ! WPK_ENABLE_LOGGING ) {
            return;
        }

        global $wpdb;
        $wpdb->insert(
            $wpdb->prefix . 'wpk_logs',
            array(
                'event_type'    => $event,
                'log_timestamp' => current_time( 'mysql' ),
                'user_agent'    => sanitize_text_field( wp_unslash( $_SERVER['HTTP_USER_AGENT'] ?? '' ) ),
                'log_data'      => wp_json_encode( $data ),
            ),
            array( '%s', '%s', '%s', '%s' )
        );
    }
}
