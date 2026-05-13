<?php
/**
 * PKFLOW_Passkeys — core WebAuthn engine.
 *
 * Handles:
 *  - DB table creation (credentials + rate limits)
 *  - AJAX endpoints for registration, login, revocation
 *  - Rate limiting
 *  - User eligibility (configurable by role and filters)
 *  - Per-user passkey cap (0 means unlimited)
 *
 * Extension points (filters / actions):
 *  - Filter  pkflow_is_eligible_user          ( bool, WP_User )
 *  - Filter  pkflow_max_passkeys_per_user      ( int,  WP_User )
 *  - Filter  pkflow_login_redirect             ( string redirect_url, WP_User )
 *  - Action  pkflow_passkey_registered         ( int user_id, string credential_hash )
 *  - Action  pkflow_passkey_login_success      ( int user_id, string credential_hash, string device_info )
 *  - Action  pkflow_passkey_revoked            ( int user_id, int credential_id )
 *
 * @package PKFLOW
 */

// phpcs:disable WordPress.Files.FileName.InvalidClassFileName -- legacy file naming kept for backward compatibility.

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

use lbuchs\WebAuthn\Binary\ByteBuffer;
use lbuchs\WebAuthn\WebAuthn;

/**
 * Passkey registration/authentication and credential lifecycle manager.
 */
class PKFLOW_Passkeys {
	/**
	 * Singleton instance.
	 *
	 * @var self|null
	 */

	private static $instance = null;

	const TABLE_CREDENTIALS    = 'pkflow_credentials';
	const TABLE_RATE_LIMITS    = 'pkflow_rate_limits';
	const DEFAULT_MAX_PASSKEYS = 0;

	// ──────────────────────────────────────────────────────────
	// Boot
	// ──────────────────────────────────────────────────────────

	/**
	 * Check whether passkeys are globally enabled.
	 *
	 * @return bool
	 */
	public static function is_enabled(): bool {
		if ( defined( 'PKFLOW_ENABLED' ) ) {
			return (bool) PKFLOW_ENABLED;
		}
		return (int) get_option( 'pkflow_enabled', 1 ) === 1;
	}

	/**
	 * Public static wrapper so shortcodes and external code can check eligibility
	 * without instantiating the full class.
	 *
	 * @param WP_User $user User instance.
	 * @return bool
	 */
	public static function user_is_eligible( WP_User $user ): bool {
		$allowed_roles = (array) get_option( 'pkflow_eligible_roles', array( 'administrator' ) );
		$eligible      = apply_filters( 'pkflow_is_eligible_user', null, $user );
		if ( null !== $eligible ) {
			return (bool) $eligible;
		}
		return ! empty( array_intersect( (array) $user->roles, $allowed_roles ) );
	}

	/**
	 * Constructor.
	 */
	public function __construct() {
		if ( ! self::is_enabled() ) {
			return;
		}

		if ( ! class_exists( 'lbuchs\\WebAuthn\\WebAuthn' ) ) {
			add_action( 'admin_notices', array( $this, 'render_missing_dependency_notice' ) );
			return;
		}

		self::$instance = $this;

		// One-time schema patch: remove raw AAGUID storage from the shared credentials table.
		if ( is_admin() && current_user_can( 'manage_options' ) && (int) get_option( 'pkflow_credentials_schema_v2', 0 ) !== 1 ) {
			self::ensure_credentials_schema_v2();
			update_option( 'pkflow_credentials_schema_v2', 1, false );
		}

		// Profile hooks.
		add_action( 'show_user_profile', array( $this, 'render_profile_section' ) );
		add_action( 'edit_user_profile', array( $this, 'render_profile_section' ) );
		add_action( 'admin_enqueue_scripts', array( $this, 'enqueue_profile_assets' ) );

		// Login hooks.
		add_action( 'login_enqueue_scripts', array( $this, 'enqueue_login_assets' ) );

		// Admin: Users list column.
		add_filter( 'manage_users_columns', array( $this, 'users_column_header' ) );
		add_filter( 'manage_users_custom_column', array( $this, 'users_column_content' ), 10, 3 );

		// Admin: passkey setup nudge notice.
		add_action( 'admin_notices', array( $this, 'render_setup_notice' ) );
		add_action( 'wp_ajax_pkflow_dismiss_notice', array( $this, 'ajax_dismiss_notice' ) );

		// Cron: scheduled cleanup.
		add_action( 'pkflow_scheduled_cleanup', array( $this, 'run_scheduled_cleanup' ) );

		// AJAX — authenticated (registration + revocation).
		add_action( 'wp_ajax_pkflow_begin_registration', array( $this, 'ajax_begin_registration' ) );
		add_action( 'wp_ajax_pkflow_finish_registration', array( $this, 'ajax_finish_registration' ) );
		add_action( 'wp_ajax_pkflow_revoke_credential', array( $this, 'ajax_revoke_credential' ) );

		// AJAX — public + authenticated (login).
		add_action( 'wp_ajax_nopriv_pkflow_begin_login', array( $this, 'ajax_begin_login' ) );
		add_action( 'wp_ajax_pkflow_begin_login', array( $this, 'ajax_begin_login' ) );
		add_action( 'wp_ajax_nopriv_pkflow_finish_login', array( $this, 'ajax_finish_login' ) );
		add_action( 'wp_ajax_pkflow_finish_login', array( $this, 'ajax_finish_login' ) );
	}

	/**
	 * Return singleton instance when initialized.
	 *
	 * @return self|null
	 */
	public static function get_instance(): ?self {
		return self::$instance;
	}

	// ──────────────────────────────────────────────────────────
	// Database
	// ──────────────────────────────────────────────────────────

	/**
	 * Create plugin database tables.
	 */
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

		$logs     = $wpdb->prefix . 'pkflow_logs';
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

		self::ensure_credentials_schema_v2();
		update_option( 'pkflow_credentials_schema_v2', 1, false );
	}

	/**
	 * Ensure credential table schema upgrades are applied.
	 */
	private static function ensure_credentials_schema_v2(): void {
		global $wpdb;

		$table = $wpdb->prefix . self::TABLE_CREDENTIALS;
		$like  = $wpdb->esc_like( $table );
		$row   = (string) $wpdb->get_var( $wpdb->prepare( 'SHOW TABLES LIKE %s', $like ) ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery
		if ( $table !== $row ) {
			return;
		}

		$column = $wpdb->get_var( $wpdb->prepare( "SHOW COLUMNS FROM {$table} LIKE %s", 'aaguid' ) ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery,WordPress.DB.PreparedSQL.InterpolatedNotPrepared
		if ( ! empty( $column ) ) {
			$wpdb->query( "ALTER TABLE {$table} DROP COLUMN aaguid" ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery,WordPress.DB.PreparedSQL.InterpolatedNotPrepared
		}
	}

	/**
	 * Drop plugin-owned database tables.
	 */
	public static function drop_tables(): void {
		global $wpdb;
		$wpdb->query( 'DROP TABLE IF EXISTS ' . $wpdb->prefix . self::TABLE_CREDENTIALS ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery,WordPress.DB.PreparedSQL.NotPrepared
		$wpdb->query( 'DROP TABLE IF EXISTS ' . $wpdb->prefix . self::TABLE_RATE_LIMITS );  // phpcs:ignore WordPress.DB.DirectDatabaseQuery,WordPress.DB.PreparedSQL.NotPrepared
		$wpdb->query( 'DROP TABLE IF EXISTS ' . $wpdb->prefix . 'pkflow_logs' );               // phpcs:ignore WordPress.DB.DirectDatabaseQuery,WordPress.DB.PreparedSQL.NotPrepared
	}

	// ──────────────────────────────────────────────────────────
	// Admin notices
	// ──────────────────────────────────────────────────────────

	/**
	 * Render admin notice when WebAuthn dependency is missing.
	 */
	public function render_missing_dependency_notice(): void {
		if ( ! current_user_can( 'manage_options' ) ) {
			return;
		}
		echo '<div class="notice notice-error"><p>' .
			esc_html__( 'Advanced Passkeys for Secure Login: The WebAuthn library is missing. Run composer install in the advanced-passkey-login plugin directory.', 'advanced-passkey-login' ) .
			'</p></div>';
	}

	// ──────────────────────────────────────────────────────────
	// Admin: passkey setup nudge notice
	// ──────────────────────────────────────────────────────────

	/**
	 * Render setup notice for eligible admins without passkeys.
	 */
	public function render_setup_notice(): void {
		if ( ! is_admin() || ! current_user_can( 'manage_options' ) ) {
			return;
		}

		if ( function_exists( 'get_current_screen' ) ) {
			$screen = get_current_screen();
			if ( ! $screen || ! in_array( (string) $screen->base, array( 'profile', 'user-edit' ), true ) ) {
				return;
			}
		}

		if ( ! (int) get_option( 'pkflow_show_setup_notice', 1 ) ) {
			return;
		}

		$user = wp_get_current_user();
		if ( ! $this->is_eligible_user( $user ) ) {
			return;
		}

		$dismissed_key = 'pkflow_notice_dismissed_' . (int) $user->ID;
		if ( get_user_meta( (int) $user->ID, $dismissed_key, true ) ) {
			return;
		}

		if ( $this->has_any_user_credentials( (int) $user->ID ) ) {
			return;
		}

		$profile_url = admin_url( 'profile.php#pkflow-profile-section' );
		$nonce       = wp_create_nonce( 'pkflow_dismiss_notice' );
		?>
		<div class="notice notice-info is-dismissible pkflow-setup-notice" data-nonce="<?php echo esc_attr( $nonce ); ?>">
			<p>
				<strong><?php esc_html_e( 'Set up a passkey for faster, more secure sign-ins.', 'advanced-passkey-login' ); ?></strong>
				<?php
				printf(
					wp_kses(
						/* translators: %s profile URL */
						__( ' <a href="%s">Register a passkey now</a> — sign in with Face ID, Touch ID, or a security key, no password needed.', 'advanced-passkey-login' ),
						array( 'a' => array( 'href' => array() ) )
					),
					esc_url( $profile_url )
				);
				?>
			</p>
		</div>
		<?php
	}

	/**
	 * Handle setup-notice dismissal AJAX request.
	 */
	public function ajax_dismiss_notice(): void {
		if ( ! check_ajax_referer( 'pkflow_dismiss_notice', 'nonce', false ) ) {
			wp_send_json_error( null, 403 );
		}

		if ( ! is_user_logged_in() ) {
			wp_send_json_error( null, 403 );
		}

		$user_id = get_current_user_id();
		if ( $user_id <= 0 ) {
			wp_send_json_error( null, 403 );
		}

		if ( ! current_user_can( 'edit_user', $user_id ) ) {
			wp_send_json_error( null, 403 );
		}

		update_user_meta( $user_id, 'pkflow_notice_dismissed_' . $user_id, 1 );
		wp_send_json_success();
	}

	// ──────────────────────────────────────────────────────────
	// Admin: Users list passkey column
	// ──────────────────────────────────────────────────────────

	/**
	 * Register users table header for passkey counts.
	 *
	 * @param array<string, string> $columns Users table columns.
	 * @return array<string, string>
	 */
	public function users_column_header( array $columns ): array {
		$columns['pkflow_passkeys'] = __( 'Passkeys', 'advanced-passkey-login' );
		return $columns;
	}

	/**
	 * Render users list custom column contents.
	 *
	 * @param string $output      Existing output.
	 * @param string $column_name Column key.
	 * @param int    $user_id     User ID.
	 * @return string
	 */
	public function users_column_content( string $output, string $column_name, int $user_id ): string {
		if ( 'pkflow_passkeys' !== $column_name ) {
			return $output;
		}

		$user = get_user_by( 'id', $user_id );
		if ( ! $user || ! $this->is_eligible_user( $user ) ) {
			return '<span class="pkflow-user-passkeys-muted">—</span>';
		}

		$count = $this->count_user_credentials( $user_id );
		if ( 0 === $count ) {
			return '<span class="pkflow-user-passkeys-muted">0</span>';
		}

		$url = add_query_arg(
			array(
				'user_id' => $user_id,
				'anchor'  => 'pkflow-profile-section',
			),
			admin_url( 'user-edit.php' )
		);
		return sprintf(
			'<a href="%s" title="%s">%d</a>',
			esc_url( $url ),
			esc_attr(
				sprintf(
				/* translators: %d passkey count, %s username */
					__( '%1$d passkey(s) for %2$s — click to manage', 'advanced-passkey-login' ),
					$count,
					$user->user_login
				)
			),
			$count
		);
	}

	/**
	 * Register sortable keys for users list custom columns.
	 *
	 * @param array<string, string> $columns Users table columns.
	 * @return array<string, string>
	 */
	public function users_column_sortable( array $columns ): array {
		$columns['pkflow_passkeys'] = 'pkflow_passkeys';
		return $columns;
	}

	// ──────────────────────────────────────────────────────────
	// Cron: scheduled cleanup
	// ──────────────────────────────────────────────────────────

	/**
	 * Schedule recurring cleanup cron hook.
	 */
	public static function schedule_cron(): void {
		if ( ! wp_next_scheduled( 'pkflow_scheduled_cleanup' ) ) {
			wp_schedule_event( time(), 'daily', 'pkflow_scheduled_cleanup' );
		}
	}

	/**
	 * Unschedule plugin cleanup cron hook.
	 */
	public static function unschedule_cron(): void {
		if ( function_exists( 'wp_clear_scheduled_hook' ) ) {
			wp_clear_scheduled_hook( 'pkflow_scheduled_cleanup' );
			return;
		}

		$timestamp = wp_next_scheduled( 'pkflow_scheduled_cleanup' );
		while ( $timestamp ) {
			wp_unschedule_event( $timestamp, 'pkflow_scheduled_cleanup' );
			$timestamp = wp_next_scheduled( 'pkflow_scheduled_cleanup' );
		}
	}

	/**
	 * Run recurring cleanup tasks.
	 */
	public function run_scheduled_cleanup(): void {
		global $wpdb;

		// Purge expired rate-limit rows.
		$rate_table = esc_sql( $wpdb->prefix . self::TABLE_RATE_LIMITS );
		$wpdb->query( // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching -- maintenance delete on plugin-owned custom rate table.
			"DELETE FROM {$rate_table} WHERE (lock_expires_at IS NULL OR lock_expires_at <= UTC_TIMESTAMP()) AND (window_expires_at IS NULL OR window_expires_at <= UTC_TIMESTAMP())" // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
		);

		// Purge log rows older than the configured retention window.
		$keep_days = max( 7, (int) get_option( 'pkflow_log_retention_days', 90 ) );
		$log_table = esc_sql( $wpdb->prefix . 'pkflow_logs' );
		$wpdb->query( // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching -- maintenance delete on plugin-owned log table.
			$wpdb->prepare( // phpcs:ignore WordPress.DB.DirectDatabaseQuery
				"DELETE FROM {$log_table} WHERE log_timestamp < DATE_SUB(UTC_TIMESTAMP(), INTERVAL %d DAY)", // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
				$keep_days
			)
		);
	}

	// ──────────────────────────────────────────────────────────
	// Asset enqueuing
	// ──────────────────────────────────────────────────────────

	/**
	 * Enqueue profile assets on eligible user profile screens.
	 *
	 * @param string $hook Current admin hook suffix.
	 */
	public function enqueue_profile_assets( string $hook ): void {
		if ( 'profile.php' !== $hook && 'user-edit.php' !== $hook ) {
			return;
		}

		$screen_uid = get_current_user_id();
		if ( 'user-edit.php' === $hook ) {
			global $user_id;
			if ( isset( $user_id ) ) {
				$screen_uid = absint( $user_id );
			}
		}

		if ( $screen_uid < 1 ) {
			return;
		}

		$target_user = get_user_by( 'id', $screen_uid );

		if ( ! $target_user || ! $this->is_eligible_user( $target_user ) ) {
			return;
		}

		wp_enqueue_script(
			'pkflow-profile',
			PKFLOW_PLUGIN_URL . 'admin/js/pkflow-profile.js',
			array(),
			PKFLOW_VERSION,
			true
		);

		wp_localize_script(
			'pkflow-profile',
			'PKFLOWProfile',
			array(
				'ajaxUrl'  => admin_url( 'admin-ajax.php' ),
				'nonce'    => wp_create_nonce( 'pkflow_profile' ),
				'messages' => array(
					'labelPlaceholder' => __( 'e.g. iPhone 15, YubiKey 5', 'advanced-passkey-login' ),
					'starting'         => __( 'Starting passkey registration…', 'advanced-passkey-login' ),
					'success'          => __( 'Passkey registered successfully.', 'advanced-passkey-login' ),
					'failed'           => __( 'Passkey registration failed. Try again.', 'advanced-passkey-login' ),
					'notSupported'     => __( 'This browser does not support passkeys.', 'advanced-passkey-login' ),
					'mobileHint'       => __( 'Tip: open this page on your phone to save a passkey to iCloud Keychain or Google Password Manager.', 'advanced-passkey-login' ),
					'confirmRevoke'    => __( 'Revoke this passkey? You will need to re-register to use it again.', 'advanced-passkey-login' ),
					'revokeFailed'     => __( 'Failed to revoke passkey.', 'advanced-passkey-login' ),
					'limitReached'     => __( 'You have reached the maximum number of passkeys. Revoke an existing one to add a new one.', 'advanced-passkey-login' ),
				),
			)
		);

		wp_enqueue_style( 'pkflow-admin', PKFLOW_PLUGIN_URL . 'admin/css/pkflow-admin.css', array(), PKFLOW_VERSION );
	}

	/**
	 * Enqueue login-page assets.
	 */
	public function enqueue_login_assets(): void {
		wp_enqueue_script(
			'pkflow-login',
			PKFLOW_PLUGIN_URL . 'admin/js/pkflow-login.js',
			array(),
			PKFLOW_VERSION,
			true
		);

		wp_localize_script(
			'pkflow-login',
			'PKFLOWLogin',
			array(
				'ajaxUrl'  => admin_url( 'admin-ajax.php' ),
				'nonce'    => wp_create_nonce( 'pkflow_login' ),
				'messages' => array(
					'notSupported' => __( 'Passkeys are unavailable here. Use HTTPS (or localhost) in a passkey-capable browser, or sign in with your password.', 'advanced-passkey-login' ),
					'genericError' => __( 'Passkey sign-in failed. Please try again or use your password.', 'advanced-passkey-login' ),
					'signingIn'    => __( 'Signing in…', 'advanced-passkey-login' ),
				),
			)
		);

		wp_enqueue_style( 'pkflow-login', PKFLOW_PLUGIN_URL . 'admin/css/pkflow-admin.css', array(), PKFLOW_VERSION );
	}

	// ──────────────────────────────────────────────────────────
	// Profile section UI
	// ──────────────────────────────────────────────────────────

	/**
	 * Render passkey profile section for eligible users.
	 *
	 * @param WP_User $user User being edited.
	 */
	public function render_profile_section( WP_User $user ): void {
		if ( ! $this->is_eligible_user( $user ) ) {
			return;
		}

		if ( (int) get_current_user_id() !== (int) $user->ID && ! current_user_can( 'edit_users' ) ) {
			return;
		}

		$credentials  = $this->get_user_credentials_meta( (int) $user->ID );
		$max_passkeys = $this->get_max_passkeys_per_user( $user );
		$at_limit     = count( $credentials ) >= $max_passkeys;
		$max_display  = $max_passkeys >= 999999 ? __( 'unlimited', 'advanced-passkey-login' ) : (string) $max_passkeys;
		?>
		<div class="pkflow-profile-section" id="pkflow-profile-section">

			<div class="pkflow-profile-header">
				<div>
					<h2><?php esc_html_e( 'Passkeys', 'advanced-passkey-login' ); ?></h2>
					<p><?php esc_html_e( 'Sign in with your fingerprint, face, or a hardware security key — no password needed.', 'advanced-passkey-login' ); ?></p>
				</div>
				<span class="pkflow-profile-count">
					<?php echo esc_html( count( $credentials ) ); ?>&thinsp;/&thinsp;<?php echo esc_html( $max_display ); ?>
					<span class="pkflow-profile-count-label"><?php esc_html_e( 'passkeys', 'advanced-passkey-login' ); ?></span>
				</span>
			</div>

			<div class="pkflow-profile-card">

				<div class="pkflow-profile-register-row">
					<div class="pkflow-profile-register-header">
						<span class="pkflow-profile-register-title"><?php esc_html_e( 'Register new passkey', 'advanced-passkey-login' ); ?></span>
					</div>

					<?php if ( $at_limit ) : ?>
						<div class="pkflow-profile-limit-notice">
							<?php
							printf(
								/* translators: %d number of passkeys */
								esc_html__( 'You have reached the maximum of %d passkeys. Revoke one to add another.', 'advanced-passkey-login' ),
								(int) $max_passkeys
							);
							?>
							<?php do_action( 'pkflow_profile_limit_reached_cta', $user ); ?>
						</div>
					<?php else : ?>
						<div class="pkflow-profile-register-controls">
							<label for="pkflow-passkey-label" class="screen-reader-text"><?php esc_html_e( 'Device label (optional)', 'advanced-passkey-login' ); ?></label>
							<input type="text"
									id="pkflow-passkey-label"
									class="pkflow-profile-label-input"
									placeholder="<?php esc_attr_e( 'Device label (optional)', 'advanced-passkey-login' ); ?>"
									maxlength="100" />
							<button type="button" class="pkflow-profile-btn" id="pkflow-passkey-register">
								<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M12 10a2 2 0 0 0-2 2c0 1.02-.1 2.51-.26 4"/><path d="M14 13.12c0 2.38 0 6.38-1 8.88"/><path d="M17.29 21.02c.12-.6.43-2.3.5-3.02"/><path d="M2 12a10 10 0 0 1 18-6"/><path d="M2 16h.01"/><path d="M21.8 16c.2-2 .131-5.354 0-6"/><path d="M5 19.5C5.5 18 6 15 6 12a6 6 0 0 1 .34-2"/><path d="M8.65 22c.21-.66.45-1.32.57-2"/><path d="M9 6.8a6 6 0 0 1 9 5.2v2"/></svg>
								<?php esc_html_e( 'Register New Passkey', 'advanced-passkey-login' ); ?>
							</button>
							<p class="pkflow-profile-tip"><?php esc_html_e( 'Tip: open this page on your phone to save to iCloud Keychain or Google Password Manager.', 'advanced-passkey-login' ); ?></p>
							<p id="pkflow-passkey-profile-message" class="pkflow-inline-message" role="alert" aria-live="assertive"></p>
						</div>
					<?php endif; ?>
				</div>

				<?php if ( ! empty( $credentials ) ) : ?>
				<div class="pkflow-profile-creds">
					<?php if ( 1 === count( $credentials ) ) : ?>
						<div class="pkflow-profile-warning">
							<svg xmlns="http://www.w3.org/2000/svg" width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M10.29 3.86 1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>
							<?php esc_html_e( 'Only one passkey registered. Add a backup on another device to avoid getting locked out.', 'advanced-passkey-login' ); ?>
						</div>
					<?php endif; ?>

					<table class="pkflow-creds-table">
						<thead>
							<tr>
								<th><?php esc_html_e( 'Label', 'advanced-passkey-login' ); ?></th>
								<th><?php esc_html_e( 'Registered', 'advanced-passkey-login' ); ?></th>
								<th><?php esc_html_e( 'Last Used', 'advanced-passkey-login' ); ?></th>
								<?php do_action( 'pkflow_profile_table_header', $user ); ?>
								<th><?php esc_html_e( 'Action', 'advanced-passkey-login' ); ?></th>
							</tr>
						</thead>
						<tbody>
							<?php foreach ( $credentials as $cred ) : ?>
								<tr data-credential-id="<?php echo esc_attr( (string) $cred->id ); ?>">
									<td class="pkflow-creds-label">
										<span class="pkflow-creds-dot" aria-hidden="true"></span>
										<?php echo esc_html( '' !== (string) $cred->credential_label ? (string) $cred->credential_label : __( 'Passkey', 'advanced-passkey-login' ) ); ?>
									</td>
									<td><?php echo esc_html( $this->format_utc_datetime_for_display( (string) $cred->created_at ) ); ?></td>
									<td><?php echo null !== $cred->last_used_at ? esc_html( $this->format_utc_datetime_for_display( (string) $cred->last_used_at ) ) : esc_html__( 'Never', 'advanced-passkey-login' ); ?></td>
									<?php do_action( 'pkflow_profile_table_row', $cred, $user ); ?>
									<td>
										<button class="pkflow-revoke-btn pkflow-passkey-revoke" type="button">
											<?php esc_html_e( 'Revoke', 'advanced-passkey-login' ); ?>
										</button>
									</td>
								</tr>
							<?php endforeach; ?>
						</tbody>
					</table>
				</div>
				<?php endif; ?>

			</div><!-- .pkflow-profile-card -->
		</div><!-- .pkflow-profile-section -->
		<?php
	}

	// ──────────────────────────────────────────────────────────
	// AJAX: Begin Registration
	// ──────────────────────────────────────────────────────────

	/**
	 * Start passkey registration ceremony.
	 */
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

		if ( ! check_ajax_referer( 'pkflow_profile', 'nonce', false ) ) {
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

		// Enforce per-user passkey cap.
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
				$this->get_registration_challenge_ttl(),
				true,
				$this->get_user_verification(),
				null,
				$exclude_ids
			);

			$token = wp_generate_password( 32, false, false );
			set_transient(
				'pkflow_reg_' . $token,
				array(
					'user_id'   => (int) $user->ID,
					'challenge' => base64_encode( $web_authn->getChallenge()->getBinaryString() ), // phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.obfuscation_base64_encode -- WebAuthn challenge binary is stored in transient-safe format.
				),
				$this->get_registration_challenge_ttl()
			);

			$this->clear_failures( 'reg_begin_ip', $ip );
			$this->clear_failures( 'reg_begin_user', (int) $user->ID );

			wp_send_json_success(
				array(
					'options' => $create_args,
					'token'   => $token,
				)
			);

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

	/**
	 * Complete passkey registration ceremony.
	 *
	 * @throws \RuntimeException When WebAuthn registration payload validation fails.
	 */
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

		if ( ! check_ajax_referer( 'pkflow_profile', 'nonce', false ) ) {
			$this->record_failure( 'reg_finish_ip', $ip );
			wp_send_json_error( array( 'message' => 'Invalid request.' ), 403 );
		}

		$user = wp_get_current_user();
		if ( $this->is_locked_out( 'reg_finish_user', (int) $user->ID ) ) {
			wp_send_json_error( array( 'message' => 'Too many attempts. Please wait and try again.' ), 429 );
		}

		if ( ! current_user_can( 'edit_user', (int) $user->ID ) ) {
			$this->record_failure( 'reg_finish_ip', $ip );
			$this->record_failure( 'reg_finish_user', (int) $user->ID );
			wp_send_json_error( array( 'message' => 'Unauthorized' ), 403 );
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

		$state = get_transient( 'pkflow_reg_' . $token );
		if ( ! $state || empty( $state['challenge'] ) || (int) $user->ID !== (int) $state['user_id'] ) {
			$this->record_failure( 'reg_finish_ip', $ip );
			$this->record_failure( 'reg_finish_user', (int) $user->ID );
			wp_send_json_error( array( 'message' => 'Registration session expired.' ), 400 );
		}

		delete_transient( 'pkflow_reg_' . $token );

		$client_data = isset( $_POST['clientDataJSON'] ) ? sanitize_text_field( wp_unslash( $_POST['clientDataJSON'] ) ) : '';
		$attestation = isset( $_POST['attestationObject'] ) ? sanitize_text_field( wp_unslash( $_POST['attestationObject'] ) ) : '';
		$label_raw   = isset( $_POST['label'] ) ? sanitize_text_field( wp_unslash( $_POST['label'] ) ) : '';
		$label       = '' !== $label_raw ? substr( $label_raw, 0, 100 ) : 'Passkey';

		// Validate transports: decode JSON, allowlist known values, re-encode.
		$transports       = '';
		$transports_input = '';
		$transports_raw   = isset( $_POST['transports'] ) ? sanitize_text_field( wp_unslash( $_POST['transports'] ) ) : '';
		if ( is_string( $transports_raw ) ) {
			$transports_input = wp_check_invalid_utf8( $transports_raw );
		}
		if ( '' !== $transports_input ) {
			$raw_transports = json_decode( $transports_input, true );
			if ( is_array( $raw_transports ) ) {
				$allowed_transports = array( 'usb', 'nfc', 'ble', 'internal', 'hybrid', 'cable', 'smart-card' );
				$clean_transports   = array_values( array_intersect( array_map( 'sanitize_key', $raw_transports ), $allowed_transports ) );
				$transports         = (string) wp_json_encode( $clean_transports );
			}
		}

		if ( '' === $client_data || '' === $attestation ) {
			$this->record_failure( 'reg_finish_ip', $ip );
			$this->record_failure( 'reg_finish_user', (int) $user->ID );
			wp_send_json_error( array( 'message' => 'Incomplete passkey response.' ), 400 );
		}

		try {
			$web_authn = $this->new_webauthn();
			$challenge = base64_decode( $state['challenge'], true ); // phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.obfuscation_base64_decode -- decodes previously stored WebAuthn challenge bytes.
			if ( false === $challenge ) {
				throw new \RuntimeException( 'Challenge decode failed' );
			}

			$result = $web_authn->processCreate(
				$this->decode_b64url( $client_data ),
				$this->decode_b64url( $attestation ),
				$challenge,
				'required' === $this->get_user_verification(),
				true,
				false
			);

			// phpcs:disable WordPress.NamingConventions.ValidVariableName.UsedPropertyNotSnakeCase
			$cred_id   = $this->encode_b64url( $result->credentialId );
			$cred_hash = hash( 'sha256', $cred_id );

			global $wpdb;
			$table = $wpdb->prefix . self::TABLE_CREDENTIALS;

			$wpdb->insert( // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching -- custom credentials table write during registration.
				$table,
				array(
					'user_id'               => (int) $user->ID,
					'credential_id'         => $cred_id,
					'credential_id_hash'    => $cred_hash,
					'credential_public_key' => (string) $result->credentialPublicKey,
					'sign_count'            => null !== $result->signatureCounter ? (int) $result->signatureCounter : 0,
					'transports'            => $transports,
					'credential_label'      => $label,
					'backed_up'             => ! empty( $result->isBackedUp ) ? 1 : 0,
					'created_at'            => gmdate( 'Y-m-d H:i:s' ),
					'last_used_at'          => null,
					'revoked_at'            => null,
				),
				array( '%d', '%s', '%s', '%s', '%d', '%s', '%s', '%d', '%s', '%s', '%s' )
			);
			// phpcs:enable WordPress.NamingConventions.ValidVariableName.UsedPropertyNotSnakeCase

			if ( $wpdb->last_error ) {
				throw new \RuntimeException( $wpdb->last_error );
			}

			$this->log_event(
				'registered',
				array(
					'user_id'         => (int) $user->ID,
					'credential_hash' => $cred_hash,
				)
			);

			/**
			 * Fires after a passkey is successfully registered.
			 *
			 * @param int    $user_id         WordPress user ID.
			 * @param string $credential_hash SHA-256 hash of the credential ID.
			 */
			do_action( 'pkflow_passkey_registered', (int) $user->ID, $cred_hash );

			$this->clear_failures( 'reg_finish_ip', $ip );
			$this->clear_failures( 'reg_finish_user', (int) $user->ID );

			wp_send_json_success( array( 'message' => 'Passkey registered.' ) );

		} catch ( \Throwable $e ) {
			$this->record_failure( 'reg_finish_ip', $ip );
			$this->record_failure( 'reg_finish_user', (int) $user->ID );
			$this->log_event(
				'registration_failed',
				array(
					'user_id' => (int) $user->ID,
					'message' => $e->getMessage(),
				)
			);
			wp_send_json_error( array( 'message' => 'Passkey registration failed.' ), 400 );
		}
	}

	// ──────────────────────────────────────────────────────────
	// AJAX: Revoke Credential
	// ──────────────────────────────────────────────────────────

	/**
	 * Revoke an existing passkey credential.
	 */
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

		if ( ! check_ajax_referer( 'pkflow_profile', 'nonce', false ) ) {
			$this->record_failure( 'revoke_ip', $ip );
			wp_send_json_error( array( 'message' => 'Invalid request.' ), 403 );
		}

		$user            = wp_get_current_user();
		$cred_row_id_raw = filter_input( INPUT_POST, 'credentialId', FILTER_SANITIZE_NUMBER_INT );
		$cred_row_id     = is_string( $cred_row_id_raw ) ? absint( $cred_row_id_raw ) : 0;

		if ( $cred_row_id < 1 ) {
			wp_send_json_error( array( 'message' => 'Invalid credential.' ), 400 );
		}

		global $wpdb;
		$table = $wpdb->prefix . self::TABLE_CREDENTIALS;

		$cred = $wpdb->get_row( // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching -- credential ownership check against custom table.
			$wpdb->prepare( // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching -- credential ownership check against custom table.
				"SELECT id, user_id FROM {$table} WHERE id = %d AND revoked_at IS NULL LIMIT 1", // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
				$cred_row_id
			)
		);

		if ( ! $cred ) {
			wp_send_json_error( array( 'message' => 'Credential not found.' ), 404 );
		}

		if ( ! current_user_can( 'edit_user', (int) $cred->user_id ) ) {
			wp_send_json_error( array( 'message' => 'Unauthorized' ), 403 );
		}

		$wpdb->update( // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching -- custom credentials table revoke timestamp update.
			$table,
			array( 'revoked_at' => current_time( 'mysql' ) ),
			array( 'id' => $cred_row_id ),
			array( '%s' ),
			array( '%d' )
		);

		$this->log_event(
			'revoked',
			array(
				'user_id'       => (int) $cred->user_id,
				'credential_id' => $cred_row_id,
			)
		);

		/**
		 * Fires after a passkey is revoked.
		 *
		 * @param int $user_id       WordPress user ID.
		 * @param int $credential_id DB row ID of the revoked credential.
		 */
		do_action( 'pkflow_passkey_revoked', (int) $cred->user_id, $cred_row_id );

		wp_send_json_success( array( 'message' => 'Passkey revoked.' ) );
	}

	// ──────────────────────────────────────────────────────────
	// AJAX: Begin Login
	// ──────────────────────────────────────────────────────────

	/**
	 * Start passkey login ceremony.
	 */
	public function ajax_begin_login(): void {
		$ip = $this->get_client_ip();

		if ( $this->is_locked_out( 'login_begin_ip', $ip ) ) {
			$this->log_event( 'login_rate_limited', array( 'ip' => $ip ) );
			wp_send_json_error( array( 'message' => 'Too many attempts. Please wait and try again.' ), 429 );
		}

		if ( ! $this->is_secure_context() ) {
			$this->record_failure( 'login_begin_ip', $ip );
			wp_send_json_error( array( 'message' => 'Passkeys require HTTPS.' ), 400 );
		}

		if ( ! check_ajax_referer( 'pkflow_login', 'nonce', false ) ) {
			$this->record_failure( 'login_begin_ip', $ip );
			wp_send_json_error( array( 'message' => 'Invalid request.' ), 403 );
		}

		$login       = isset( $_POST['login'] ) ? sanitize_text_field( wp_unslash( $_POST['login'] ) ) : '';
		$login_key   = '';
		$state_uid   = 0;
		$cred_rows   = array();
		$generic_err = 'Passkey sign-in could not be started. Please try again.';

		// Optional: username-based flow (non-discoverable / legacy credentials).
		if ( '' !== $login ) {
			$login_key = strtolower( $login );

			if ( $this->is_locked_out( 'login_begin_acct', $login_key ) ) {
				$this->log_event( 'login_rate_limited', array( 'ip' => $ip ) );
				wp_send_json_error( array( 'message' => 'Too many attempts. Please wait and try again.' ), 429 );
			}

			$user = $this->resolve_user( $login );
			if ( ! $user || ! $this->is_eligible_user( $user ) ) {
				$this->record_failure( 'login_begin_ip', $ip );
				$this->record_failure( 'login_begin_acct', $login_key );
				wp_send_json_error( array( 'message' => $generic_err ), 400 );
			}

			$cred_rows = $this->get_user_credentials( (int) $user->ID );
			if ( empty( $cred_rows ) ) {
				$this->record_failure( 'login_begin_ip', $ip );
				$this->record_failure( 'login_begin_acct', $login_key );
				wp_send_json_error( array( 'message' => $generic_err ), 400 );
			}

			$state_uid = (int) $user->ID;
		}

		try {
			$web_authn = $this->new_webauthn();
			$cred_ids  = array_map( fn( $r ) => $this->decode_b64url( $r->credential_id ), $cred_rows );

			$get_args = $web_authn->getGetArgs(
				$cred_ids,
				$this->get_login_challenge_ttl(),
				true,
				true,
				true,
				true,
				true,
				$this->get_user_verification()
			);

			$token = wp_generate_password( 32, false, false );
			set_transient(
				'pkflow_login_' . $token,
				array(
					'user_id'   => $state_uid,
					'challenge' => base64_encode( $web_authn->getChallenge()->getBinaryString() ), // phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.obfuscation_base64_encode -- WebAuthn challenge binary is stored in transient-safe format.
				),
				$this->get_login_challenge_ttl()
			);

			$this->clear_failures( 'login_begin_ip', $ip );
			if ( '' !== $login_key ) {
				$this->clear_failures( 'login_begin_acct', $login_key );
			}

			wp_send_json_success(
				array(
					'options' => $get_args,
					'token'   => $token,
				)
			);

		} catch ( \Throwable $e ) {
			$this->record_failure( 'login_begin_ip', $ip );
			if ( '' !== $login_key ) {
				$this->record_failure( 'login_begin_acct', $login_key );
			}
			$this->log_event( 'login_begin_failed', array( 'message' => $e->getMessage() ) );
			wp_send_json_error( array( 'message' => 'Could not start passkey sign-in.' ), 500 );
		}
	}

	// ──────────────────────────────────────────────────────────
	// AJAX: Finish Login
	// ──────────────────────────────────────────────────────────

	/**
	 * Complete passkey login ceremony.
	 *
	 * @throws \RuntimeException When credential assertions fail verification.
	 */
	public function ajax_finish_login(): void {
		$ip = $this->get_client_ip();

		if ( $this->is_locked_out( 'login_finish_ip', $ip ) ) {
			$this->log_event( 'login_rate_limited', array( 'ip' => $ip ) );
			wp_send_json_error( array( 'message' => 'Too many attempts. Please wait and try again.' ), 429 );
		}

		if ( ! $this->is_secure_context() ) {
			$this->record_failure( 'login_finish_ip', $ip );
			wp_send_json_error( array( 'message' => 'Passkeys require HTTPS.' ), 400 );
		}

		if ( ! check_ajax_referer( 'pkflow_login', 'nonce', false ) ) {
			$this->record_failure( 'login_finish_ip', $ip );
			wp_send_json_error( array( 'message' => 'Invalid request.' ), 403 );
		}

		$token = isset( $_POST['token'] ) ? sanitize_text_field( wp_unslash( $_POST['token'] ) ) : '';
		if ( '' === $token || ! preg_match( '/\A[a-zA-Z0-9]{20,64}\z/', $token ) ) {
			$this->record_failure( 'login_finish_ip', $ip );
			wp_send_json_error( array( 'message' => 'Login session expired.' ), 400 );
		}

		$state = get_transient( 'pkflow_login_' . $token );
		if ( ! $state || empty( $state['challenge'] ) || ! isset( $state['user_id'] ) ) {
			$this->record_failure( 'login_finish_ip', $ip );
			wp_send_json_error( array( 'message' => 'Login session expired.' ), 400 );
		}

		$state_uid = (int) $state['user_id'];

		if ( $state_uid > 0 && $this->is_locked_out( 'login_finish_user', $state_uid ) ) {
			$this->log_event( 'login_rate_limited', array( 'ip' => $ip ) );
			wp_send_json_error( array( 'message' => 'Too many attempts. Please wait and try again.' ), 429 );
		}

		delete_transient( 'pkflow_login_' . $token );

		$cred_id     = isset( $_POST['id'] ) ? sanitize_text_field( wp_unslash( $_POST['id'] ) ) : '';
		$client_data = isset( $_POST['clientDataJSON'] ) ? sanitize_text_field( wp_unslash( $_POST['clientDataJSON'] ) ) : '';
		$auth_data   = isset( $_POST['authenticatorData'] ) ? sanitize_text_field( wp_unslash( $_POST['authenticatorData'] ) ) : '';
		$signature   = isset( $_POST['signature'] ) ? sanitize_text_field( wp_unslash( $_POST['signature'] ) ) : '';
		$user_handle = isset( $_POST['userHandle'] ) ? sanitize_text_field( wp_unslash( $_POST['userHandle'] ) ) : '';

		if ( '' === $cred_id || '' === $client_data || '' === $auth_data || '' === $signature ) {
			$this->record_failure( 'login_finish_ip', $ip );
			if ( $state_uid > 0 ) {
				$this->record_failure( 'login_finish_user', $state_uid );
			}
			wp_send_json_error( array( 'message' => 'Incomplete passkey response.' ), 400 );
		}

		global $wpdb;
		$table     = $wpdb->prefix . self::TABLE_CREDENTIALS;
		$cred_hash = hash( 'sha256', $cred_id );

		if ( 0 === $state_uid && $this->is_locked_out( 'login_finish_cred', $cred_hash ) ) {
			$this->log_event( 'login_rate_limited', array( 'ip' => $ip ) );
			wp_send_json_error( array( 'message' => 'Too many attempts. Please wait and try again.' ), 429 );
		}

		// Fetch stored credential.
		if ( $state_uid > 0 ) {
			$cred = $wpdb->get_row( // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching -- custom credential lookup for user-bound login flow.
				$wpdb->prepare( // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching -- custom credential lookup for user-bound login flow.
					"SELECT * FROM {$table} WHERE credential_id_hash = %s AND user_id = %d AND revoked_at IS NULL LIMIT 1", // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
					$cred_hash,
					$state_uid
				)
			);
		} else {
			$cred = $wpdb->get_row( // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching -- custom credential lookup for discoverable login flow.
				$wpdb->prepare( // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching -- custom credential lookup for discoverable login flow.
					"SELECT * FROM {$table} WHERE credential_id_hash = %s AND revoked_at IS NULL LIMIT 1", // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
					$cred_hash
				)
			);
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
			$this->log_event( 'login_rate_limited', array( 'ip' => $ip ) );
			wp_send_json_error( array( 'message' => 'Too many attempts. Please wait and try again.' ), 429 );
		}

		try {
			$web_authn = $this->new_webauthn();
			$challenge = base64_decode( $state['challenge'], true ); // phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.obfuscation_base64_decode -- decodes previously stored WebAuthn challenge bytes.
			if ( false === $challenge ) {
				throw new \RuntimeException( 'Challenge decode failed' );
			}

			$web_authn->processGet(
				$this->decode_b64url( $client_data ),
				$this->decode_b64url( $auth_data ),
				$this->decode_b64url( $signature ),
				$cred->credential_public_key,
				$challenge,
				is_null( $cred->sign_count ) ? null : (int) $cred->sign_count,
				'required' === $this->get_user_verification(),
				true
			);

			// Verify user handle (discoverable credential).
			if ( '' !== $user_handle ) {
				$decoded_handle  = $this->decode_b64url( $user_handle );
				$expected_handle = 'wp-user-' . (string) ( (int) $cred->user_id );
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
			wp_set_auth_cookie( (int) $user->ID, false );
			do_action( 'wp_login', $user->user_login, $user ); // phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedHooknameFound -- core WordPress hook.

			// Update sign count and last-used timestamp.
			$next_count = $web_authn->getSignatureCounter();
			$wpdb->update( // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching -- persist signature counter/last-used metadata in custom table.
				$table,
				array(
					'sign_count'   => null === $next_count ? (int) $cred->sign_count : (int) $next_count,
					'last_used_at' => gmdate( 'Y-m-d H:i:s' ),
				),
				array( 'id' => (int) $cred->id ),
				array( '%d', '%s' ),
				array( '%d' )
			);

			$this->log_event(
				'login_success',
				array(
					'user_id'         => (int) $user->ID,
					'credential_hash' => $cred_hash,
				)
			);

			/**
			 * Fires after a successful passkey login.
			 *
			 * @param int    $user_id         WordPress user ID.
			 * @param string $credential_hash SHA-256 hash of the credential ID.
			 * @param string $user_agent       Raw User-Agent string.
			 */
			do_action( 'pkflow_passkey_login_success', (int) $user->ID, $cred_hash, sanitize_text_field( wp_unslash( $_SERVER['HTTP_USER_AGENT'] ?? '' ) ) );

			$this->clear_failures( 'login_finish_ip', $ip );
			$this->clear_failures( 'login_finish_user', (int) $user->ID );
			$this->clear_failures( 'login_finish_cred', $cred_hash );

			// Determine redirect target.
			$request_redirect     = '';
			$request_redirect_raw = filter_input( INPUT_POST, 'redirect_to', FILTER_SANITIZE_URL );
			if ( is_string( $request_redirect_raw ) && '' !== $request_redirect_raw ) {
				$request_redirect = esc_url_raw( wp_unslash( $request_redirect_raw ) );
			}
			$redirect = '' !== $request_redirect ? $this->safe_redirect( $request_redirect ) : '';

			if ( '' === $redirect && isset( $_COOKIE['pkflow_redirect_to'] ) ) {
				$cookie_redirect_raw = wp_unslash( $_COOKIE['pkflow_redirect_to'] ); // phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- sanitized via esc_url_raw/safe_redirect.
				if ( is_string( $cookie_redirect_raw ) ) {
					$redirect = $this->safe_redirect( esc_url_raw( $cookie_redirect_raw ) );
				}
			}

			$this->clear_redirect_cookie();

			// Fall back to the settings-page redirect URL.
			if ( '' === $redirect ) {
				$settings_redirect = (string) get_option( 'pkflow_login_redirect', '' );
				if ( '' !== $settings_redirect ) {
					$redirect = $this->safe_redirect( $settings_redirect );
				}
			}

			if ( '' === $redirect ) {
				$default  = apply_filters( 'login_redirect', admin_url(), '', $user ); // phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedHooknameFound -- core WordPress hook.
				$redirect = $this->safe_redirect( $default, admin_url() );
			}

			/**
			 * Filters the URL the user is sent to after a successful passkey login.
			 *
			 * @param string  $redirect Redirect URL.
			 * @param WP_User $user     Logged-in user.
			 */
			// Re-validate after filter to prevent open-redirect via third-party hooks.
			$redirect = $this->safe_redirect( (string) apply_filters( 'pkflow_login_redirect', $redirect, $user ), admin_url() );

			wp_send_json_success( array( 'redirect' => $redirect ) );

		} catch ( \Throwable $e ) {
			$this->record_failure( 'login_finish_ip', $ip );
			$this->record_failure( 'login_finish_user', (int) $cred->user_id );
			$this->record_failure( 'login_finish_cred', $cred_hash );
			$this->log_event(
				'login_failed',
				array(
					'user_id' => (int) $cred->user_id,
					'message' => $e->getMessage(),
				)
			);
			wp_send_json_error( array( 'message' => 'Passkey sign-in failed. Please use another login method.' ), 400 );
		}
	}

	// ──────────────────────────────────────────────────────────
	// Private helpers — WebAuthn
	// ──────────────────────────────────────────────────────────

	/**
	 * Create WebAuthn service configured for this relying party.
	 *
	 * @return WebAuthn
	 */
	private function new_webauthn(): WebAuthn {
		return new WebAuthn(
			$this->get_rp_name(),
			$this->get_rp_id(),
			array( 'none', 'packed', 'apple', 'fido-u2f', 'tpm', 'android-key', 'android-safetynet' ),
			true
		);
	}

	/**
	 * Resolve relying-party ID.
	 *
	 * @return string
	 */
	private function get_rp_id(): string {
		if ( defined( 'PKFLOW_RP_ID' ) && PKFLOW_RP_ID ) {
			return (string) PKFLOW_RP_ID;
		}
		return (string) wp_parse_url( home_url(), PHP_URL_HOST );
	}

	/**
	 * Resolve relying-party display name.
	 *
	 * @return string
	 */
	private function get_rp_name(): string {
		if ( defined( 'PKFLOW_RP_NAME' ) && PKFLOW_RP_NAME ) {
			return (string) PKFLOW_RP_NAME;
		}
		$name = get_option( 'pkflow_rp_name', '' );
		return '' !== $name ? (string) $name : (string) get_bloginfo( 'name' );
	}

	/**
	 * Get default challenge TTL in seconds.
	 *
	 * @return int
	 */
	private function get_challenge_ttl(): int {
		if ( defined( 'PKFLOW_CHALLENGE_TTL' ) && (int) PKFLOW_CHALLENGE_TTL > 30 ) {
			return (int) PKFLOW_CHALLENGE_TTL;
		}
		$opt = (int) get_option( 'pkflow_challenge_ttl', 0 );
		if ( $opt >= 30 ) {
			return min( 600, $opt );
		}
		return 300;
	}

	/**
	 * Get login challenge TTL in seconds.
	 *
	 * @return int
	 */
	private function get_login_challenge_ttl(): int {
		$opt = (int) get_option( 'pkflow_login_challenge_ttl', 0 );
		if ( $opt >= 30 ) {
			return min( 1200, $opt );
		}

		return $this->get_challenge_ttl();
	}

	/**
	 * Get registration challenge TTL in seconds.
	 *
	 * @return int
	 */
	private function get_registration_challenge_ttl(): int {
		$opt = (int) get_option( 'pkflow_registration_challenge_ttl', 0 );
		if ( $opt >= 30 ) {
			return min( 1200, $opt );
		}

		return $this->get_challenge_ttl();
	}

	/**
	 * Resolve WebAuthn user-verification preference.
	 *
	 * @return string
	 */
	private function get_user_verification(): string {
		$opt = strtolower( (string) get_option( 'pkflow_user_verification', '' ) );
		if ( in_array( $opt, array( 'required', 'preferred', 'discouraged' ), true ) ) {
			return $opt;
		}
		if ( defined( 'PKFLOW_USER_VERIFICATION' ) ) {
			$v = strtolower( (string) PKFLOW_USER_VERIFICATION );
			if ( in_array( $v, array( 'required', 'preferred', 'discouraged' ), true ) ) {
				return $v;
			}
		}
		return 'required';
	}

	/**
	 * Decode base64url input to binary.
	 *
	 * @param string $value Base64url value.
	 * @return string
	 */
	private function decode_b64url( string $value ): string {
		return ByteBuffer::fromBase64Url( $value )->getBinaryString();
	}

	/**
	 * Encode binary input as base64url.
	 *
	 * @param string $value Binary value.
	 * @return string
	 */
	private function encode_b64url( string $value ): string {
		return rtrim( strtr( base64_encode( $value ), '+/', '-_' ), '=' ); // phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.obfuscation_base64_encode -- canonical base64url encoding for WebAuthn payloads.
	}

	// ──────────────────────────────────────────────────────────
	// Private helpers — User
	// ──────────────────────────────────────────────────────────

	/**
	 * Determine whether a user can register and use passkeys.
	 *
	 * @param WP_User $user User instance.
	 * @return bool
	 */
	private function is_eligible_user( WP_User $user ): bool {
		/**
		 * Filters whether a user may register/use passkeys.
		 *
		 * @param bool    $eligible Whether the user is eligible.
		 * @param WP_User $user     The user in question.
		 */
		$eligible = apply_filters( 'pkflow_is_eligible_user', null, $user );
		if ( null !== $eligible ) {
			return (bool) $eligible;
		}

		$allowed_roles = (array) get_option( 'pkflow_eligible_roles', array( 'administrator' ) );
		return ! empty( array_intersect( (array) $user->roles, $allowed_roles ) );
	}

	/**
	 * Get max credentials allowed for the given user.
	 *
	 * @param WP_User $user User instance.
	 * @return int
	 */
	private function get_max_passkeys_per_user( WP_User $user ): int {
		/**
		 * Filters the max number of passkeys a user may hold.
		 * Return 0 or less to remove the cap.
		 *
		 * @param int     $max  Current cap.
		 * @param WP_User $user The user.
		 */
		$filtered = apply_filters( 'pkflow_max_passkeys_per_user', null, $user );
		if ( null !== $filtered ) {
			$filtered = (int) $filtered;
			return $filtered <= 0 ? PHP_INT_MAX : max( 1, $filtered );
		}

		$setting = (int) get_option( 'pkflow_max_passkeys_per_user', self::DEFAULT_MAX_PASSKEYS );
		return $setting <= 0 ? PHP_INT_MAX : max( 1, $setting );
	}

	/**
	 * Resolve a user from email or login identifier.
	 *
	 * @param string $login Login or email.
	 * @return WP_User|null
	 */
	private function resolve_user( string $login ): ?WP_User {
		$user = is_email( $login ) ? get_user_by( 'email', $login ) : false;
		if ( ! $user ) {
			$user = get_user_by( 'login', $login );
		}
		return $user instanceof WP_User ? $user : null;
	}

	/**
	 * Get active credentials for a user.
	 *
	 * @param int $user_id User ID.
	 * @return array<int, object>
	 */
	private function get_user_credentials( int $user_id ): array {
		global $wpdb;
		$table = $wpdb->prefix . self::TABLE_CREDENTIALS;
		return (array) $wpdb->get_results( // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching -- authentication requires live reads from plugin credential table.
			$wpdb->prepare( // phpcs:ignore WordPress.DB.DirectDatabaseQuery
				"SELECT * FROM {$table} WHERE user_id = %d AND revoked_at IS NULL ORDER BY created_at DESC", // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
				$user_id
			)
		);
	}

	/**
	 * Fetch display-only metadata for a user's passkeys.
	 * Does NOT load credential_public_key — use get_user_credentials() for authentication.
	 *
	 * @param int $user_id User ID.
	 * @return array<int, object>
	 */
	private function get_user_credentials_meta( int $user_id ): array {
		global $wpdb;
		$table = $wpdb->prefix . self::TABLE_CREDENTIALS;
		return (array) $wpdb->get_results( // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching -- admin credential metadata view reads plugin-owned custom table.
			$wpdb->prepare( // phpcs:ignore WordPress.DB.DirectDatabaseQuery
				"SELECT id, credential_label, created_at, last_used_at FROM {$table} WHERE user_id = %d AND revoked_at IS NULL ORDER BY created_at DESC", // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
				$user_id
			)
		);
	}

	/**
	 * Return the count of active (non-revoked) passkeys for a user.
	 * Avoids loading full credential rows just for a count check.
	 *
	 * @param int $user_id User ID.
	 * @return int
	 */
	private function count_user_credentials( int $user_id ): int {
		global $wpdb;
		$table = $wpdb->prefix . self::TABLE_CREDENTIALS;
		return (int) $wpdb->get_var( // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching -- realtime credential count used for limit enforcement.
			$wpdb->prepare( // phpcs:ignore WordPress.DB.DirectDatabaseQuery
				"SELECT COUNT(*) FROM {$table} WHERE user_id = %d AND revoked_at IS NULL", // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
				$user_id
			)
		);
	}

	/**
	 * Suppress setup nudge when credentials already exist.
	 *
	 * @param int $user_id User ID.
	 * @return bool
	 */
	private function has_any_user_credentials( int $user_id ): bool {
		return $this->count_user_credentials( $user_id ) > 0;
	}

	/**
	 * Get credential IDs in binary form for WebAuthn allowCredentials.
	 *
	 * @param int $user_id User ID.
	 * @return array<int, string>
	 */
	private function get_credential_ids_binary( int $user_id ): array {
		return array_map(
			fn( $r ) => $this->decode_b64url( $r->credential_id ),
			$this->get_user_credentials( $user_id )
		);
	}

	// ──────────────────────────────────────────────────────────
	// Private helpers — Redirect / Cookie
	// ──────────────────────────────────────────────────────────

	/**
	 * Validate and normalize a redirect URL.
	 *
	 * @param string $target   Candidate target URL.
	 * @param string $fallback Fallback URL.
	 * @return string
	 */
	private function safe_redirect( string $target, string $fallback = '' ): string {
		return '' !== $target ? (string) wp_validate_redirect( $target, $fallback ) : $fallback;
	}

	/**
	 * Clear the login redirect helper cookie.
	 */
	private function clear_redirect_cookie(): void {
		setcookie(
			'pkflow_redirect_to',
			'',
			array(
				'expires'  => time() - 3600,
				'path'     => defined( 'COOKIEPATH' ) ? (string) COOKIEPATH : '/',
				'domain'   => defined( 'COOKIE_DOMAIN' ) ? (string) COOKIE_DOMAIN : '',
				'secure'   => is_ssl(),
				'httponly' => true,
				'samesite' => 'Lax',
			)
		);
	}

	// ──────────────────────────────────────────────────────────
	// Private helpers — Rate limiting
	// ──────────────────────────────────────────────────────────

	/**
	 * Get rate-limit window length in seconds.
	 *
	 * @return int
	 */
	private function get_rate_window(): int {
		$opt = (int) get_option( 'pkflow_rate_limit_window', 0 );
		if ( $opt >= 60 ) {
			return min( 3600, $opt );
		}
		// Backward compatibility with pre-1.1 option keys.
		$opt = (int) get_option( 'pkflow_rate_window', 0 );
		if ( $opt >= 60 ) {
			return min( 3600, $opt );
		}
		if ( defined( 'PKFLOW_RATE_WINDOW' ) && (int) PKFLOW_RATE_WINDOW >= 60 ) {
			return (int) PKFLOW_RATE_WINDOW;
		}
		return 300;
	}

	/**
	 * Get max failed attempts before lockout.
	 *
	 * @return int
	 */
	private function get_rate_max_attempts(): int {
		$opt = (int) get_option( 'pkflow_rate_limit_max_failures', 0 );
		if ( $opt >= 1 ) {
			return min( 50, $opt );
		}
		// Backward compatibility with pre-1.1 option keys.
		$opt = (int) get_option( 'pkflow_rate_max_attempts', 0 );
		if ( $opt >= 1 ) {
			return min( 50, $opt );
		}
		if ( defined( 'PKFLOW_RATE_MAX_ATTEMPTS' ) && (int) PKFLOW_RATE_MAX_ATTEMPTS >= 1 ) {
			return (int) PKFLOW_RATE_MAX_ATTEMPTS;
		}
		return 5;
	}

	/**
	 * Get lockout duration in seconds.
	 *
	 * @return int
	 */
	private function get_rate_lockout(): int {
		$opt = (int) get_option( 'pkflow_rate_limit_lockout', 0 );
		if ( $opt >= 60 ) {
			return min( 86400, $opt );
		}
		// Backward compatibility with pre-1.1 option keys.
		$opt = (int) get_option( 'pkflow_rate_lockout', 0 );
		if ( $opt >= 60 ) {
			return min( 86400, $opt );
		}
		if ( defined( 'PKFLOW_RATE_LOCKOUT' ) && (int) PKFLOW_RATE_LOCKOUT >= 60 ) {
			return (int) PKFLOW_RATE_LOCKOUT;
		}
		return 900;
	}

	/**
	 * Build deterministic, privacy-safe bucket key.
	 *
	 * @param string $prefix     Bucket namespace prefix.
	 * @param string $identifier User/IP identifier.
	 * @return string
	 */
	private function bucket_key( string $prefix, string $identifier ): string {
		return 'pkflow_' . hash_hmac( 'sha256', $prefix . '|' . $identifier, wp_salt( 'auth' ) );
	}

	/**
	 * Check whether a bucket is currently locked.
	 *
	 * @param string     $prefix     Bucket namespace prefix.
	 * @param int|string $identifier User/IP identifier.
	 * @return bool
	 */
	private function is_locked_out( string $prefix, $identifier ): bool {
		global $wpdb;
		$table = esc_sql( $wpdb->prefix . self::TABLE_RATE_LIMITS );
		$key   = $this->bucket_key( $prefix, (string) $identifier );
		$until = $wpdb->get_var( // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching -- rate-limit lock checks require live table reads.
			$wpdb->prepare( // phpcs:ignore WordPress.DB.DirectDatabaseQuery
				"SELECT lock_expires_at FROM {$table} WHERE bucket_key = %s LIMIT 1", // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
				$key
			)
		);
		return $until && strtotime( (string) $until ) > time();
	}

	/**
	 * Record a failed operation in a rate-limit bucket.
	 *
	 * @param string     $prefix     Bucket namespace prefix.
	 * @param int|string $identifier User/IP identifier.
	 */
	private function record_failure( string $prefix, $identifier ): void {
		global $wpdb;
		$table   = esc_sql( $wpdb->prefix . self::TABLE_RATE_LIMITS );
		$key     = $this->bucket_key( $prefix, (string) $identifier );
		$window  = $this->get_rate_window();
		$max     = $this->get_rate_max_attempts();
		$lockout = $this->get_rate_lockout();

		$wpdb->query( // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching -- rate-limit bucket initialization write.
			$wpdb->prepare( // phpcs:ignore WordPress.DB.DirectDatabaseQuery
				"INSERT IGNORE INTO {$table} (bucket_key, failure_count, window_expires_at, lock_expires_at, updated_at) VALUES (%s, 0, NULL, NULL, UTC_TIMESTAMP())", // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
				$key
			)
		);

		$wpdb->query( // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching -- rate-limit counters and expirations are updated atomically.
			$wpdb->prepare( // phpcs:ignore WordPress.DB.DirectDatabaseQuery,WordPress.DB.PreparedSQL.InterpolatedNotPrepared -- table name is derived from plugin constant + WP prefix and escaped via esc_sql().
				// phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared -- table name is derived from plugin constant + WP prefix and escaped via esc_sql().
				"UPDATE {$table} SET
                failure_count = IF(window_expires_at IS NULL OR window_expires_at <= UTC_TIMESTAMP(), 1, failure_count + 1),
                window_expires_at = IF(window_expires_at IS NULL OR window_expires_at <= UTC_TIMESTAMP(), DATE_ADD(UTC_TIMESTAMP(), INTERVAL %d SECOND), window_expires_at),
                lock_expires_at = IF(
                    IF(window_expires_at IS NULL OR window_expires_at <= UTC_TIMESTAMP(), 1, failure_count + 1) >= %d,
                    DATE_ADD(UTC_TIMESTAMP(), INTERVAL %d SECOND),
                    IF(lock_expires_at IS NOT NULL AND lock_expires_at <= UTC_TIMESTAMP(), NULL, lock_expires_at)
                ),
                updated_at = UTC_TIMESTAMP()
			WHERE bucket_key = %s",
				$window,
				$max,
				$lockout,
				$key
			)
		);

		if ( random_int( 1, 100 ) === 1 ) {
			$this->cleanup_rate_table();
		}
	}

	/**
	 * Clear failures for a specific bucket.
	 *
	 * @param string     $prefix     Bucket namespace prefix.
	 * @param int|string $identifier User/IP identifier.
	 */
	private function clear_failures( string $prefix, $identifier ): void {
		global $wpdb;
		$table = esc_sql( $wpdb->prefix . self::TABLE_RATE_LIMITS );
		$key   = $this->bucket_key( $prefix, (string) $identifier );
		$wpdb->query( // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching -- explicit reset of a rate-limit bucket.
			$wpdb->prepare( // phpcs:ignore WordPress.DB.DirectDatabaseQuery
				"DELETE FROM {$table} WHERE bucket_key = %s", // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
				$key
			)
		);
	}

	/**
	 * Purge expired rows from rate-limit table.
	 */
	private function cleanup_rate_table(): void {
		global $wpdb;
		$table = esc_sql( $wpdb->prefix . self::TABLE_RATE_LIMITS );
		$wpdb->query( // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching -- periodic cleanup for expired rate-limit buckets.
			"DELETE FROM {$table} WHERE (lock_expires_at IS NULL OR lock_expires_at <= UTC_TIMESTAMP()) AND (window_expires_at IS NULL OR window_expires_at <= UTC_TIMESTAMP())" // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
		);
	}

	// ──────────────────────────────────────────────────────────
	// Private helpers — Misc
	// ──────────────────────────────────────────────────────────

	/**
	 * Convert UTC datetime string to timestamp.
	 *
	 * @param string $raw_datetime Datetime string.
	 * @return int
	 */
	private function utc_datetime_to_timestamp( string $raw_datetime ): int {
		$raw_datetime = trim( $raw_datetime );
		if ( '' === $raw_datetime ) {
			return 0;
		}

		$date_utc = DateTimeImmutable::createFromFormat( 'Y-m-d H:i:s', $raw_datetime, new DateTimeZone( 'UTC' ) );
		if ( $date_utc instanceof DateTimeImmutable ) {
			return $date_utc->getTimestamp();
		}

		$fallback_ts = strtotime( $raw_datetime . ' UTC' );
		return $fallback_ts ? (int) $fallback_ts : 0;
	}

	/**
	 * Format UTC datetime for local display.
	 *
	 * @param string $raw_datetime Datetime string.
	 * @return string
	 */
	private function format_utc_datetime_for_display( string $raw_datetime ): string {
		$timestamp = $this->utc_datetime_to_timestamp( $raw_datetime );
		if ( $timestamp <= 0 ) {
			return $raw_datetime;
		}

		return wp_date(
			get_option( 'date_format' ) . ' ' . get_option( 'time_format' ),
			$timestamp,
			wp_timezone()
		);
	}

	/**
	 * Determine whether passkeys may run in this request context.
	 *
	 * @return bool
	 */
	private function is_secure_context(): bool {
		if ( is_ssl() ) {
			return true;
		}

		// Allow HTTP only for local/dev-style environments when explicitly enabled.
		if ( defined( 'PKFLOW_ALLOW_HTTP' ) && PKFLOW_ALLOW_HTTP ) {
			if ( function_exists( 'wp_get_environment_type' ) && 'production' === wp_get_environment_type() ) {
				return false;
			}
			return true;
		}

		return false;
	}

	/**
	 * Get client IP address with strict sanitization.
	 *
	 * @return string
	 */
	private function get_client_ip(): string {
		$ip = '';
		if ( isset( $_SERVER['REMOTE_ADDR'] ) ) {
			$ip_raw = wp_unslash( $_SERVER['REMOTE_ADDR'] ); // phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- sanitized below by sanitize_text_field/filter_var.
			if ( is_string( $ip_raw ) ) {
				$ip = sanitize_text_field( $ip_raw );
			}
		}
		if ( '' === $ip || false === filter_var( $ip, FILTER_VALIDATE_IP ) ) {
			return '0.0.0.0';
		}
		return $ip;
	}

	/**
	 * Persist a sanitized activity log event.
	 *
	 * @param string               $event Event key.
	 * @param array<string, mixed> $data  Event payload.
	 */
	private function log_event( string $event, array $data = array() ): void {
		if ( defined( 'PKFLOW_ENABLE_LOGGING' ) && ! PKFLOW_ENABLE_LOGGING ) {
			return;
		}

		if ( ! (bool) get_option( 'pkflow_activity_logging_enabled', true ) ) {
			return;
		}

		// Privacy-first logging: strip or pseudonymize fields that can contain PII.
		if ( isset( $data['user_id'] ) ) {
			$data['user_ref'] = hash_hmac( 'sha256', (string) absint( $data['user_id'] ), wp_salt( 'auth' ) );
			unset( $data['user_id'] );
		}

		foreach ( array( 'message', 'email', 'ip', 'user_agent', 'login', 'username', 'display_name', 'redirect' ) as $sensitive_key ) {
			if ( isset( $data[ $sensitive_key ] ) ) {
				unset( $data[ $sensitive_key ] );
			}
		}

		$event = sanitize_key( $event );
		if ( '' === $event ) {
			return;
		}

		$encoded_data = wp_json_encode( $data );
		if ( ! is_string( $encoded_data ) ) {
			$encoded_data = '{}';
		}

		global $wpdb;
		$wpdb->insert( // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching -- append-only logging table write.
			$wpdb->prefix . 'pkflow_logs',
			array(
				'event_type'    => $event,
				'log_timestamp' => gmdate( 'Y-m-d H:i:s' ),
				// Keep user_agent empty to avoid storing browser fingerprinting data.
				'user_agent'    => '',
				'log_data'      => $encoded_data,
			),
			array( '%s', '%s', '%s', '%s' )
		);
	}
}
