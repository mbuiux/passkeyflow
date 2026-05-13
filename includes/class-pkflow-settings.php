<?php
/**
 * Advanced Passkeys for Secure Login premium admin settings screen.
 *
 * Drop this in place of your existing settings class file, or copy the markup
 * methods into your current class if your plugin already wires settings elsewhere.
 *
 * @package PKFLOW
 */

// phpcs:disable WordPress.Files.FileName.InvalidClassFileName -- legacy file naming kept for backward compatibility.

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Admin settings page controller and dashboard data presenter.
 */
class PKFLOW_Settings {
	/**
	 * Settings API option group key.
	 *
	 * @var string
	 */
	private $option_group = 'pkflow_settings_group';

	/**
	 * Admin page slug.
	 *
	 * @var string
	 */
	private $page_slug = 'advanced-passkey-login';

	/**
	 * Prefix for per-user notice transients.
	 *
	 * @var string
	 */
	private $notice_transient_prefix = 'pkflow_settings_notice_';

	/**
	 * Build per-user transient key for save notices.
	 *
	 * @param int $user_id User ID.
	 * @return string
	 */
	private function get_notice_transient_key( $user_id ) {
		return $this->notice_transient_prefix . absint( $user_id );
	}

	/**
	 * Register settings-page hooks.
	 */
	public function __construct() {
		add_action( 'admin_menu', array( $this, 'add_admin_menu' ) );
		add_action( 'admin_init', array( $this, 'register_settings' ) );
		add_action( 'admin_action_update', array( $this, 'flag_settings_save' ), 1 );
		add_action( 'admin_enqueue_scripts', array( $this, 'enqueue_assets' ) );
	}

	/**
	 * Detect when our settings form is submitted to options.php and store a
	 * per-user flag BEFORE the redirect happens. Avoids relying on the
	 * settings-updated URL param or the settings_errors transient, both of
	 * which can be consumed or missing depending on environment.
	 */
	public function flag_settings_save() {
		if ( ! isset( $_SERVER['REQUEST_METHOD'] ) ) {
			return;
		}

		$request_method = sanitize_text_field( wp_unslash( $_SERVER['REQUEST_METHOD'] ) ); // phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- sanitized immediately for method check.

		if ( 'POST' !== strtoupper( $request_method ) ) {
			return;
		}

		if ( ! current_user_can( 'manage_options' ) ) {
			return;
		}

		if ( empty( $_POST['option_page'] ) ) {
			return;
		}

		$option_page = sanitize_text_field( wp_unslash( $_POST['option_page'] ) );
		if ( $this->option_group !== $option_page ) {
			return;
		}

		if ( empty( $_POST['_wpnonce'] ) ) {
			return;
		}

		$nonce = sanitize_text_field( wp_unslash( $_POST['_wpnonce'] ) );
		if ( ! wp_verify_nonce( $nonce, $option_page . '-options' ) ) {
			return;
		}

		$user_id = get_current_user_id();
		if ( $user_id <= 0 ) {
			return;
		}

		$notice = array(
			'type'    => 'success',
			'message' => __( 'Settings saved.', 'advanced-passkey-login' ),
		);

		set_transient( $this->get_notice_transient_key( $user_id ), $notice, 180 );
	}

	/**
	 * Retrieve and consume any pending save notice for the user.
	 *
	 * @param int $user_id User ID.
	 * @return array<string, string>|null
	 */
	private function consume_save_notice( $user_id ) {
		if ( $user_id <= 0 ) {
			return null;
		}

		$key    = $this->get_notice_transient_key( $user_id );
		$notice = get_transient( $key );

		if ( false === $notice ) {
			return null;
		}

		delete_transient( $key );

		if ( ! is_array( $notice ) || empty( $notice['message'] ) ) {
			return null;
		}

		$type = ! empty( $notice['type'] ) ? sanitize_key( $notice['type'] ) : 'success';
		if ( ! in_array( $type, array( 'success', 'error', 'warning', 'info' ), true ) ) {
			$type = 'success';
		}

		return array(
			'type'    => $type,
			'message' => wp_kses_post( $notice['message'] ),
		);
	}

	/**
	 * Register the plugin settings page under Settings.
	 */
	public function add_admin_menu() {
		add_options_page(
			__( 'Advanced Passkeys for Secure Login', 'advanced-passkey-login' ),
			__( 'Advanced Passkeys for Secure Login', 'advanced-passkey-login' ),
			'manage_options',
			$this->page_slug,
			array( $this, 'render_settings_page' )
		);
	}

	/**
	 * Enqueue admin styles/scripts for this plugin settings screen.
	 *
	 * @param string $hook Current admin page hook.
	 */
	public function enqueue_assets( $hook ) {
		if ( 'settings_page_' . $this->page_slug !== $hook ) {
			return;
		}

		$version = defined( 'PKFLOW_VERSION' ) ? PKFLOW_VERSION : '1.0.0';
		$css_url = '';

		/*
		 * Support the common Advanced Passkeys for Secure Login plugin structure first:
		 * /admin/css/pkflow-admin.css. The other paths are fallbacks for simple
		 * copy/paste installs and older generated bundles.
		 */
		if ( file_exists( plugin_dir_path( __DIR__ ) . 'admin/css/pkflow-admin.css' ) ) {
			$css_url = plugin_dir_url( __DIR__ ) . 'admin/css/pkflow-admin.css';
		} elseif ( file_exists( __DIR__ . '/pkflow-admin.css' ) ) {
			$css_url = plugin_dir_url( __FILE__ ) . 'pkflow-admin.css';
		} elseif ( file_exists( plugin_dir_path( __DIR__ ) . 'assets/css/pkflow-admin.css' ) ) {
			$css_url = plugin_dir_url( __DIR__ ) . 'assets/css/pkflow-admin.css';
		} elseif ( file_exists( plugin_dir_path( __DIR__ ) . 'pkflow-admin.css' ) ) {
			$css_url = plugin_dir_url( __DIR__ ) . 'pkflow-admin.css';
		}

		if ( $css_url ) {
			wp_enqueue_style( 'pkflow-admin', $css_url, array(), $version );
		}

		$active_tab = $this->resolve_active_tab();
		if ( 'dashboard' !== $active_tab ) {
			return;
		}

		$dashboard_css = plugin_dir_path( __DIR__ ) . 'admin/css/pkflow-dashboard.css';
		if ( file_exists( $dashboard_css ) ) {
			wp_enqueue_style(
				'pkflow-dashboard',
				plugin_dir_url( __DIR__ ) . 'admin/css/pkflow-dashboard.css',
				array( 'pkflow-admin' ),
				$version
			);
		}

		$apexcharts_js   = plugin_dir_path( __DIR__ ) . 'admin/vendor/apexcharts/apexcharts.min.js';
		$apex_dependency = '';
		if ( file_exists( $apexcharts_js ) ) {
			wp_enqueue_script(
				'pkflow-apexcharts',
				plugin_dir_url( __DIR__ ) . 'admin/vendor/apexcharts/apexcharts.min.js',
				array(),
				'3.49.1',
				true
			);
			$apex_dependency = 'pkflow-apexcharts';
		} elseif ( wp_script_is( 'apexcharts', 'registered' ) || wp_script_is( 'apexcharts', 'enqueued' ) ) {
			$apex_dependency = 'apexcharts';
		}

		$dashboard_js = plugin_dir_path( __DIR__ ) . 'admin/js/pkflow-dashboard.js';
		if ( file_exists( $dashboard_js ) ) {
			$dashboard_deps = array();
			if ( '' !== $apex_dependency ) {
				$dashboard_deps[] = $apex_dependency;
			}

			wp_enqueue_script(
				'pkflow-dashboard',
				plugin_dir_url( __DIR__ ) . 'admin/js/pkflow-dashboard.js',
				$dashboard_deps,
				$version,
				true
			);
		}
	}

	/**
	 * Register plugin options and sanitization callbacks.
	 */
	public function register_settings() {
		register_setting(
			$this->option_group,
			'pkflow_enabled',
			array(
				'type'              => 'boolean',
				'sanitize_callback' => array( $this, 'sanitize_checkbox' ),
				'default'           => true,
			)
		);

		register_setting(
			$this->option_group,
			'pkflow_show_separator',
			array(
				'type'              => 'boolean',
				'sanitize_callback' => array( $this, 'sanitize_checkbox' ),
				'default'           => true,
			)
		);

		register_setting(
			$this->option_group,
			'pkflow_show_setup_notice',
			array(
				'type'              => 'boolean',
				'sanitize_callback' => array( $this, 'sanitize_checkbox' ),
				'default'           => true,
			)
		);

		register_setting(
			$this->option_group,
			'pkflow_enable_woocommerce_support',
			array(
				'type'              => 'boolean',
				'sanitize_callback' => array( $this, 'sanitize_checkbox' ),
				'default'           => true,
			)
		);

		register_setting(
			$this->option_group,
			'pkflow_enable_edd_support',
			array(
				'type'              => 'boolean',
				'sanitize_callback' => array( $this, 'sanitize_checkbox' ),
				'default'           => true,
			)
		);

		register_setting(
			$this->option_group,
			'pkflow_enable_memberpress_support',
			array(
				'type'              => 'boolean',
				'sanitize_callback' => array( $this, 'sanitize_checkbox' ),
				'default'           => true,
			)
		);

		register_setting(
			$this->option_group,
			'pkflow_enable_ultimate_member_support',
			array(
				'type'              => 'boolean',
				'sanitize_callback' => array( $this, 'sanitize_checkbox' ),
				'default'           => true,
			)
		);

		register_setting(
			$this->option_group,
			'pkflow_enable_learndash_support',
			array(
				'type'              => 'boolean',
				'sanitize_callback' => array( $this, 'sanitize_checkbox' ),
				'default'           => true,
			)
		);

		register_setting(
			$this->option_group,
			'pkflow_enable_buddyboss_support',
			array(
				'type'              => 'boolean',
				'sanitize_callback' => array( $this, 'sanitize_checkbox' ),
				'default'           => true,
			)
		);

		register_setting(
			$this->option_group,
			'pkflow_enable_gravityforms_support',
			array(
				'type'              => 'boolean',
				'sanitize_callback' => array( $this, 'sanitize_checkbox' ),
				'default'           => true,
			)
		);

		register_setting(
			$this->option_group,
			'pkflow_enable_pmp_support',
			array(
				'type'              => 'boolean',
				'sanitize_callback' => array( $this, 'sanitize_checkbox' ),
				'default'           => true,
			)
		);

		register_setting(
			$this->option_group,
			'pkflow_eligible_roles',
			array(
				'type'              => 'array',
				'sanitize_callback' => array( $this, 'sanitize_roles' ),
				'default'           => array( 'administrator' ),
			)
		);

		register_setting(
			$this->option_group,
			'pkflow_max_passkeys_per_user',
			array(
				'type'              => 'integer',
				'sanitize_callback' => array( $this, 'sanitize_max_passkeys' ),
				'default'           => 0,
			)
		);

		register_setting(
			$this->option_group,
			'pkflow_user_verification',
			array(
				'type'              => 'string',
				'sanitize_callback' => array( $this, 'sanitize_user_verification' ),
				'default'           => 'required',
			)
		);

		register_setting(
			$this->option_group,
			'pkflow_rp_name',
			array(
				'type'              => 'string',
				'sanitize_callback' => 'sanitize_text_field',
				'default'           => '',
			)
		);

		register_setting(
			$this->option_group,
			'pkflow_rp_id',
			array(
				'type'              => 'string',
				'sanitize_callback' => array( $this, 'sanitize_rp_id' ),
				'default'           => '',
			)
		);

		register_setting(
			$this->option_group,
			'pkflow_login_challenge_ttl',
			array(
				'type'              => 'integer',
				'sanitize_callback' => array( $this, 'sanitize_challenge_ttl' ),
				'default'           => 300,
			)
		);

		register_setting(
			$this->option_group,
			'pkflow_registration_challenge_ttl',
			array(
				'type'              => 'integer',
				'sanitize_callback' => array( $this, 'sanitize_challenge_ttl' ),
				'default'           => 300,
			)
		);

		register_setting(
			$this->option_group,
			'pkflow_rate_limit_window',
			array(
				'type'              => 'integer',
				'sanitize_callback' => array( $this, 'sanitize_rate_limit_window' ),
				'default'           => 300,
			)
		);

		register_setting(
			$this->option_group,
			'pkflow_rate_limit_max_failures',
			array(
				'type'              => 'integer',
				'sanitize_callback' => array( $this, 'sanitize_rate_limit_max_failures' ),
				'default'           => 5,
			)
		);

		register_setting(
			$this->option_group,
			'pkflow_rate_limit_lockout',
			array(
				'type'              => 'integer',
				'sanitize_callback' => array( $this, 'sanitize_rate_limit_lockout' ),
				'default'           => 900,
			)
		);
	}

	/**
	 * Render the full settings page shell and active tab content.
	 */
	public function render_settings_page() {
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( esc_html__( 'You do not have permission to access this page.', 'advanced-passkey-login' ) );
		}

		$active_tab = $this->resolve_active_tab();

		$base_url = admin_url( 'options-general.php?page=' . $this->page_slug );

		$user_id = get_current_user_id();

		$queued_notices = array();
		$notice_source  = 'none';

		$core_settings_errors = get_settings_errors();
		foreach ( $core_settings_errors as $notice ) {
			if ( empty( $notice['message'] ) ) {
				continue;
			}

			$type = ! empty( $notice['type'] ) ? sanitize_key( $notice['type'] ) : 'info';
			if ( 'updated' === $type ) {
				$type = 'success';
			}
			if ( ! in_array( $type, array( 'success', 'error', 'warning', 'info' ), true ) ) {
				$type = 'info';
			}

			$queued_notices[] = array(
				'type'    => $type,
				'message' => wp_kses_post( $notice['message'] ),
			);
		}

		if ( ! empty( $queued_notices ) ) {
			$notice_source = 'core_settings_errors';
		}

		$transient_present = false;
		if ( $user_id > 0 ) {
			$transient_present = false !== get_transient( $this->get_notice_transient_key( $user_id ) );
		}

		if ( empty( $queued_notices ) ) {
			$save_notice = $this->consume_save_notice( $user_id );
			if ( ! empty( $save_notice ) ) {
				$queued_notices[] = $save_notice;
				$notice_source    = 'transient';
			}
		}

		$notice_debug      = filter_input( INPUT_GET, 'pkflow_notice_debug', FILTER_SANITIZE_NUMBER_INT );
		$raw_debug_nonce   = filter_input( INPUT_GET, 'pkflow_notice_debug_nonce', FILTER_SANITIZE_FULL_SPECIAL_CHARS );
		$debug_nonce_valid = false;

		if ( is_string( $raw_debug_nonce ) && '' !== $raw_debug_nonce ) {
			$debug_nonce = sanitize_text_field( $raw_debug_nonce );
			$debug_nonce_valid = wp_verify_nonce( $debug_nonce, 'pkflow_notice_debug' );
		}

		$show_debug = current_user_can( 'manage_options' )
			&& is_string( $notice_debug )
			&& '1' === $notice_debug
			&& $debug_nonce_valid;

		$debug_payload = array();
		if ( $show_debug ) {
			$request_method_debug = isset( $_SERVER['REQUEST_METHOD'] ) ? sanitize_text_field( wp_unslash( $_SERVER['REQUEST_METHOD'] ) ) : '';

			$debug_payload = array(
				'method'               => $request_method_debug,
				'page'                 => $this->page_slug,
				'tab'                  => $active_tab,
				'settings_updated_get' => '(not read)',
				'core_errors_count'    => count( $core_settings_errors ),
				'transient_present'    => $transient_present ? 'yes' : 'no',
				'queued_notices_count' => count( $queued_notices ),
				'notice_source'        => $notice_source,
				'user_id'              => $user_id,
			);
		}
		?>
		<div class="wrap pkflow-admin-wrap">
			<?php if ( $show_debug ) : ?>
			<div class="pkflow-debug-banner" role="status" aria-live="polite">
				<strong><?php esc_html_e( 'PKFLOW Notice Debug', 'advanced-passkey-login' ); ?></strong>
				<pre><?php echo esc_html( wp_json_encode( $debug_payload, JSON_PRETTY_PRINT ) ); ?></pre>
			</div>
			<?php endif; ?>

			<?php if ( ! empty( $queued_notices ) ) : ?>
			<div class="pkflow-notices-wrap">
				<?php foreach ( $queued_notices as $notice ) : ?>
				<div class="pkflow-flash pkflow-flash--<?php echo esc_attr( $notice['type'] ); ?>" role="alert">
					<p><?php echo wp_kses_post( $notice['message'] ); ?></p>
				</div>
				<?php endforeach; ?>
			</div>
			<?php endif; ?>

			<div class="pkflow-premium-shell">
				<header class="pkflow-hero">
					<div class="pkflow-hero__content">
						<div class="pkflow-product-mark">
							<span class="pkflow-product-icon" aria-hidden="true"><svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><path d="M12 10a2 2 0 0 0-2 2c0 1.02-.1 2.51-.26 4"></path><path d="M14 13.12c0 2.38 0 6.38-1 8.88"></path><path d="M17.29 21.02c.12-.6.43-2.3.5-3.02"></path><path d="M2 12a10 10 0 0 1 18-6"></path><path d="M2 16h.01"></path><path d="M21.8 16c.2-2 .131-5.354 0-6"></path><path d="M5 19.5C5.5 18 6 15 6 12a6 6 0 0 1 .34-2"></path><path d="M8.65 22c.21-.66.45-1.32.57-2"></path><path d="M9 6.8a6 6 0 0 1 9 5.2v2"></path></svg></span>
							<div>
								<p class="pkflow-eyebrow"><?php esc_html_e( 'Welcome to', 'advanced-passkey-login' ); ?></p>
								<h1><?php esc_html_e( 'Advanced Passkeys for Secure Login', 'advanced-passkey-login' ); ?></h1>
							</div>
						</div>
						<p class="pkflow-hero__copy">
							<?php esc_html_e( 'A premium passwordless authentication control center built for WordPress.', 'advanced-passkey-login' ); ?>
						</p>
					</div>
					<div class="pkflow-hero__actions">
						<span class="pkflow-status-pill pkflow-status-pill--success">
							<span class="pkflow-status-dot" aria-hidden="true"></span>
							<?php esc_html_e( 'Ready', 'advanced-passkey-login' ); ?>
						</span>

					</div>
				</header>

				<nav class="pkflow-tabs" aria-label="<?php esc_attr_e( 'Advanced Passkeys for Secure Login settings tabs', 'advanced-passkey-login' ); ?>">
					<?php $this->render_tab_link( $base_url, 'dashboard', __( 'Dashboard', 'advanced-passkey-login' ), $active_tab ); ?>
					<?php $this->render_tab_link( $base_url, 'settings', __( 'Settings', 'advanced-passkey-login' ), $active_tab ); ?>
					<?php $this->render_tab_link( $base_url, 'advanced', __( 'Advanced', 'advanced-passkey-login' ), $active_tab ); ?>
					<?php $this->render_tab_link( $base_url, 'shortcodes', __( 'Shortcodes', 'advanced-passkey-login' ), $active_tab ); ?>
				</nav>

				<div class="pkflow-layout<?php echo 'dashboard' === $active_tab ? ' pkflow-layout--dashboard' : ''; ?>">
					<main class="pkflow-main-panel">
						<?php if ( 'dashboard' === $active_tab ) : ?>
							<?php $this->render_dashboard_tab(); ?>
						<?php elseif ( 'shortcodes' === $active_tab ) : ?>
							<?php $this->render_shortcodes_tab(); ?>
						<?php else : ?>
							<form method="post" action="options.php" class="pkflow-settings-form">
								<?php settings_fields( $this->option_group ); ?>
								<?php $this->render_preserved_hidden_fields( $active_tab ); ?>
								<?php 'advanced' === $active_tab ? $this->render_advanced_tab() : $this->render_settings_tab(); ?>
								<footer class="pkflow-form-footer">
									<p><?php esc_html_e( 'Changes apply immediately after saving.', 'advanced-passkey-login' ); ?></p>
									<?php submit_button( __( 'Save Settings', 'advanced-passkey-login' ), 'primary pkflow-save-button', 'submit', false ); ?>
								</footer>
							</form>
						<?php endif; ?>
					</main>

					<?php if ( 'dashboard' !== $active_tab ) : ?>
					<aside class="pkflow-sidebar" aria-label="<?php esc_attr_e( 'Advanced Passkeys for Secure Login quick actions', 'advanced-passkey-login' ); ?>">
						<?php $this->render_sidebar_cards(); ?>
					</aside>
					<?php endif; ?>
				</div>

				<?php $this->render_shell_footer(); ?>
			</div>
		</div>
		<?php
	}

	/**
	 * Render a single tab link.
	 *
	 * @param string $base_url   Base settings URL.
	 * @param string $tab        Tab key.
	 * @param string $label      Tab label.
	 * @param string $active_tab Currently active tab key.
	 */
	private function render_tab_link( $base_url, $tab, $label, $active_tab ) {
		$classes = 'pkflow-tab';
		if ( $tab === $active_tab ) {
			$classes .= ' is-active';
		}

		$tab_url = add_query_arg( 'tab', $tab, $base_url );
		$tab_url = wp_nonce_url( $tab_url, 'pkflow_tab_' . $tab, 'pkflow_tab_nonce' );

		printf(
			'<a class="%1$s" href="%2$s">%3$s</a>',
			esc_attr( $classes ),
			esc_url( $tab_url ),
			esc_html( $label )
		);
	}

	/**
	 * Resolve active settings tab with nonce verification.
	 *
	 * @return string
	 */
	private function resolve_active_tab() {
		$allowed_tabs = array( 'dashboard', 'settings', 'advanced', 'shortcodes' );
		$raw_tab      = filter_input( INPUT_GET, 'tab', FILTER_SANITIZE_FULL_SPECIAL_CHARS );

		if ( ! is_string( $raw_tab ) || '' === $raw_tab ) {
			return 'dashboard';
		}

		$active_tab = sanitize_key( $raw_tab );
		if ( ! in_array( $active_tab, $allowed_tabs, true ) ) {
			return 'settings';
		}

		$raw_nonce = filter_input( INPUT_GET, 'pkflow_tab_nonce', FILTER_SANITIZE_FULL_SPECIAL_CHARS );
		if ( ! is_string( $raw_nonce ) || '' === $raw_nonce ) {
			return 'settings';
		}

		$nonce = sanitize_text_field( $raw_nonce );
		if ( ! wp_verify_nonce( $nonce, 'pkflow_tab_' . $active_tab ) ) {
			return 'settings';
		}

		return $active_tab;
	}

	/**
	 * Output hidden fields to preserve values from non-active tabs.
	 *
	 * @param string $active_tab Active tab key.
	 */
	private function render_preserved_hidden_fields( $active_tab ) {
		if ( 'advanced' === $active_tab ) {
			$enabled              = (bool) get_option( 'pkflow_enabled', true );
			$show_setup_notice    = (bool) get_option( 'pkflow_show_setup_notice', true );
			$integration_settings = class_exists( 'PKFLOW_Integration_Manager' ) && method_exists( 'PKFLOW_Integration_Manager', 'get_settings_registry' )
				? PKFLOW_Integration_Manager::get_settings_registry()
				: array();
			$roles                = (array) get_option( 'pkflow_eligible_roles', array( 'administrator' ) );
			$max_passkeys         = absint( get_option( 'pkflow_max_passkeys_per_user', 0 ) );
			$verification         = get_option( 'pkflow_user_verification', 'required' );

			echo '<input type="hidden" name="pkflow_enabled" value="' . esc_attr( $enabled ? '1' : '0' ) . '" />';
			echo '<input type="hidden" name="pkflow_show_setup_notice" value="' . esc_attr( $show_setup_notice ? '1' : '0' ) . '" />';

			foreach ( $integration_settings as $integration_setting ) {
				if ( empty( $integration_setting['master_option'] ) ) {
					continue;
				}

				$master_option = sanitize_key( (string) $integration_setting['master_option'] );

				$dependency_active = ! empty( $integration_setting['dependency_active'] );
				$master_value      = $dependency_active
					? (bool) get_option( $master_option, ! empty( $integration_setting['default_master'] ) )
					: false;

				echo '<input type="hidden" name="' . esc_attr( $master_option ) . '" value="' . esc_attr( $master_value ? '1' : '0' ) . '" />';
			}

			foreach ( $roles as $role ) {
				echo '<input type="hidden" name="pkflow_eligible_roles[]" value="' . esc_attr( sanitize_key( $role ) ) . '" />';
			}
			echo '<input type="hidden" name="pkflow_max_passkeys_per_user" value="' . esc_attr( (string) $max_passkeys ) . '" />';
			echo '<input type="hidden" name="pkflow_user_verification" value="' . esc_attr( (string) $verification ) . '" />';
			return;
		}

		if ( 'settings' === $active_tab ) {
			$show_separator             = (bool) get_option( 'pkflow_show_separator', true );
			$rp_name                    = get_option( 'pkflow_rp_name', '' );
			$rp_id                      = get_option( 'pkflow_rp_id', '' );
			$login_challenge_ttl        = absint( get_option( 'pkflow_login_challenge_ttl', 300 ) );
			$registration_challenge_ttl = absint( get_option( 'pkflow_registration_challenge_ttl', 300 ) );
			$window                     = absint( get_option( 'pkflow_rate_limit_window', 300 ) );
			$max_failures               = absint( get_option( 'pkflow_rate_limit_max_failures', 5 ) );
			$lockout                    = absint( get_option( 'pkflow_rate_limit_lockout', 900 ) );

			echo '<input type="hidden" name="pkflow_show_separator" value="' . esc_attr( $show_separator ? '1' : '0' ) . '" />';
			echo '<input type="hidden" name="pkflow_rp_name" value="' . esc_attr( (string) $rp_name ) . '" />';
			echo '<input type="hidden" name="pkflow_rp_id" value="' . esc_attr( (string) $rp_id ) . '" />';
			echo '<input type="hidden" name="pkflow_login_challenge_ttl" value="' . esc_attr( (string) $login_challenge_ttl ) . '" />';
			echo '<input type="hidden" name="pkflow_registration_challenge_ttl" value="' . esc_attr( (string) $registration_challenge_ttl ) . '" />';
			echo '<input type="hidden" name="pkflow_rate_limit_window" value="' . esc_attr( (string) $window ) . '" />';
			echo '<input type="hidden" name="pkflow_rate_limit_max_failures" value="' . esc_attr( (string) $max_failures ) . '" />';
			echo '<input type="hidden" name="pkflow_rate_limit_lockout" value="' . esc_attr( (string) $lockout ) . '" />';
		}
	}

	/**
	 * Render the everyday settings tab.
	 */
	private function render_settings_tab() {
		$enabled           = (bool) get_option( 'pkflow_enabled', true );
		$show_setup_notice = (bool) get_option( 'pkflow_show_setup_notice', true );
		$eligible_roles    = (array) get_option( 'pkflow_eligible_roles', array( 'administrator' ) );
		$max_passkeys      = absint( get_option( 'pkflow_max_passkeys_per_user', 0 ) );
		$verification      = get_option( 'pkflow_user_verification', 'required' );
		$roles             = wp_roles()->roles;
		?>
		<section class="pkflow-section-header">
			<div>
				<p class="pkflow-eyebrow"><?php esc_html_e( 'Settings', 'advanced-passkey-login' ); ?></p>
				<h2><?php esc_html_e( 'Everyday passkey controls', 'advanced-passkey-login' ); ?></h2>
			</div>
			<span class="pkflow-badge"><?php esc_html_e( 'Recommended defaults', 'advanced-passkey-login' ); ?></span>
		</section>

		<div class="pkflow-card pkflow-card--setting">
			<div class="pkflow-setting-copy">
				<h3><?php esc_html_e( 'Enable passkeys', 'advanced-passkey-login' ); ?></h3>
				<p><?php esc_html_e( 'Allow eligible users to register and sign in with secure device passkeys.', 'advanced-passkey-login' ); ?></p>
			</div>
			<label class="pkflow-switch">
				<input type="checkbox" name="pkflow_enabled" value="1" <?php checked( $enabled ); ?> />
				<span class="pkflow-switch__track"><span class="pkflow-switch__thumb"></span></span>
				<span class="screen-reader-text"><?php esc_html_e( 'Enable passkeys', 'advanced-passkey-login' ); ?></span>
			</label>
		</div>

		<div class="pkflow-card pkflow-card--setting">
			<div class="pkflow-setting-copy">
				<h3><?php esc_html_e( 'Show setup alert on profile', 'advanced-passkey-login' ); ?></h3>
				<p><?php esc_html_e( 'Show or hide the admin alert that reminds users to set up a passkey on their profile page.', 'advanced-passkey-login' ); ?></p>
			</div>
			<label class="pkflow-switch">
				<input type="checkbox" name="pkflow_show_setup_notice" value="1" <?php checked( $show_setup_notice ); ?> />
				<span class="pkflow-switch__track"><span class="pkflow-switch__thumb"></span></span>
				<span class="screen-reader-text"><?php esc_html_e( 'Show setup alert on profile', 'advanced-passkey-login' ); ?></span>
			</label>
		</div>

		<?php
		if ( class_exists( 'PKFLOW_Integration_Manager' ) && method_exists( 'PKFLOW_Integration_Manager', 'get_settings_registry' ) ) {
			$integration_settings = PKFLOW_Integration_Manager::get_settings_registry();
			if ( ! empty( $integration_settings ) ) {
				?>
				<div class="pkflow-card">
					<div class="pkflow-card__header">
						<div>
							<h3><?php esc_html_e( 'Integration modules', 'advanced-passkey-login' ); ?></h3>
							<p><?php esc_html_e( 'Control each integration independently with master and auto-inject switches.', 'advanced-passkey-login' ); ?></p>
						</div>
					</div>
					<div class="pkflow-integration-settings-grid">
						<?php
						foreach ( $integration_settings as $integration_setting ) :
							$label                = ! empty( $integration_setting['label'] ) ? (string) $integration_setting['label'] : __( 'Integration', 'advanced-passkey-login' );
							$master_option        = ! empty( $integration_setting['master_option'] ) ? sanitize_key( (string) $integration_setting['master_option'] ) : '';
							$dependency_active    = ! empty( $integration_setting['dependency_active'] );
							$default_master       = ! empty( $integration_setting['default_master'] );
							$saved_master_enabled = $master_option ? (bool) get_option( $master_option, $default_master ) : false;
							$master_enabled       = $dependency_active ? $saved_master_enabled : false;
							?>
							<article class="pkflow-integration-setting-card<?php echo esc_attr( $dependency_active ? ' is-active' : ' is-missing' ); ?>">
								<header>
									<h4><?php echo esc_html( $label ); ?></h4>
									<span class="pkflow-integration-status <?php echo esc_attr( $dependency_active ? 'is-active' : 'is-missing' ); ?>">
										<?php echo $dependency_active ? esc_html__( 'Installed', 'advanced-passkey-login' ) : esc_html__( 'Not installed', 'advanced-passkey-login' ); ?>
									</span>
								</header>
								<p><?php esc_html_e( 'Enable this to add passkey blocks, shortcodes, and auto sign-in prompts.', 'advanced-passkey-login' ); ?></p>
								<?php if ( ! $dependency_active && $master_option ) : ?>
									<input type="hidden" name="<?php echo esc_attr( $master_option ); ?>" value="0" />
								<?php endif; ?>
								<div class="pkflow-integration-toggle-row">
									<label><?php esc_html_e( 'Enable module', 'advanced-passkey-login' ); ?></label>
									<label class="pkflow-switch">
										<input type="checkbox" name="<?php echo esc_attr( $master_option ); ?>" value="1" <?php checked( $master_enabled ); ?> <?php disabled( ! $dependency_active ); ?> />
										<span class="pkflow-switch__track"><span class="pkflow-switch__thumb"></span></span>
										<span class="screen-reader-text"><?php esc_html_e( 'Enable integration module', 'advanced-passkey-login' ); ?></span>
									</label>
								</div>
							</article>
						<?php endforeach; ?>
					</div>
				</div>
				<?php
			}
		}
		?>

		<div class="pkflow-card">
			<div class="pkflow-card__header">
				<div>
					<h3><?php esc_html_e( 'Eligible user roles', 'advanced-passkey-login' ); ?></h3>
					<p><?php esc_html_e( 'Choose which WordPress roles can create and use passkeys.', 'advanced-passkey-login' ); ?></p>
				</div>
			</div>
			<div class="pkflow-role-grid">
				<?php foreach ( $roles as $role_key => $role ) : ?>
					<label class="pkflow-role-chip">
						<input type="checkbox" name="pkflow_eligible_roles[]" value="<?php echo esc_attr( $role_key ); ?>" <?php checked( in_array( $role_key, $eligible_roles, true ) ); ?> />
						<span><?php echo esc_html( translate_user_role( $role['name'] ) ); ?></span>
					</label>
				<?php endforeach; ?>
			</div>
		</div>

		<div class="pkflow-card pkflow-grid-2">
			<div class="pkflow-field">
				<div class="pkflow-label-row">
					<label for="pkflow_max_passkeys_per_user"><?php esc_html_e( 'Passkeys per user', 'advanced-passkey-login' ); ?></label>
				</div>
				<input id="pkflow_max_passkeys_per_user" class="regular-text" type="number" min="0" max="999999" name="pkflow_max_passkeys_per_user" value="<?php echo esc_attr( $max_passkeys ); ?>" />
				<p><?php esc_html_e( 'Maximum number of passkeys each user can register. Use 0 for no limit.', 'advanced-passkey-login' ); ?></p>
			</div>

			<div class="pkflow-field">
				<div class="pkflow-label-row">
					<label for="pkflow_user_verification"><?php esc_html_e( 'User verification', 'advanced-passkey-login' ); ?></label>
					<span class="pkflow-badge pkflow-badge--success"><?php esc_html_e( 'Recommended', 'advanced-passkey-login' ); ?></span>
				</div>
				<select id="pkflow_user_verification" name="pkflow_user_verification">
					<option value="required" <?php selected( $verification, 'required' ); ?>><?php esc_html_e( 'Required — biometric or device PIN', 'advanced-passkey-login' ); ?></option>
					<option value="preferred" <?php selected( $verification, 'preferred' ); ?>><?php esc_html_e( 'Preferred — use when available', 'advanced-passkey-login' ); ?></option>
					<option value="discouraged" <?php selected( $verification, 'discouraged' ); ?>><?php esc_html_e( 'Discouraged — presence only', 'advanced-passkey-login' ); ?></option>
				</select>
				<p><?php esc_html_e( 'Required verification gives the strongest account protection.', 'advanced-passkey-login' ); ?></p>
			</div>
		</div>
		<?php
	}

	/**
	 * Render the dashboard overview tab.
	 */
	private function render_dashboard_tab() {
		global $wpdb;

		$credentials_table   = $this->get_credentials_table_for_audit();
		$users_with_passkeys = 0;
		$passkeys_total      = 0;

		if ( '' !== $credentials_table ) {
			$credentials_table_sql = $this->quote_table_name( $credentials_table );
			if ( '' !== $credentials_table_sql ) {
				$users_with_passkeys = (int) $wpdb->get_var( 'SELECT COUNT(DISTINCT user_id) FROM ' . $credentials_table_sql . ' WHERE revoked_at IS NULL' ); // phpcs:ignore PluginCheck.Security.DirectDB.UnescapedDBParameter,WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching,WordPress.DB.PreparedSQL.NotPrepared -- table identifier is strict-validated by quote_table_name().
				$passkeys_total      = (int) $wpdb->get_var( 'SELECT COUNT(*) FROM ' . $credentials_table_sql . ' WHERE revoked_at IS NULL' ); // phpcs:ignore PluginCheck.Security.DirectDB.UnescapedDBParameter,WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching,WordPress.DB.PreparedSQL.NotPrepared -- table identifier is strict-validated by quote_table_name().
			}
		}

		$activities_total = $this->count_combined_audit_login_rows();
		$blocked_attempts = $this->count_combined_login_event( 'login_password_blocked_passkey_only' ) + $this->count_combined_login_event( 'login_rate_limited' );

		$authenticator_totals = array();
		if ( '' !== $credentials_table ) {
			$credentials_table_sql = $this->quote_table_name( $credentials_table );
			if ( '' === $credentials_table_sql ) {
				$rows = array();
			} else {
				$rows = $wpdb->get_results( // phpcs:ignore PluginCheck.Security.DirectDB.UnescapedDBParameter,WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching,WordPress.DB.PreparedSQL.NotPrepared -- table identifier is strict-validated by quote_table_name().
					// phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared -- table identifier is strict-validated by quote_table_name().
					'SELECT COALESCE(NULLIF(TRIM(credential_label), ""), "") AS credential_label, COUNT(*) AS total FROM ' . $credentials_table_sql . ' WHERE revoked_at IS NULL GROUP BY credential_label ORDER BY total DESC LIMIT 30',
					ARRAY_A
				);
			}

			foreach ( $rows as $row ) {
				$provider = $this->resolve_authenticator_provider_for_reporting( (string) ( $row['credential_label'] ?? '' ) );
				if ( ! isset( $authenticator_totals[ $provider ] ) ) {
					$authenticator_totals[ $provider ] = 0;
				}
				$authenticator_totals[ $provider ] += (int) ( $row['total'] ?? 0 );
			}
		}

		arsort( $authenticator_totals );
		$authenticator_rows = array();
		foreach ( $authenticator_totals as $provider => $total ) {
			$authenticator_rows[] = array(
				'provider' => (string) $provider,
				'total'    => (int) $total,
			);
			if ( count( $authenticator_rows ) >= 8 ) {
				break;
			}
		}

		$authenticator_chart_labels      = array();
		$authenticator_chart_series      = array();
		$authenticator_chart_other_total = 0;
		$authenticator_chart_limit       = 5;
		$authenticator_chart_index       = 0;

		foreach ( $authenticator_totals as $provider => $total ) {
			if ( $authenticator_chart_index < $authenticator_chart_limit ) {
				$authenticator_chart_labels[] = (string) $provider;
				$authenticator_chart_series[] = (int) $total;
			} else {
				$authenticator_chart_other_total += (int) $total;
			}
			++$authenticator_chart_index;
		}

		if ( $authenticator_chart_other_total > 0 ) {
			$authenticator_chart_labels[] = __( 'Other', 'advanced-passkey-login' );
			$authenticator_chart_series[] = (int) $authenticator_chart_other_total;
		}

		$authenticator_chart_payload = array(
			'labels' => $authenticator_chart_labels,
			'series' => $authenticator_chart_series,
		);

		$login_rows                 = $this->get_combined_audit_login_rows_for_last_days( 14, 600 );
		$dashboard_allowed_statuses = array( 'success', 'blocked', 'failed' );
		$dashboard_activity_rows    = array();
		foreach ( $login_rows as $login_row ) {
			$event_type  = (string) ( $login_row['event_type'] ?? '' );
			$status_meta = $this->classify_audit_event_for_activity_feed( $event_type );
			$status_key  = (string) ( $status_meta['key'] ?? '' );
			if ( in_array( $status_key, $dashboard_allowed_statuses, true ) ) {
				$dashboard_activity_rows[] = $login_row;
			}
		}
		$dashboard_activity_rows = array_slice( $dashboard_activity_rows, 0, 8 );

		$chart_days           = 14;
		$chart_success_points = array();
		$chart_blocked_points = array();
		$chart_failed_points  = array();
		$chart_labels         = array();
		$chart_timezone       = wp_timezone();
		$day_success_buckets  = array();
		$day_blocked_buckets  = array();
		$day_failed_buckets   = array();

		for ( $offset = $chart_days - 1; $offset >= 0; $offset-- ) {
			$bucket_ts                          = strtotime( '-' . $offset . ' days', time() );
			$bucket_key                         = wp_date( 'Y-m-d', $bucket_ts, $chart_timezone );
			$day_success_buckets[ $bucket_key ] = 0;
			$day_blocked_buckets[ $bucket_key ] = 0;
			$day_failed_buckets[ $bucket_key ]  = 0;
		}

		$chart_source_rows = $this->get_combined_audit_login_rows( 300 );
		foreach ( $chart_source_rows as $row ) {
			$event_type   = (string) ( $row['event_type'] ?? '' );
			$event_bucket = $this->classify_audit_event_for_activity_trend( $event_type );
			if ( '' === $event_bucket ) {
				continue;
			}

			$timestamp_raw = (string) ( $row['log_timestamp'] ?? '' );
			$timestamp_ts  = $this->utc_datetime_to_timestamp( $timestamp_raw );
			if ( $timestamp_ts <= 0 ) {
				continue;
			}

			$day_key = wp_date( 'Y-m-d', $timestamp_ts, $chart_timezone );
			if ( 'success' === $event_bucket && array_key_exists( $day_key, $day_success_buckets ) ) {
				++$day_success_buckets[ $day_key ];
			} elseif ( 'blocked' === $event_bucket && array_key_exists( $day_key, $day_blocked_buckets ) ) {
				++$day_blocked_buckets[ $day_key ];
			} elseif ( 'failed' === $event_bucket && array_key_exists( $day_key, $day_failed_buckets ) ) {
				++$day_failed_buckets[ $day_key ];
			}
		}

		foreach ( $day_success_buckets as $day_key => $count ) {
			$chart_success_points[] = (int) $count;
			$chart_blocked_points[] = (int) ( $day_blocked_buckets[ $day_key ] ?? 0 );
			$chart_failed_points[]  = (int) ( $day_failed_buckets[ $day_key ] ?? 0 );
			$chart_labels[]         = wp_date( 'M j', strtotime( $day_key ), $chart_timezone );
		}

		$activity_chart_payload = array(
			'labels'  => $chart_labels,
			'success' => $chart_success_points,
			'blocked' => $chart_blocked_points,
			'failed'  => $chart_failed_points,
		);
		?>
		<section class="wpkpro-section-header">
			<div>
				<p class="wpkpro-eyebrow"><?php esc_html_e( 'Dashboard', 'advanced-passkey-login' ); ?></p>
				<h2><?php esc_html_e( 'Security activity overview', 'advanced-passkey-login' ); ?></h2>
			</div>
		</section>

		<div class="wpkpro-audit-stats-grid wpkpro-dashboard-kpis">
			<article class="wpkpro-audit-stat wpkpro-audit-stat--users">
				<h3><?php esc_html_e( 'Users with passkeys', 'advanced-passkey-login' ); ?></h3>
				<p><?php echo esc_html( number_format_i18n( $users_with_passkeys ) ); ?></p>
			</article>
			<article class="wpkpro-audit-stat wpkpro-audit-stat--passkeys">
				<h3><?php esc_html_e( 'Passkeys stored', 'advanced-passkey-login' ); ?></h3>
				<p><?php echo esc_html( number_format_i18n( $passkeys_total ) ); ?></p>
			</article>
			<article class="wpkpro-audit-stat wpkpro-audit-stat--passkey-logins">
				<h3><?php esc_html_e( 'Activities', 'advanced-passkey-login' ); ?></h3>
				<p><?php echo esc_html( number_format_i18n( $activities_total ) ); ?></p>
			</article>
			<article class="wpkpro-audit-stat wpkpro-audit-stat--blocked-attempts">
				<h3><?php esc_html_e( 'Blocked attempts', 'advanced-passkey-login' ); ?></h3>
				<p><?php echo esc_html( number_format_i18n( $blocked_attempts ) ); ?></p>
			</article>
		</div>

		<div class="wpkpro-dashboard-grid">
			<div class="wpkpro-card wpkpro-dashboard-card">
				<div class="wpkpro-card__header">
					<h3><?php esc_html_e( 'Overview of Authenticators', 'advanced-passkey-login' ); ?></h3>
				</div>
				<div class="wpkpro-card__body">
					<div class="wpkpro-dashboard-auth-chart-wrap">
						<div class="wpkpro-dashboard-auth-chart-labels">
							<strong><?php esc_html_e( 'Authenticator Distribution', 'advanced-passkey-login' ); ?></strong>
							<span><?php esc_html_e( 'Top providers', 'advanced-passkey-login' ); ?></span>
						</div>
						<?php if ( empty( $authenticator_chart_series ) ) : ?>
							<p class="wpkpro-dashboard-auth-chart-empty"><?php esc_html_e( 'No authenticator records yet.', 'advanced-passkey-login' ); ?></p>
						<?php else : ?>
							<div class="wpkpro-dashboard-auth-chart" data-auth-chart="<?php echo esc_attr( wp_json_encode( $authenticator_chart_payload ) ); ?>"></div>
						<?php endif; ?>
					</div>

					<div class="wpkpro-dashboard-auth-body">
						<?php if ( empty( $authenticator_rows ) ) : ?>
							<p><?php esc_html_e( 'No authenticator records yet.', 'advanced-passkey-login' ); ?></p>
						<?php else : ?>
							<ul class="wpkpro-dashboard-auth-list">
								<?php foreach ( $authenticator_rows as $row ) : ?>
									<li>
										<div>
											<?php echo wp_kses_post( $this->render_authenticator_provider_badge( (string) $row['provider'] ) ); ?>
											<span class="wpkpro-dashboard-auth-total"><?php echo esc_html( number_format_i18n( (int) $row['total'] ) ); ?></span>
										</div>
									</li>
								<?php endforeach; ?>
							</ul>
						<?php endif; ?>
					</div>
				</div>
			</div>

			<div class="wpkpro-card wpkpro-dashboard-card">
				<div class="wpkpro-card__header">
					<h3><?php esc_html_e( 'Last Login Activity', 'advanced-passkey-login' ); ?></h3>
				</div>
				<div class="wpkpro-card__body">
					<div class="wpkpro-dashboard-activity-chart-wrap">
						<div class="wpkpro-dashboard-activity-chart-labels">
							<strong><?php esc_html_e( 'Login Activity Trend', 'advanced-passkey-login' ); ?></strong>
							<span><?php esc_html_e( 'Last 14 days', 'advanced-passkey-login' ); ?></span>
						</div>
						<div class="wpkpro-dashboard-activity-chart" data-activity-chart="<?php echo esc_attr( wp_json_encode( $activity_chart_payload ) ); ?>"></div>
					</div>

					<div class="wpkpro-dashboard-activity-body">
						<?php if ( empty( $dashboard_activity_rows ) ) : ?>
							<p><?php esc_html_e( 'No login activity recorded yet.', 'advanced-passkey-login' ); ?></p>
						<?php else : ?>
							<table class="wpkpro-dashboard-activity-table">
								<tbody>
									<?php foreach ( $dashboard_activity_rows as $row ) : ?>
										<?php
										$data = json_decode( (string) ( $row['log_data'] ?? '' ), true );
										if ( ! is_array( $data ) ) {
											$data = array();
										}

										$event        = (string) ( $row['event_type'] ?? '' );
										$status_meta  = $this->classify_audit_event_for_activity_feed( $event );
										$status_key   = (string) ( $status_meta['key'] ?? 'info' );
										$status_label = (string) ( $status_meta['label'] ?? __( 'Info', 'advanced-passkey-login' ) );

										$method     = __( 'Other', 'advanced-passkey-login' );
										$method_key = 'other';
										if ( 'login_success' === $event ) {
											$method     = __( 'Passkey', 'advanced-passkey-login' );
											$method_key = 'passkey';
										} elseif ( 'login_password_success' === $event || 'login_password_blocked_passkey_only' === $event || 'login_bypass_cookie_used' === $event ) {
											$method     = __( 'Password', 'advanced-passkey-login' );
											$method_key = 'password';
										} elseif ( 'login_rate_limited' === $event ) {
											$method     = __( 'Passkey', 'advanced-passkey-login' );
											$method_key = 'passkey';
										} elseif ( in_array( $event, array( 'login_failed', 'login_credential_mismatch', 'login_begin_failed' ), true ) ) {
											$method     = __( 'Passkey', 'advanced-passkey-login' );
											$method_key = 'passkey';
										} elseif ( in_array( $event, array( 'attestation_policy_pass', 'trusted_device_match', 'trusted_device_first_seen', 'trusted_device_marked_trusted', 'session_hardening_other_sessions_terminated', 'attestation_policy_dry_run_block', 'attestation_policy_aaguid_dry_run_block', 'trusted_device_mismatch', 'attestation_policy_blocked', 'attestation_policy_aaguid_blocked', 'trusted_device_revoked' ), true ) ) {
											$method     = __( 'Security Policy', 'advanced-passkey-login' );
											$method_key = 'security';
										}

										$authenticator = isset( $data['authenticator'] ) ? (string) $data['authenticator'] : '';
										if ( '' === $authenticator && isset( $data['credential_hash'] ) ) {
											$authenticator = $this->lookup_credential_label_for_hash( (string) $data['credential_hash'] );
										}
										if ( '' === $authenticator && isset( $data['authenticator_label'] ) ) {
											$authenticator = $this->resolve_authenticator_provider_for_reporting( (string) $data['authenticator_label'] );
										}
										if ( in_array( $method_key, array( 'password', 'security' ), true ) ) {
											$authenticator = '—';
										}
										if ( '' === $authenticator ) {
											$authenticator = __( 'Unknown Authenticator', 'advanced-passkey-login' );
										}

										$user_label = isset( $data['user_login'] ) ? (string) $data['user_login'] : '';
										if ( '' === $user_label && isset( $data['user_id'] ) ) {
											$activity_user = get_userdata( (int) $data['user_id'] );
											if ( $activity_user instanceof WP_User ) {
												$user_label = (string) $activity_user->user_login;
											}
										}
										if ( '' === $user_label ) {
											$user_label = __( 'User activity', 'advanced-passkey-login' );
										}

										$timestamp_raw      = (string) ( $row['log_timestamp'] ?? '' );
										$timestamp_display  = $this->format_utc_datetime_for_display( $timestamp_raw );
										$timestamp_relative = $this->format_utc_relative_for_display( $timestamp_raw );
										?>
										<tr>
											<td>
												<strong><?php echo esc_html( $user_label ); ?></strong>
												<span class="wpkpro-dashboard-activity-meta">
													<span class="wpkpro-dashboard-status-pill wpkpro-dashboard-status-pill--<?php echo esc_attr( $status_key ); ?>">
														<span class="wpkpro-dashboard-status-dot" aria-hidden="true"></span>
														<?php echo esc_html( $status_label ); ?>
													</span>
													<span class="wpkpro-dashboard-method-pill wpkpro-dashboard-method-pill--<?php echo esc_attr( $method_key ); ?>"><?php echo esc_html( $method ); ?></span>
													<?php if ( '—' === $authenticator ) : ?>
														&mdash;
													<?php else : ?>
														<?php echo wp_kses_post( $this->render_authenticator_provider_badge( $authenticator ) ); ?>
													<?php endif; ?>
												</span>
												<span class="wpkpro-dashboard-activity-time"><?php echo esc_html( $timestamp_display ); ?><?php echo '' !== $timestamp_relative ? esc_html( ' | ' . $timestamp_relative ) : ''; ?></span>
											</td>
										</tr>
									<?php endforeach; ?>
								</tbody>
							</table>
						<?php endif; ?>
					</div>
				</div>
			</div>
		</div>
		<?php
	}

	/**
	 * Resolve credential label from a stored credential hash.
	 *
	 * @param string $credential_hash Credential SHA-256 hash.
	 * @return string
	 */
	private function lookup_credential_label_for_hash( string $credential_hash ): string {
		static $cache    = array();
		$credential_hash = strtolower( trim( $credential_hash ) );
		if ( '' === $credential_hash ) {
			return '';
		}

		if ( isset( $cache[ $credential_hash ] ) ) {
			return (string) $cache[ $credential_hash ];
		}

		global $wpdb;
		$table_name = $this->get_credentials_table_for_audit();
		$table_sql  = $this->quote_table_name( $table_name );
		if ( '' === $table_sql ) {
			$cache[ $credential_hash ] = '';
			return '';
		}

		$label = (string) $wpdb->get_var( // phpcs:ignore PluginCheck.Security.DirectDB.UnescapedDBParameter,WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching -- one-off label lookup on plugin-owned custom table.
			$wpdb->prepare(
				// phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared -- table identifier is strict-validated by quote_table_name().
				'SELECT COALESCE(NULLIF(TRIM(credential_label), ""), "") FROM ' . $table_sql . ' WHERE credential_id_hash = %s LIMIT 1',
				$credential_hash
			)
		); // phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared -- table identifier is strict-validated by quote_table_name().

		$cache[ $credential_hash ] = $label;
		return $label;
	}

	/**
	 * Locate the active credentials table used for reporting.
	 *
	 * @return string
	 */
	private function get_credentials_table_for_audit(): string {
		global $wpdb;
		$candidates = array(
			$wpdb->prefix . 'pkflow_credentials',
		);

		foreach ( $candidates as $candidate ) {
			if ( $this->table_exists( $candidate ) ) {
				return $candidate;
			}
		}

		return '';
	}

	/**
	 * Check whether a database table exists.
	 *
	 * @param string $table_name Table name.
	 * @return bool
	 */
	private function table_exists( string $table_name ): bool {
		global $wpdb;
		$table_name = trim( $table_name );
		if ( '' === $table_name ) {
			return false;
		}

		static $exists_cache = array();
		if ( array_key_exists( $table_name, $exists_cache ) ) {
			return (bool) $exists_cache[ $table_name ];
		}

		$found                       = (string) $wpdb->get_var( $wpdb->prepare( 'SHOW TABLES LIKE %s', $wpdb->esc_like( $table_name ) ) ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery
		$exists_cache[ $table_name ] = ( $found === $table_name );
		return (bool) $exists_cache[ $table_name ];
	}

	/**
	 * Quote and validate a table name for SQL usage.
	 *
	 * @param string $table_name Table name.
	 * @return string
	 */
	private function quote_table_name( string $table_name ): string {
		$table_name = trim( $table_name );
		if ( '' === $table_name ) {
			return '';
		}
		if ( 1 !== preg_match( '/^[A-Za-z0-9_]+$/', $table_name ) ) {
			return '';
		}
		return '`' . $table_name . '`';
	}

	/**
	 * Convert a UTC datetime string to a Unix timestamp.
	 *
	 * @param string $raw_datetime Datetime value.
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
	 * Format UTC datetime for admin display in site timezone.
	 *
	 * @param string $raw_datetime Datetime value.
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
	 * Render relative time label from UTC datetime input.
	 *
	 * @param string $raw_datetime Datetime value.
	 * @return string
	 */
	private function format_utc_relative_for_display( string $raw_datetime ): string {
		$timestamp = $this->utc_datetime_to_timestamp( $raw_datetime );
		if ( $timestamp <= 0 ) {
			return '';
		}

		$now   = time();
		$delta = $now - $timestamp;
		if ( $delta < 0 ) {
			return '';
		}

		if ( $delta < MINUTE_IN_SECONDS ) {
			return __( 'just now', 'advanced-passkey-login' );
		}

		return sprintf(
			/* translators: %s human time diff */
			__( '%s ago', 'advanced-passkey-login' ),
			human_time_diff( $timestamp, $now )
		);
	}

	/**
	 * Get combined audit/login rows across new and legacy log tables.
	 *
	 * @param int $limit  Row limit.
	 * @param int $offset Row offset.
	 * @return array<int, array<string, mixed>>
	 */
	private function get_combined_audit_login_rows( int $limit, int $offset = 0 ): array {
		global $wpdb;

		$limit  = max( 1, absint( $limit ) );
		$offset = max( 0, absint( $offset ) );
		$tables = array( $wpdb->prefix . 'pkflow_logs' );

		$where_sql    = '';
		$where_params = array();
		$table_sql    = '';
		foreach ( $tables as $table_name ) {
			if ( ! $this->table_exists( $table_name ) ) {
				continue;
			}

			$table_sql = $this->quote_table_name( $table_name );
			if ( '' === $table_sql ) {
				continue;
			}

			list( $where_sql, $where_params ) = $this->build_audit_event_where_clause( $this->get_audit_event_types(), true );
			break;
		}

		if ( '' === $table_sql || '' === $where_sql ) {
			return array();
		}

		$params = array_merge( $where_params, array( $limit, $offset ) );
		return $wpdb->get_results( // phpcs:ignore PluginCheck.Security.DirectDB.UnescapedDBParameter,WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching -- table identifier is strict-validated by quote_table_name(); query parameters are prepared below.
			$wpdb->prepare( // phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared,WordPress.DB.PreparedSQLPlaceholders.ReplacementsWrongNumber -- table identifier is strict-validated by quote_table_name(); placeholder count is supplied dynamically via splat params.
				'SELECT id, event_type, log_timestamp, log_data FROM ' . $table_sql . ' WHERE ' . $where_sql . ' ORDER BY log_timestamp DESC, id DESC LIMIT %d OFFSET %d', // phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared -- $table_sql and $where_sql are generated by quote_table_name()/build_audit_event_where_clause().
				...$params
			),
			ARRAY_A
		);
	}

	/**
	 * Get combined audit/login rows for a trailing day range.
	 *
	 * @param int $days  Number of days.
	 * @param int $limit Row limit.
	 * @return array<int, array<string, mixed>>
	 */
	private function get_combined_audit_login_rows_for_last_days( int $days, int $limit = 300 ): array {
		global $wpdb;

		$days       = max( 1, min( 365, absint( $days ) ) );
		$limit      = max( 1, min( 2000, absint( $limit ) ) );
		$cutoff_utc = gmdate( 'Y-m-d H:i:s', time() - ( $days * DAY_IN_SECONDS ) );

		$tables       = array( $wpdb->prefix . 'pkflow_logs' );
		$where_sql    = '';
		$where_params = array();
		$table_sql    = '';

		foreach ( $tables as $table_name ) {
			if ( ! $this->table_exists( $table_name ) ) {
				continue;
			}

			$table_sql = $this->quote_table_name( $table_name );
			if ( '' === $table_sql ) {
				continue;
			}

			list( $where_sql, $where_params ) = $this->build_audit_event_where_clause( $this->get_audit_event_types(), true );
			break;
		}

		if ( '' === $table_sql || '' === $where_sql ) {
			return array();
		}

		$where_params[] = $cutoff_utc;
		$where_params[] = $limit;
		return $wpdb->get_results( // phpcs:ignore PluginCheck.Security.DirectDB.UnescapedDBParameter,WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching -- table identifier is strict-validated by quote_table_name(); query parameters are prepared below.
			$wpdb->prepare( // phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared,WordPress.DB.PreparedSQLPlaceholders.ReplacementsWrongNumber -- table identifier is strict-validated by quote_table_name(); placeholder count is supplied dynamically via splat params.
				'SELECT id, event_type, log_timestamp, log_data FROM ' . $table_sql . ' WHERE (' . $where_sql . ') AND log_timestamp >= %s ORDER BY log_timestamp DESC, id DESC LIMIT %d', // phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared -- $table_sql and $where_sql are generated by quote_table_name()/build_audit_event_where_clause().
				...$where_params
			),
			ARRAY_A
		);
	}

	/**
	 * Count combined audit/login rows across available log tables.
	 *
	 * @return int
	 */
	private function count_combined_audit_login_rows(): int {
		global $wpdb;
		$total = 0;

		$tables = array( $wpdb->prefix . 'pkflow_logs' );
		foreach ( $tables as $table_name ) {
			if ( ! $this->table_exists( $table_name ) ) {
				continue;
			}

			$table_sql = $this->quote_table_name( $table_name );
			if ( '' === $table_sql ) {
				continue;
			}

			list( $where_sql, $where_params ) = $this->build_audit_event_where_clause( $this->get_audit_event_types(), true );
			$total                           += (int) $wpdb->get_var( // phpcs:ignore PluginCheck.Security.DirectDB.UnescapedDBParameter,WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching -- aggregate count over plugin-owned log tables.
				$wpdb->prepare(
					// phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared,WordPress.DB.PreparedSQLPlaceholders.UnfinishedPrepare -- table identifier is strict-validated by quote_table_name(); where clause placeholders are generated by build_audit_event_where_clause().
					'SELECT COUNT(*) FROM ' . $table_sql . ' WHERE ' . $where_sql,
					...$where_params
				)
			);
		}

		return $total;
	}

	/**
	 * Count a specific event type across combined log tables.
	 *
	 * @param string $event_type Event type key.
	 * @return int
	 */
	private function count_combined_login_event( string $event_type ): int {
		global $wpdb;
		$event_type = sanitize_key( $event_type );
		if ( '' === $event_type ) {
			return 0;
		}

		$total  = 0;
		$tables = array( $wpdb->prefix . 'pkflow_logs' );
		foreach ( $tables as $table_name ) {
			if ( ! $this->table_exists( $table_name ) ) {
				continue;
			}

			$table_sql = $this->quote_table_name( $table_name );
			if ( '' === $table_sql ) {
				continue;
			}

			$total += (int) $wpdb->get_var( // phpcs:ignore PluginCheck.Security.DirectDB.UnescapedDBParameter,WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching -- aggregate count over plugin-owned log table.
				$wpdb->prepare( 'SELECT COUNT(*) FROM ' . $table_sql . ' WHERE event_type = %s', $event_type ) // phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared -- table identifier is strict-validated by quote_table_name().
			);
		}

		return $total;
	}

	/**
	 * List all event types included in audit reporting.
	 *
	 * @return array<int, string>
	 */
	private function get_audit_event_types(): array {
		return array(
			'login_success',
			'login_password_success',
			'login_password_blocked_passkey_only',
			'login_rate_limited',
			'login_failed',
			'login_credential_mismatch',
			'login_begin_failed',
			'login_bypass_cookie_used',
			'attestation_policy_pass',
			'attestation_policy_dry_run_block',
			'attestation_policy_blocked',
			'attestation_policy_aaguid_dry_run_block',
			'attestation_policy_aaguid_blocked',
			'trusted_device_first_seen',
			'trusted_device_match',
			'trusted_device_mismatch',
			'trusted_device_marked_trusted',
			'trusted_device_revoked',
			'session_hardening_other_sessions_terminated',
		);
	}

	/**
	 * Build WHERE SQL and parameters for selected audit event filters.
	 *
	 * @param array<int, string> $events Event keys.
	 * @param bool               $include_magic_recovery_prefixes Include magic/recovery prefixed events.
	 * @return array{0:string,1:array<int,string>}
	 */
	private function build_audit_event_where_clause( array $events, bool $include_magic_recovery_prefixes ): array {
		if ( empty( $events ) ) {
			return array( '1=0', array() );
		}

		$placeholders = implode( ',', array_fill( 0, count( $events ), '%s' ) );
		$where_sql    = 'event_type IN (' . $placeholders . ')';
		$params       = array_values( $events );

		if ( $include_magic_recovery_prefixes ) {
			$where_sql .= ' OR event_type LIKE %s OR event_type LIKE %s';
			$params[]   = 'magic_link_%';
			$params[]   = 'recovery_code_%';
		}

		return array( $where_sql, $params );
	}

	/**
	 * Map an event type to success/blocked/failed trend bucket.
	 *
	 * @param string $event_type Event type key.
	 * @return string
	 */
	private function classify_audit_event_for_activity_trend( string $event_type ): string {
		if ( '' === $event_type ) {
			return '';
		}

		if ( in_array( $event_type, array( 'login_success', 'login_password_success', 'login_bypass_cookie_used', 'magic_link_success', 'recovery_code_success' ), true ) ) {
			return 'success';
		}

		if ( in_array( $event_type, array( 'login_password_blocked_passkey_only', 'login_rate_limited', 'recovery_code_rate_limited', 'magic_link_rate_limited' ), true ) ) {
			return 'blocked';
		}

		if ( in_array( $event_type, array( 'login_failed', 'login_credential_mismatch', 'login_begin_failed', 'magic_link_invalid_or_expired', 'magic_link_replay_denied', 'recovery_code_invalid_or_used' ), true ) ) {
			return 'failed';
		}

		return '';
	}

	/**
	 * Map an event type to feed badge metadata.
	 *
	 * @param string $event_type Event type key.
	 * @return array{key:string,label:string}
	 */
	private function classify_audit_event_for_activity_feed( string $event_type ): array {
		if ( '' === $event_type ) {
			return array(
				'key'   => 'info',
				'label' => __( 'Info', 'advanced-passkey-login' ),
			);
		}

		if ( in_array( $event_type, array( 'login_success', 'login_password_success', 'login_bypass_cookie_used', 'magic_link_success', 'recovery_code_success', 'attestation_policy_pass', 'trusted_device_match', 'trusted_device_first_seen', 'trusted_device_marked_trusted', 'session_hardening_other_sessions_terminated' ), true ) ) {
			return array(
				'key'   => 'success',
				'label' => __( 'Successful', 'advanced-passkey-login' ),
			);
		}

		if ( in_array( $event_type, array( 'login_password_blocked_passkey_only', 'login_rate_limited', 'magic_link_rate_limited', 'recovery_code_rate_limited', 'attestation_policy_dry_run_block', 'attestation_policy_aaguid_dry_run_block', 'attestation_policy_blocked', 'attestation_policy_aaguid_blocked', 'trusted_device_mismatch', 'trusted_device_revoked' ), true ) ) {
			return array(
				'key'   => 'blocked',
				'label' => __( 'Blocked', 'advanced-passkey-login' ),
			);
		}

		if ( in_array( $event_type, array( 'login_failed', 'login_credential_mismatch', 'login_begin_failed', 'magic_link_invalid_or_expired', 'magic_link_replay_denied', 'magic_link_send_failed', 'magic_link_recaptcha_failed', 'magic_link_user_not_found', 'magic_link_signing_error', 'magic_link_bot_challenge_failed', 'recovery_code_invalid_or_used', 'recovery_code_user_not_found', 'recovery_code_alert_failed', 'recovery_stepup_failed', 'recovery_stepup_magic_link_send_failed' ), true ) ) {
			return array(
				'key'   => 'failed',
				'label' => __( 'Failed', 'advanced-passkey-login' ),
			);
		}

		if ( 0 === strpos( $event_type, 'magic_link_' ) || 0 === strpos( $event_type, 'recovery_code_' ) ) {
			return array(
				'key'   => 'failed',
				'label' => __( 'Failed', 'advanced-passkey-login' ),
			);
		}

		return array(
			'key'   => 'info',
			'label' => __( 'Info', 'advanced-passkey-login' ),
		);
	}

	/**
	 * Normalize authenticator/provider labels for reporting.
	 *
	 * @param string $label Raw label.
	 * @return string
	 */
	private function resolve_authenticator_provider_for_reporting( string $label = '' ): string {
		$provider = 'Unknown Authenticator';

		$label_lc = strtolower( trim( $label ) );
		if ( strpos( $label_lc, 'icloud' ) !== false || strpos( $label_lc, 'apple' ) !== false ) {
			$provider = 'iCloud Keychain';
		} elseif ( strpos( $label_lc, 'bitwarden' ) !== false ) {
			$provider = 'Bitwarden';
		} elseif ( strpos( $label_lc, 'chrome' ) !== false || strpos( $label_lc, 'google' ) !== false ) {
			$provider = 'Google Password Manager';
		} elseif ( strpos( $label_lc, 'samsung' ) !== false ) {
			$provider = 'Samsung Pass';
		} elseif ( strpos( $label_lc, 'lastpass' ) !== false ) {
			$provider = 'LastPass';
		} elseif ( strpos( $label_lc, '1password' ) !== false ) {
			$provider = '1Password';
		} elseif ( strpos( $label_lc, 'dashlane' ) !== false ) {
			$provider = 'Dashlane';
		} elseif ( strpos( $label_lc, 'nordpass' ) !== false ) {
			$provider = 'NordPass';
		}

		$provider = (string) apply_filters( 'pkflow_authenticator_provider_label', $provider, '', $label );
		return '' !== $provider ? $provider : 'Unknown Authenticator';
	}

	/**
	 * Render a styled authenticator provider badge.
	 *
	 * @param string $provider Provider label.
	 * @return string
	 */
	private function render_authenticator_provider_badge( string $provider ): string {
		$provider = trim( $provider );
		if ( '' === $provider ) {
			$provider = 'Unknown Authenticator';
		}

		$provider_key = $this->normalize_authenticator_provider_key( $provider );
		$icon_markup  = $this->get_authenticator_provider_icon_svg( $provider_key );

		$html = '<span class="wpkpro-provider-chip wpkpro-provider-chip--' . esc_attr( $provider_key ) . '">';
		if ( '' !== $icon_markup ) {
			$html .= '<span class="wpkpro-provider-icon" aria-hidden="true">' . $icon_markup . '</span>';
		}
		$html .= '<span class="wpkpro-provider-label">' . esc_html( $provider ) . '</span>';
		$html .= '</span>';

		$allowed = array(
			'span'     => array(
				'class'       => true,
				'aria-hidden' => true,
			),
			'svg'      => array(
				'xmlns'           => true,
				'width'           => true,
				'height'          => true,
				'viewBox'         => true,
				'fill'            => true,
				'stroke'          => true,
				'stroke-width'    => true,
				'stroke-linecap'  => true,
				'stroke-linejoin' => true,
				'aria-hidden'     => true,
				'focusable'       => true,
				'role'            => true,
			),
			'path'     => array(
				'd'            => true,
				'fill'         => true,
				'stroke'       => true,
				'stroke-width' => true,
			),
			'circle'   => array(
				'cx'           => true,
				'cy'           => true,
				'r'            => true,
				'fill'         => true,
				'stroke'       => true,
				'stroke-width' => true,
			),
			'rect'     => array(
				'x'            => true,
				'y'            => true,
				'width'        => true,
				'height'       => true,
				'rx'           => true,
				'ry'           => true,
				'fill'         => true,
				'stroke'       => true,
				'stroke-width' => true,
			),
			'line'     => array(
				'x1'           => true,
				'y1'           => true,
				'x2'           => true,
				'y2'           => true,
				'stroke'       => true,
				'stroke-width' => true,
			),
			'polyline' => array(
				'points'       => true,
				'fill'         => true,
				'stroke'       => true,
				'stroke-width' => true,
			),
			'polygon'  => array(
				'points'       => true,
				'fill'         => true,
				'stroke'       => true,
				'stroke-width' => true,
			),
			'g'        => array(
				'fill'   => true,
				'stroke' => true,
			),
		);

		return wp_kses( $html, $allowed );
	}

	/**
	 * Normalize provider label to a stable key.
	 *
	 * @param string $provider Provider label.
	 * @return string
	 */
	private function normalize_authenticator_provider_key( string $provider ): string {
		$provider_lc = strtolower( trim( $provider ) );

		if ( strpos( $provider_lc, 'bitwarden' ) !== false ) {
			return 'bitwarden';
		}
		if ( strpos( $provider_lc, 'icloud' ) !== false || strpos( $provider_lc, 'apple' ) !== false ) {
			return 'icloud';
		}
		if ( strpos( $provider_lc, '1password' ) !== false ) {
			return '1password';
		}
		if ( strpos( $provider_lc, 'lastpass' ) !== false ) {
			return 'lastpass';
		}
		if ( strpos( $provider_lc, 'google' ) !== false || strpos( $provider_lc, 'chrome' ) !== false ) {
			return 'google';
		}
		if ( strpos( $provider_lc, 'samsung' ) !== false ) {
			return 'samsung';
		}
		if ( strpos( $provider_lc, 'dashlane' ) !== false ) {
			return 'dashlane';
		}
		if ( strpos( $provider_lc, 'nordpass' ) !== false ) {
			return 'nordpass';
		}
		if ( strpos( $provider_lc, 'proton' ) !== false ) {
			return 'proton-pass';
		}

		return 'unknown';
	}

	/**
	 * Return SVG icon markup for known provider keys.
	 *
	 * @param string $provider_key Provider key.
	 * @return string
	 */
	private function get_authenticator_provider_icon_svg( string $provider_key ): string {
		$icon = '';

		switch ( $provider_key ) {
			case 'bitwarden':
				$icon = '<svg viewBox="0 0 16 16" width="16" height="16" fill="none" aria-hidden="true" focusable="false" role="img"><path d="M8 1.6 12.8 3v4.4c0 3-1.9 5.7-4.8 7-2.9-1.3-4.8-4-4.8-7V3L8 1.6Z" stroke="currentColor" stroke-width="1.3"/><circle cx="8" cy="7" r="1.35" fill="currentColor"/><path d="M8 8.35v2" stroke="currentColor" stroke-width="1.2" stroke-linecap="round"/></svg>';
				break;
			case 'icloud':
				$icon = '<svg viewBox="0 0 16 16" width="16" height="16" fill="none" aria-hidden="true" focusable="false" role="img"><path d="M11.9 7.3a2.7 2.7 0 0 0-2.6-2.2 3 3 0 0 0-5.7.7A2.5 2.5 0 0 0 4 10.7h7.6a2.1 2.1 0 0 0 .3-3.4Z" stroke="currentColor" stroke-width="1.3" stroke-linecap="round" stroke-linejoin="round"/></svg>';
				break;
			case '1password':
				$icon = '<svg viewBox="0 0 16 16" width="16" height="16" fill="none" aria-hidden="true" focusable="false" role="img"><rect x="1.5" y="3" width="13" height="10" rx="5" stroke="currentColor" stroke-width="1.5"/><circle cx="8" cy="8" r="2" fill="currentColor"/><path d="M8 8v2.1" stroke="#fff" stroke-width="1.2" stroke-linecap="round"/></svg>';
				break;
			case 'lastpass':
				$icon = '<svg viewBox="0 0 16 16" width="16" height="16" fill="none" aria-hidden="true" focusable="false" role="img"><circle cx="4.2" cy="8" r="1.6" fill="currentColor"/><circle cx="8" cy="8" r="1.6" fill="currentColor"/><circle cx="11.8" cy="8" r="1.6" fill="currentColor"/></svg>';
				break;
			case 'google':
				$icon = '<svg viewBox="0 0 16 16" width="16" height="16" fill="none" aria-hidden="true" focusable="false" role="img"><circle cx="8" cy="8" r="6" stroke="currentColor" stroke-width="1.8"/><path d="M8 5.4v2.8l2 1.2" stroke="currentColor" stroke-width="1.5" stroke-linecap="round"/></svg>';
				break;
			case 'samsung':
				$icon = '<svg viewBox="0 0 16 16" width="16" height="16" fill="none" aria-hidden="true" focusable="false" role="img"><rect x="2" y="3" width="12" height="10" rx="5" stroke="currentColor" stroke-width="1.6"/><path d="M5 8h6" stroke="currentColor" stroke-width="1.6" stroke-linecap="round"/></svg>';
				break;
			case 'dashlane':
				$icon = '<svg viewBox="0 0 16 16" width="16" height="16" fill="none" aria-hidden="true" focusable="false" role="img"><path d="M3 4.3h4.4c2.4 0 4.3 1.9 4.3 4.2S9.8 12.7 7.4 12.7H3V4.3Z" fill="currentColor"/><path d="M8.4 4.3H13v8.4H8.4" fill="currentColor" fill-opacity="0.55"/></svg>';
				break;
			case 'nordpass':
				$icon = '<svg viewBox="0 0 16 16" width="16" height="16" fill="none" aria-hidden="true" focusable="false" role="img"><path d="M4 12V4.5l4 3.1V12" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"/><path d="M8 12V4l4 3.3V12" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"/></svg>';
				break;
			case 'proton-pass':
				$icon = '<svg viewBox="0 0 16 16" width="16" height="16" fill="none" aria-hidden="true" focusable="false" role="img"><path d="M3 5.2A2.2 2.2 0 0 1 5.2 3h5.6A2.2 2.2 0 0 1 13 5.2v5.6a2.2 2.2 0 0 1-2.2 2.2H5.2A2.2 2.2 0 0 1 3 10.8V5.2Z" stroke="currentColor" stroke-width="1.4"/><path d="M6 8h4" stroke="currentColor" stroke-width="1.4" stroke-linecap="round"/></svg>';
				break;
			default:
				break;
		}

		return $icon;
	}

	/**
	 * Render advanced settings tab.
	 */
	private function render_advanced_tab() {
		$show_separator             = (bool) get_option( 'pkflow_show_separator', true );
		$rp_name                    = get_option( 'pkflow_rp_name', '' );
		$rp_id                      = get_option( 'pkflow_rp_id', '' );
		$login_challenge_ttl        = absint( get_option( 'pkflow_login_challenge_ttl', 300 ) );
		$registration_challenge_ttl = absint( get_option( 'pkflow_registration_challenge_ttl', 300 ) );
		$window                     = absint( get_option( 'pkflow_rate_limit_window', 300 ) );
		$max_failures               = absint( get_option( 'pkflow_rate_limit_max_failures', 5 ) );
		$lockout                    = absint( get_option( 'pkflow_rate_limit_lockout', 900 ) );
		?>
		<section class="pkflow-section-header">
			<div>
				<p class="pkflow-eyebrow"><?php esc_html_e( 'Advanced', 'advanced-passkey-login' ); ?></p>
				<h2><?php esc_html_e( 'Technical configuration', 'advanced-passkey-login' ); ?></h2>
			</div>
		</section>

		<div class="pkflow-card pkflow-card--setting">
			<div class="pkflow-setting-copy">
				<h3><?php esc_html_e( 'Show login OR separator', 'advanced-passkey-login' ); ?></h3>
				<p><?php esc_html_e( 'Display the centered OR divider above the passkey button on wp-login.php.', 'advanced-passkey-login' ); ?></p>
			</div>
			<label class="pkflow-switch">
				<input type="checkbox" name="pkflow_show_separator" value="1" <?php checked( $show_separator ); ?> />
				<span class="pkflow-switch__track"><span class="pkflow-switch__thumb"></span></span>
				<span class="screen-reader-text"><?php esc_html_e( 'Show login OR separator', 'advanced-passkey-login' ); ?></span>
			</label>
		</div>

		<div class="pkflow-card pkflow-grid-2">
			<div class="pkflow-field">
				<label for="pkflow_rp_name"><?php esc_html_e( 'Relying Party Name', 'advanced-passkey-login' ); ?></label>
				<input id="pkflow_rp_name" class="regular-text" type="text" name="pkflow_rp_name" value="<?php echo esc_attr( $rp_name ); ?>" placeholder="<?php echo esc_attr( get_bloginfo( 'name' ) ); ?>" />
				<p><?php esc_html_e( 'The name users see in their passkey prompt. Leave blank to use the site name.', 'advanced-passkey-login' ); ?></p>
			</div>
			<div class="pkflow-field">
				<label for="pkflow_rp_id"><?php esc_html_e( 'Relying Party ID', 'advanced-passkey-login' ); ?></label>
				<input id="pkflow_rp_id" class="regular-text" type="text" name="pkflow_rp_id" value="<?php echo esc_attr( $rp_id ); ?>" placeholder="<?php echo esc_attr( wp_parse_url( home_url(), PHP_URL_HOST ) ); ?>" />
				<p><?php esc_html_e( 'Usually your root domain. Leave blank unless you know you need to customize it.', 'advanced-passkey-login' ); ?></p>
			</div>
		</div>

		<div class="pkflow-card">
			<div class="pkflow-card__header">
				<div>
					<h3><?php esc_html_e( 'Passkey challenge timeouts', 'advanced-passkey-login' ); ?></h3>
					<p><?php esc_html_e( 'Control how long users have to complete passkey login or registration after a challenge is issued.', 'advanced-passkey-login' ); ?></p>
				</div>
				<span class="pkflow-badge"><?php esc_html_e( 'Seconds', 'advanced-passkey-login' ); ?></span>
			</div>
			<div class="pkflow-grid-2">
				<div class="pkflow-field">
					<label for="pkflow_login_challenge_ttl"><?php esc_html_e( 'Login challenge timeout', 'advanced-passkey-login' ); ?></label>
					<input id="pkflow_login_challenge_ttl" type="number" min="30" max="1200" name="pkflow_login_challenge_ttl" value="<?php echo esc_attr( $login_challenge_ttl ); ?>" />
					<p><?php esc_html_e( 'How long a user has to complete passkey sign-in.', 'advanced-passkey-login' ); ?></p>
				</div>
				<div class="pkflow-field">
					<label for="pkflow_registration_challenge_ttl"><?php esc_html_e( 'Registration challenge timeout', 'advanced-passkey-login' ); ?></label>
					<input id="pkflow_registration_challenge_ttl" type="number" min="30" max="1200" name="pkflow_registration_challenge_ttl" value="<?php echo esc_attr( $registration_challenge_ttl ); ?>" />
					<p><?php esc_html_e( 'How long a user has to finish passkey registration.', 'advanced-passkey-login' ); ?></p>
				</div>
			</div>
		</div>

		<div class="pkflow-card">
			<div class="pkflow-card__header">
				<div>
					<h3><?php esc_html_e( 'Rate limiting', 'advanced-passkey-login' ); ?></h3>
					<p><?php esc_html_e( 'Protect authentication endpoints from repeated failed attempts.', 'advanced-passkey-login' ); ?></p>
				</div>
				<span class="pkflow-badge pkflow-badge--success"><?php esc_html_e( 'Protected', 'advanced-passkey-login' ); ?></span>
			</div>
			<div class="pkflow-grid-3">
				<div class="pkflow-field">
					<label for="pkflow_rate_limit_window"><?php esc_html_e( 'Failure window', 'advanced-passkey-login' ); ?></label>
					<input id="pkflow_rate_limit_window" type="number" min="60" max="3600" name="pkflow_rate_limit_window" value="<?php echo esc_attr( $window ); ?>" />
					<p><?php esc_html_e( 'Seconds.', 'advanced-passkey-login' ); ?></p>
				</div>
				<div class="pkflow-field">
					<label for="pkflow_rate_limit_max_failures"><?php esc_html_e( 'Max failures', 'advanced-passkey-login' ); ?></label>
					<input id="pkflow_rate_limit_max_failures" type="number" min="1" max="50" name="pkflow_rate_limit_max_failures" value="<?php echo esc_attr( $max_failures ); ?>" />
					<p><?php esc_html_e( 'Attempts before lockout.', 'advanced-passkey-login' ); ?></p>
				</div>
				<div class="pkflow-field">
					<label for="pkflow_rate_limit_lockout"><?php esc_html_e( 'Lockout duration', 'advanced-passkey-login' ); ?></label>
					<input id="pkflow_rate_limit_lockout" type="number" min="60" max="86400" name="pkflow_rate_limit_lockout" value="<?php echo esc_attr( $lockout ); ?>" />
					<p><?php esc_html_e( 'Seconds.', 'advanced-passkey-login' ); ?></p>
				</div>
			</div>
		</div>

		<?php
	}

	/**
	 * Render shortcode reference/help tab.
	 */
	private function render_shortcodes_tab() {
		$shortcodes = array(
			array(
				'title'       => __( 'Login Form', 'advanced-passkey-login' ),
				'code'        => '[pkflow_login_button]',
				'description' => __( 'Display a passkey login form on any page.', 'advanced-passkey-login' ),
				'placement'   => __( 'Best for custom login pages.', 'advanced-passkey-login' ),
			),
			array(
				'title'       => __( 'Register Button', 'advanced-passkey-login' ),
				'code'        => '[pkflow_register_button]',
				'description' => __( 'Let signed-in users register a new passkey.', 'advanced-passkey-login' ),
				'placement'   => __( 'Best for account and onboarding pages.', 'advanced-passkey-login' ),
			),
			array(
				'title'       => __( 'Account Passkeys', 'advanced-passkey-login' ),
				'code'        => '[pkflow_passkey_profile]',
				'description' => __( 'Show a user-facing passkey management area.', 'advanced-passkey-login' ),
				'placement'   => __( 'Best for profile or dashboard pages.', 'advanced-passkey-login' ),
			),
			array(
				'title'       => __( 'Conditional Prompt', 'advanced-passkey-login' ),
				'code'        => '[pkflow_passkey_prompt]',
				'description' => __( 'Prompt eligible users to set up passwordless login.', 'advanced-passkey-login' ),
				'placement'   => __( 'Best after login or checkout.', 'advanced-passkey-login' ),
			),
		);

		if ( class_exists( 'PKFLOW_Integration_Manager' ) && method_exists( 'PKFLOW_Integration_Manager', 'get_integration_shortcodes' ) ) {
			$integration_shortcodes = PKFLOW_Integration_Manager::get_integration_shortcodes();

			foreach ( $integration_shortcodes as $integration_shortcode ) {
				if ( empty( $integration_shortcode['title'] ) || empty( $integration_shortcode['code'] ) ) {
					continue;
				}

				$shortcodes[] = array(
					'title'       => sanitize_text_field( (string) $integration_shortcode['title'] ),
					'code'        => sanitize_text_field( (string) $integration_shortcode['code'] ),
					'description' => __( 'Integration-specific passkey entry point.', 'advanced-passkey-login' ),
					'placement'   => __( 'Shown only when the related plugin is active.', 'advanced-passkey-login' ),
				);
			}
		}
		?>
		<section class="pkflow-section-header">
			<div>
				<p class="pkflow-eyebrow"><?php esc_html_e( 'Shortcodes', 'advanced-passkey-login' ); ?></p>
				<h2><?php esc_html_e( 'Drop-in passkey experiences', 'advanced-passkey-login' ); ?></h2>
				<p class="pkflow-shortcode-tab-note"><?php esc_html_e( 'Prefer visual editing? Use matching Gutenberg blocks for login, registration, profile prompts, and active integrations or drop in shortcodes wherever you need them.', 'advanced-passkey-login' ); ?></p>
			</div>
		</section>

		<div class="pkflow-shortcode-grid">
			<?php foreach ( $shortcodes as $shortcode ) : ?>
				<article class="pkflow-shortcode-card">
					<h3><?php echo esc_html( $shortcode['title'] ); ?></h3>
					<p><?php echo esc_html( $shortcode['description'] ); ?></p>
					<code><?php echo esc_html( $shortcode['code'] ); ?></code>
					<span><?php echo esc_html( $shortcode['placement'] ); ?></span>
				</article>
			<?php endforeach; ?>
		</div>

		<article class="pkflow-shortcode-helper-card" aria-label="<?php esc_attr_e( 'Shortcode quick start guide', 'advanced-passkey-login' ); ?>">
			<header class="pkflow-shortcode-helper-card__header">
				<h3><?php esc_html_e( 'Quick start: shortcode guide', 'advanced-passkey-login' ); ?></h3>
				<p><?php esc_html_e( 'Paste a shortcode into any page, post, or block that supports shortcodes. Then add options to control labels, redirects, and behavior.', 'advanced-passkey-login' ); ?></p>
			</header>

			<div class="pkflow-shortcode-helper-grid">
				<section>
					<h4><?php esc_html_e( 'How to add one', 'advanced-passkey-login' ); ?></h4>
					<ol>
						<li><?php esc_html_e( 'Open the page where you want passkey UI to appear.', 'advanced-passkey-login' ); ?></li>
						<li><?php esc_html_e( 'Add a Shortcode block (or paste into classic content).', 'advanced-passkey-login' ); ?></li>
						<li><?php esc_html_e( 'Paste a shortcode from the cards above and update the page.', 'advanced-passkey-login' ); ?></li>
					</ol>
				</section>

				<section>
					<h4><?php esc_html_e( 'Most useful options', 'advanced-passkey-login' ); ?></h4>
					<ul class="pkflow-shortcode-helper-list">
						<li><code>label</code> <?php esc_html_e( 'Change button text.', 'advanced-passkey-login' ); ?></li>
						<li><code>redirect_to</code> <?php esc_html_e( 'Send users to a specific URL after sign-in.', 'advanced-passkey-login' ); ?></li>
						<li><code>class</code> <?php esc_html_e( 'Add your own CSS class for styling.', 'advanced-passkey-login' ); ?></li>
						<li><code>allow_multiple</code> <?php esc_html_e( 'Allow more than one login button on a page (0 or 1).', 'advanced-passkey-login' ); ?></li>
						<li><code>button_label</code> <?php esc_html_e( 'Set prompt CTA text for passkey setup prompts.', 'advanced-passkey-login' ); ?></li>
					</ul>
				</section>
			</div>

			<div class="pkflow-shortcode-examples">
				<h4><?php esc_html_e( 'Copy-and-paste examples', 'advanced-passkey-login' ); ?></h4>
				<div class="pkflow-shortcode-examples__grid">
					<div>
						<p><?php esc_html_e( 'Custom login button + redirect', 'advanced-passkey-login' ); ?></p>
						<code>[pkflow_login_button label="Sign in securely" redirect_to="/my-account/"]</code>
					</div>
					<div>
						<p><?php esc_html_e( 'Multiple login buttons on one page', 'advanced-passkey-login' ); ?></p>
						<code>[pkflow_login_button allow_multiple="1" class="my-passkey-login"]</code>
					</div>
					<div>
						<p><?php esc_html_e( 'Custom register button label', 'advanced-passkey-login' ); ?></p>
						<code>[pkflow_register_button label="Add this device"]</code>
					</div>
					<div>
						<p><?php esc_html_e( 'Prompt users to set up passkeys', 'advanced-passkey-login' ); ?></p>
						<code>[pkflow_passkey_prompt title="Secure your account" button_label="Set up passkey"]</code>
					</div>
				</div>
			</div>
		</article>
		<?php
	}

	/**
	 * Render settings sidebar cards.
	 */
	private function render_sidebar_cards() {
		?>
		<section class="pkflow-side-card">
			<h2><?php esc_html_e( 'Quick setup', 'advanced-passkey-login' ); ?></h2>
			<ol class="pkflow-checklist">
				<li><?php esc_html_e( 'Activate the plugin', 'advanced-passkey-login' ); ?></li>
				<li><?php esc_html_e( 'Enable passkeys in Settings', 'advanced-passkey-login' ); ?></li>
				<li><?php esc_html_e( 'Choose eligible roles', 'advanced-passkey-login' ); ?></li>
				<li><?php esc_html_e( 'Register your first passkey in Your Profile', 'advanced-passkey-login' ); ?></li>
				<li><?php esc_html_e( 'Sign out and test the login button', 'advanced-passkey-login' ); ?></li>
			</ol>
		</section>

		<?php
		if ( class_exists( 'PKFLOW_Integration_Manager' ) && method_exists( 'PKFLOW_Integration_Manager', 'get_available_integrations' ) ) {
			$available_integrations = PKFLOW_Integration_Manager::get_available_integrations();
			if ( ! empty( $available_integrations ) ) {
				?>
				<section class="pkflow-side-card">
					<h2><?php esc_html_e( 'Active integrations', 'advanced-passkey-login' ); ?></h2>
					<p><?php esc_html_e( 'Passkey modules, shortcodes, and Gutenberg blocks are available for these detected plugins.', 'advanced-passkey-login' ); ?></p>
					<ul>
						<?php foreach ( $available_integrations as $integration_label ) : ?>
							<li><?php echo esc_html( $integration_label ); ?></li>
						<?php endforeach; ?>
					</ul>
				</section>
				<?php
			}
		}
		?>

		<?php
	}

	/**
	 * Render footer links within the settings shell.
	 */
	private function render_shell_footer() {
		?>
		<footer class="pkflow-shell-footer" aria-label="<?php esc_attr_e( 'Maintainer links', 'advanced-passkey-login' ); ?>">
			<span class="pkflow-shell-footer__label"><?php esc_html_e( 'Maintained by mbuiux', 'advanced-passkey-login' ); ?></span>
			<a class="pkflow-shell-footer__link" href="https://profiles.wordpress.org/mbuiux/" target="_blank" rel="noopener noreferrer">
				<span class="pkflow-shell-footer__icon" aria-hidden="true">
					<span class="dashicons dashicons-wordpress" aria-hidden="true"></span>
				</span>
				<span><?php esc_html_e( 'WordPress.org', 'advanced-passkey-login' ); ?></span>
			</a>
			<a class="pkflow-shell-footer__link" href="https://github.com/mbuiux/advanced-passkey-login.git" target="_blank" rel="noopener noreferrer">
				<span class="pkflow-shell-footer__icon" aria-hidden="true">
					<svg viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg" focusable="false">
						<path d="M12 .5C5.65.5.5 5.67.5 12.06c0 5.12 3.3 9.46 7.87 10.99.58.11.79-.26.79-.57v-2.02c-3.2.7-3.88-1.56-3.88-1.56-.52-1.34-1.28-1.69-1.28-1.69-1.05-.72.08-.7.08-.7 1.16.08 1.77 1.2 1.77 1.2 1.03 1.78 2.7 1.27 3.36.97.1-.76.4-1.27.73-1.56-2.56-.29-5.25-1.29-5.25-5.73 0-1.26.45-2.29 1.19-3.1-.12-.29-.51-1.46.11-3.04 0 0 .97-.32 3.18 1.18a10.97 10.97 0 0 1 5.8 0c2.2-1.5 3.17-1.18 3.17-1.18.63 1.58.24 2.75.12 3.04.74.81 1.18 1.84 1.18 3.1 0 4.46-2.69 5.44-5.26 5.72.41.36.78 1.08.78 2.18v3.24c0 .32.21.69.8.57A11.6 11.6 0 0 0 23.5 12.06C23.5 5.67 18.35.5 12 .5Z"/>
					</svg>
				</span>
				<span><?php esc_html_e( 'GitHub', 'advanced-passkey-login' ); ?></span>
			</a>
		</footer>
		<?php
	}

	/**
	 * Normalize checkbox value to int flag.
	 *
	 * @param mixed $value Raw value.
	 * @return int
	 */
	public function sanitize_checkbox( $value ) {
		return ! empty( $value ) ? 1 : 0;
	}

	/**
	 * Sanitize eligible roles list.
	 *
	 * @param mixed $roles Submitted roles.
	 * @return array<int, string>
	 */
	public function sanitize_roles( $roles ) {
		if ( ! is_array( $roles ) ) {
			return array();
		}

		$valid_roles = array_keys( wp_roles()->roles );
		return array_values( array_intersect( array_map( 'sanitize_key', $roles ), $valid_roles ) );
	}

	/**
	 * Sanitize max passkeys setting.
	 *
	 * @param mixed $value Raw value.
	 * @return int
	 */
	public function sanitize_max_passkeys( $value ) {
		return min( 999999, max( 0, absint( $value ) ) );
	}

	/**
	 * Sanitize user verification mode.
	 *
	 * @param mixed $value Raw value.
	 * @return string
	 */
	public function sanitize_user_verification( $value ) {
		$allowed = array( 'required', 'preferred', 'discouraged' );
		return in_array( $value, $allowed, true ) ? $value : 'required';
	}

	/**
	 * Sanitize relying party ID.
	 *
	 * @param mixed $value Raw value.
	 * @return string
	 */
	public function sanitize_rp_id( $value ) {
		$value = strtolower( sanitize_text_field( $value ) );
		return preg_replace( '/[^a-z0-9.-]/', '', $value );
	}

	/**
	 * Sanitize rate-limit window setting.
	 *
	 * @param mixed $value Raw value.
	 * @return int
	 */
	public function sanitize_rate_limit_window( $value ) {
		return min( 3600, max( 60, absint( $value ) ) );
	}

	/**
	 * Sanitize max failures setting.
	 *
	 * @param mixed $value Raw value.
	 * @return int
	 */
	public function sanitize_rate_limit_max_failures( $value ) {
		return min( 50, max( 1, absint( $value ) ) );
	}

	/**
	 * Sanitize lockout duration setting.
	 *
	 * @param mixed $value Raw value.
	 * @return int
	 */
	public function sanitize_rate_limit_lockout( $value ) {
		return min( 86400, max( 60, absint( $value ) ) );
	}

	/**
	 * Sanitize challenge timeout setting.
	 *
	 * @param mixed $value Raw value.
	 * @return int
	 */
	public function sanitize_challenge_ttl( $value ) {
		return min( 1200, max( 30, absint( $value ) ) );
	}
}
