<?php
/**
 * WPK_Settings — admin settings page for WP Passkey.
 *
 * Registers the "Settings > WP Passkey" submenu and all option fields.
 * All options are prefixed `wpk_`.
 *
 * REDESIGNED UI (v1.1) — keeps all original options/sanitize logic intact;
 * only the rendered HTML and the wpk-admin.css stylesheet have changed.
 */

if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

class WPK_Settings {

    const PAGE_SLUG      = 'wp-passkeys';
    const ADVANCED_SLUG  = 'wp-passkeys-advanced';
    const OPTION_GROUP   = 'wpk_settings';

    public function __construct() {
        add_action( 'admin_menu',            array( $this, 'register_menu' ) );
        add_action( 'admin_init',            array( $this, 'register_settings' ) );
        add_action( 'admin_init',            array( $this, 'maybe_reset_defaults' ) );
        add_action( 'admin_enqueue_scripts', array( $this, 'enqueue_settings_assets' ) );
    }

    // ──────────────────────────────────────────────────────────
    // Reset to defaults
    // ──────────────────────────────────────────────────────────

    public function maybe_reset_defaults(): void {
        if ( ( $_GET['wpk_action'] ?? '' ) !== 'reset_defaults' ) { // phpcs:ignore WordPress.Security.NonceVerification.Recommended
            return;
        }
        if ( ! current_user_can( 'manage_options' ) ) {
            wp_die( esc_html__( 'You do not have permission to do this.', 'wp-passkeys' ) );
        }
        check_admin_referer( 'wpk_reset_defaults' );

        $defaults = array(
            'wpk_enabled'               => 1,
            'wpk_show_separator'        => 1,
            'wpk_show_setup_notice'     => 1,
            'wpk_eligible_roles'        => array( 'administrator' ),
            'wpk_max_passkeys_per_user' => WPK_Passkeys::LITE_MAX_PASSKEYS,
            'wpk_user_verification'     => 'required',
            'wpk_rate_window'           => 300,
            'wpk_rate_max_attempts'     => 8,
            'wpk_rate_lockout'          => 900,
            'wpk_challenge_ttl'         => 300,
            'wpk_login_redirect'        => '',
            'wpk_log_retention_days'    => 90,
            'wpk_rp_name'               => '',
        );
        foreach ( $defaults as $option => $value ) {
            update_option( $option, $value );
        }

        add_settings_error( self::OPTION_GROUP, 'wpk_reset_success', __( 'Settings reset to defaults.', 'wp-passkeys' ), 'success' );
        set_transient( 'settings_errors', get_settings_errors(), 30 );

        $tab = isset( $_GET['tab'] ) ? sanitize_key( $_GET['tab'] ) : 'settings'; // phpcs:ignore WordPress.Security.NonceVerification.Recommended
        wp_safe_redirect( add_query_arg(
            array( 'page' => self::PAGE_SLUG, 'tab' => $tab, 'settings-updated' => 'true' ),
            admin_url( 'options-general.php' )
        ) );
        exit;
    }

    // ──────────────────────────────────────────────────────────
    // Menu
    // ──────────────────────────────────────────────────────────

    public function register_menu(): void {
        add_options_page(
            __( 'WP Passkey', 'wp-passkeys' ),
            __( 'WP Passkey', 'wp-passkeys' ),
            'manage_options',
            self::PAGE_SLUG,
            array( $this, 'render_settings_page' )
        );
    }

    // ──────────────────────────────────────────────────────────
    // Assets
    // ──────────────────────────────────────────────────────────

    public function enqueue_settings_assets( string $hook ): void {
        if ( $hook !== 'settings_page_wp-passkeys' ) {
            return;
        }
        wp_enqueue_style( 'wpk-admin', WPK_PLUGIN_URL . 'admin/css/wpk-admin.css', array(), WPK_VERSION );
    }

    // ──────────────────────────────────────────────────────────
    // Settings registration  (UNCHANGED from v1.0)
    // ──────────────────────────────────────────────────────────

    public function register_settings(): void {

        // ── General ────────────────────────────────────────────
        add_settings_section( 'wpk_general', __( 'General', 'wp-passkeys' ), array( $this, 'section_intro_general' ), self::PAGE_SLUG );

        register_setting( self::OPTION_GROUP, 'wpk_enabled', array(
            'type'              => 'integer',
            'default'           => 1,
            'sanitize_callback' => 'absint',
        ) );
        add_settings_field( 'wpk_enabled', __( 'Enable Passkeys', 'wp-passkeys' ),
            array( $this, 'field_checkbox' ), self::PAGE_SLUG, 'wpk_general',
            array( 'option' => 'wpk_enabled', 'description' => __( 'Allow users to register and sign in with passkeys.', 'wp-passkeys' ) )
        );

        register_setting( self::OPTION_GROUP, 'wpk_show_separator', array(
            'type'              => 'integer',
            'default'           => 1,
            'sanitize_callback' => 'absint',
        ) );
        add_settings_field( 'wpk_show_separator', __( 'Show "OR" Separator', 'wp-passkeys' ),
            array( $this, 'field_checkbox' ), self::PAGE_SLUG, 'wpk_general',
            array( 'option' => 'wpk_show_separator', 'description' => __( 'Display the "OR" divider line above the passkey button on the login page.', 'wp-passkeys' ) )
        );

        register_setting( self::OPTION_GROUP, 'wpk_show_setup_notice', array(
            'type'              => 'integer',
            'default'           => 1,
            'sanitize_callback' => 'absint',
        ) );
        add_settings_field( 'wpk_show_setup_notice', __( 'Passkey Setup Reminder', 'wp-passkeys' ),
            array( $this, 'field_checkbox' ), self::PAGE_SLUG, 'wpk_general',
            array( 'option' => 'wpk_show_setup_notice', 'description' => __( 'Show a dismissible admin notice to eligible users who have not yet registered a passkey.', 'wp-passkeys' ) )
        );

        register_setting( self::OPTION_GROUP, 'wpk_eligible_roles', array(
            'type'              => 'array',
            'default'           => array( 'administrator' ),
            'sanitize_callback' => array( $this, 'sanitize_roles' ),
        ) );
        add_settings_field( 'wpk_eligible_roles', __( 'Eligible Roles', 'wp-passkeys' ),
            array( $this, 'field_roles' ), self::PAGE_SLUG, 'wpk_general',
            array( 'option' => 'wpk_eligible_roles', 'description' => __( 'Which user roles may register and use passkeys.', 'wp-passkeys' ) )
        );

        register_setting( self::OPTION_GROUP, 'wpk_max_passkeys_per_user', array(
            'type'              => 'integer',
            'default'           => WPK_Passkeys::LITE_MAX_PASSKEYS,
            'sanitize_callback' => array( $this, 'sanitize_max_passkeys' ),
        ) );
        add_settings_field( 'wpk_max_passkeys_per_user', __( 'Passkeys per User', 'wp-passkeys' ),
            array( $this, 'field_max_passkeys' ), self::PAGE_SLUG, 'wpk_general',
            array( 'option' => 'wpk_max_passkeys_per_user' )
        );

        // ── Security ───────────────────────────────────────────
        add_settings_section( 'wpk_security', __( 'Security', 'wp-passkeys' ), array( $this, 'section_intro_security' ), self::PAGE_SLUG );

        register_setting( self::OPTION_GROUP, 'wpk_user_verification', array(
            'type'              => 'string',
            'default'           => 'required',
            'sanitize_callback' => array( $this, 'sanitize_user_verification' ),
        ) );
        add_settings_field( 'wpk_user_verification', __( 'User Verification', 'wp-passkeys' ),
            array( $this, 'field_user_verification' ), self::PAGE_SLUG, 'wpk_security',
            array( 'option' => 'wpk_user_verification' )
        );

        // ── Rate Limiting ──────────────────────────────────────
        add_settings_section( 'wpk_rate_limiting', __( 'Rate Limiting', 'wp-passkeys' ), array( $this, 'section_intro_rate' ), self::PAGE_SLUG );

        register_setting( self::OPTION_GROUP, 'wpk_rate_window', array(
            'type'              => 'integer',
            'default'           => 300,
            'sanitize_callback' => array( $this, 'sanitize_rate_window' ),
        ) );
        add_settings_field( 'wpk_rate_window', __( 'Failure Window (seconds)', 'wp-passkeys' ),
            array( $this, 'field_number' ), self::PAGE_SLUG, 'wpk_rate_limiting',
            array( 'option' => 'wpk_rate_window', 'min' => 60, 'max' => 3600, 'default' => 300,
                   'description' => __( 'Time window in which failures are counted before a lockout is triggered.', 'wp-passkeys' ) )
        );

        register_setting( self::OPTION_GROUP, 'wpk_rate_max_attempts', array(
            'type'              => 'integer',
            'default'           => 8,
            'sanitize_callback' => array( $this, 'sanitize_rate_attempts' ),
        ) );
        add_settings_field( 'wpk_rate_max_attempts', __( 'Max Failures Before Lockout', 'wp-passkeys' ),
            array( $this, 'field_number' ), self::PAGE_SLUG, 'wpk_rate_limiting',
            array( 'option' => 'wpk_rate_max_attempts', 'min' => 1, 'max' => 50, 'default' => 8,
                   'description' => __( 'Number of failures allowed within the window before the IP/user is locked out.', 'wp-passkeys' ) )
        );

        register_setting( self::OPTION_GROUP, 'wpk_rate_lockout', array(
            'type'              => 'integer',
            'default'           => 900,
            'sanitize_callback' => array( $this, 'sanitize_rate_lockout' ),
        ) );
        add_settings_field( 'wpk_rate_lockout', __( 'Lockout Duration (seconds)', 'wp-passkeys' ),
            array( $this, 'field_number' ), self::PAGE_SLUG, 'wpk_rate_limiting',
            array( 'option' => 'wpk_rate_lockout', 'min' => 60, 'max' => 86400, 'default' => 900,
                   'description' => __( 'How long an IP or user is locked out after exceeding the failure threshold.', 'wp-passkeys' ) )
        );

        // ── Advanced (tab 2) ───────────────────────────────────
        add_settings_section( 'wpk_advanced', __( 'Advanced', 'wp-passkeys' ), array( $this, 'section_intro_advanced' ), self::ADVANCED_SLUG );

        register_setting( self::OPTION_GROUP, 'wpk_challenge_ttl', array(
            'type'              => 'integer',
            'default'           => 300,
            'sanitize_callback' => array( $this, 'sanitize_challenge_ttl' ),
        ) );
        add_settings_field( 'wpk_challenge_ttl', __( 'Challenge Timeout (seconds)', 'wp-passkeys' ),
            array( $this, 'field_number' ), self::ADVANCED_SLUG, 'wpk_advanced',
            array( 'option' => 'wpk_challenge_ttl', 'min' => 30, 'max' => 600, 'default' => 300,
                   'description' => __( 'How long a passkey registration or login challenge stays valid. 300 seconds (5 minutes) is recommended.', 'wp-passkeys' ) )
        );

        register_setting( self::OPTION_GROUP, 'wpk_login_redirect', array(
            'type'              => 'string',
            'default'           => '',
            'sanitize_callback' => array( $this, 'sanitize_redirect_url' ),
        ) );
        add_settings_field( 'wpk_login_redirect', __( 'Login Redirect URL', 'wp-passkeys' ),
            array( $this, 'field_text' ), self::ADVANCED_SLUG, 'wpk_advanced',
            array( 'option' => 'wpk_login_redirect', 'placeholder' => admin_url(),
                   'description' => __( 'Where to send users after a successful passkey login. Leave blank to use the default WordPress redirect (wp-admin for admins). The wpk_login_redirect filter can override this per-user (Pro).', 'wp-passkeys' ) )
        );

        register_setting( self::OPTION_GROUP, 'wpk_log_retention_days', array(
            'type'              => 'integer',
            'default'           => 90,
            'sanitize_callback' => array( $this, 'sanitize_log_retention' ),
        ) );
        add_settings_field( 'wpk_log_retention_days', __( 'Log Retention (days)', 'wp-passkeys' ),
            array( $this, 'field_number' ), self::ADVANCED_SLUG, 'wpk_advanced',
            array( 'option' => 'wpk_log_retention_days', 'min' => 7, 'max' => 365, 'default' => 90,
                   'description' => __( 'Activity log entries older than this are automatically deleted on the daily cron run. Requires WPK_ENABLE_LOGGING to be active.', 'wp-passkeys' ) )
        );

        register_setting( self::OPTION_GROUP, 'wpk_rp_name', array(
            'type'              => 'string',
            'default'           => '',
            'sanitize_callback' => 'sanitize_text_field',
        ) );
        add_settings_field( 'wpk_rp_name', __( 'Relying Party Name', 'wp-passkeys' ),
            array( $this, 'field_text' ), self::ADVANCED_SLUG, 'wpk_advanced',
            array( 'option' => 'wpk_rp_name', 'placeholder' => get_bloginfo( 'name' ),
                   'description' => __( 'Your site\'s display name, sent to the authenticator during passkey registration. Some platforms (e.g. Chrome on Windows, Android) show this in the "Create a passkey" dialog. Note: the sign-in prompt always shows your domain (RP ID) — that is a browser/OS requirement and cannot be changed. Defaults to site name.', 'wp-passkeys' ) )
        );
    }

    // Section intros (small descriptive paragraphs above each section)
    public function section_intro_general(): void {
        echo '<p>' . esc_html__( 'Core behavior and which users can use passkeys.', 'wp-passkeys' ) . '</p>';
    }
    public function section_intro_security(): void {
        echo '<p>' . esc_html__( 'Choose how strictly users must prove their presence.', 'wp-passkeys' ) . '</p>';
    }
    public function section_intro_rate(): void {
        echo '<p>' . esc_html__( 'Protects against brute-force attacks. Defaults are secure for most sites.', 'wp-passkeys' ) . '</p>';
    }
    public function section_intro_advanced(): void {
        echo '<p>' . esc_html__( 'Fine-tune timeouts, redirects, and data retention. Values here can also be set via PHP constants in wp-config.php.', 'wp-passkeys' ) . '</p>';
    }

    // ──────────────────────────────────────────────────────────
    // Page render  (REDESIGNED)
    // ──────────────────────────────────────────────────────────

    public function render_settings_page(): void {
        if ( ! current_user_can( 'manage_options' ) ) {
            return;
        }

        $current_tab = isset( $_GET['tab'] ) ? sanitize_key( $_GET['tab'] ) : 'settings'; // phpcs:ignore WordPress.Security.NonceVerification.Recommended
        $tabs = array(
            'settings'  => __( 'Settings', 'wp-passkeys' ),
            'advanced'  => __( 'Advanced', 'wp-passkeys' ),
            'shortcodes'=> __( 'Shortcodes', 'wp-passkeys' ),
        );
        $is_enabled = (int) get_option( 'wpk_enabled', 1 ) === 1;
        $base_url   = admin_url( 'options-general.php?page=' . self::PAGE_SLUG );
        ?>
        <div class="wrap wpk-settings-wrap">

            <header class="wpk-page-header">
                <h1>
                    <?php esc_html_e( 'WP Passkey', 'wp-passkeys' ); ?>
                    <?php if ( $is_enabled ) : ?>
                        <span class="wpk-status-pill"><?php esc_html_e( 'Active', 'wp-passkeys' ); ?></span>
                    <?php endif; ?>
                </h1>
                <p class="wpk-tagline">
                    <?php esc_html_e( 'Passwordless login for WordPress — powered by WebAuthn / FIDO2.', 'wp-passkeys' ); ?>
                </p>
            </header>

            <nav class="nav-tab-wrapper">
                <?php foreach ( $tabs as $slug => $label ) : ?>
                    <a href="<?php echo esc_url( $base_url . '&tab=' . $slug ); ?>"
                       class="nav-tab<?php echo $current_tab === $slug ? ' nav-tab-active' : ''; ?>">
                        <?php echo esc_html( $label ); ?>
                    </a>
                <?php endforeach; ?>
            </nav>

            <?php settings_errors( self::OPTION_GROUP ); ?>

            <?php if ( $current_tab === 'settings' ) : ?>

            <div class="wpk-settings-body">
                <div class="wpk-settings-main">
                    <div class="wpk-settings-card">
                        <div class="wpk-settings-card__header">
                            <h2><?php esc_html_e( 'Configuration', 'wp-passkeys' ); ?></h2>
                            <p><?php esc_html_e( 'Control how passkeys behave across your site.', 'wp-passkeys' ); ?></p>
                        </div>
                        <form method="post" action="options.php">
                            <?php
                            settings_fields( self::OPTION_GROUP );
                            do_settings_sections( self::PAGE_SLUG );
                            $this->render_submit_row( 'settings' );
                            ?>
                        </form>
                    </div>
                </div>
                <aside class="wpk-settings-sidebar">
                    <?php $this->render_pro_card(); ?>
                    <?php $this->render_quick_setup_card(); ?>
                    <?php $this->render_compatibility_card(); ?>
                </aside>
            </div>

            <?php elseif ( $current_tab === 'advanced' ) : ?>

            <div class="wpk-settings-body">
                <div class="wpk-settings-main">
                    <div class="wpk-settings-card">
                        <div class="wpk-settings-card__header">
                            <h2><?php esc_html_e( 'Advanced Settings', 'wp-passkeys' ); ?></h2>
                            <p><?php esc_html_e( 'Fine-tune timeouts, redirects, data retention, and technical defaults.', 'wp-passkeys' ); ?></p>
                        </div>
                        <form method="post" action="options.php">
                            <?php
                            settings_fields( self::OPTION_GROUP );
                            do_settings_sections( self::ADVANCED_SLUG );
                            $this->render_submit_row( 'advanced' );
                            ?>
                        </form>
                    </div>

                    <div class="wpk-settings-card" style="margin-top:20px;">
                        <div class="wpk-settings-card__header">
                            <h2><?php esc_html_e( 'Scheduled Cleanup', 'wp-passkeys' ); ?></h2>
                            <p><?php esc_html_e( 'Automatic maintenance runs daily via WordPress cron.', 'wp-passkeys' ); ?></p>
                        </div>
                        <div style="padding:16px 24px 20px;">
                            <?php
                            $next = wp_next_scheduled( 'wpk_scheduled_cleanup' );
                            $log_on = defined( 'WPK_ENABLE_LOGGING' ) && WPK_ENABLE_LOGGING;
                            ?>
                            <table class="form-table" role="presentation">
                                <tr>
                                    <th scope="row"><?php esc_html_e( 'Next run', 'wp-passkeys' ); ?></th>
                                    <td>
                                        <?php if ( $next ) : ?>
                                            <strong><?php echo esc_html( wp_date( get_option( 'date_format' ) . ' ' . get_option( 'time_format' ), $next ) ); ?></strong>
                                        <?php else : ?>
                                            <em><?php esc_html_e( 'Not scheduled — deactivate and reactivate the plugin to reschedule.', 'wp-passkeys' ); ?></em>
                                        <?php endif; ?>
                                    </td>
                                </tr>
                                <tr>
                                    <th scope="row"><?php esc_html_e( 'What it cleans', 'wp-passkeys' ); ?></th>
                                    <td>
                                        <ul style="margin:0;list-style:disc;padding-left:18px;">
                                            <li><?php esc_html_e( 'Expired rate-limit rows from wp_wpk_rate_limits', 'wp-passkeys' ); ?></li>
                                            <li>
                                                <?php
                                                if ( $log_on ) {
                                                    printf(
                                                        /* translators: %d days */
                                                        esc_html__( 'Log entries older than %d days from wp_wpk_logs', 'wp-passkeys' ),
                                                        (int) get_option( 'wpk_log_retention_days', 90 )
                                                    );
                                                } else {
                                                    echo esc_html__( 'Log cleanup (inactive — WPK_ENABLE_LOGGING is not set)', 'wp-passkeys' );
                                                }
                                                ?>
                                            </li>
                                        </ul>
                                    </td>
                                </tr>
                                <tr>
                                    <th scope="row"><?php esc_html_e( 'PHP constant overrides', 'wp-passkeys' ); ?></th>
                                    <td>
                                        <code>WPK_CHALLENGE_TTL</code>, <code>WPK_ENABLE_LOGGING</code>,
                                        <code>WPK_RP_ID</code>, <code>WPK_RP_NAME</code>,
                                        <code>WPK_ALLOW_HTTP</code>
                                        <p class="description" style="margin-top:6px;"><?php esc_html_e( 'Add these to wp-config.php to override the settings above at the server level.', 'wp-passkeys' ); ?></p>
                                    </td>
                                </tr>
                            </table>
                        </div>
                    </div>
                </div>
                <aside class="wpk-settings-sidebar">
                    <?php $this->render_pro_card(); ?>
                </aside>
            </div>

            <?php elseif ( $current_tab === 'shortcodes' ) : ?>

            <?php $this->render_shortcodes_tab(); ?>

            <?php endif; ?>

        </div>
        <?php
    }

    // ──────────────────────────────────────────────────────────
    // Custom submit row
    // ──────────────────────────────────────────────────────────

    private function render_submit_row( string $tab = 'settings' ): void {
        $reset_url = wp_nonce_url(
            add_query_arg(
                array( 'page' => self::PAGE_SLUG, 'tab' => $tab, 'wpk_action' => 'reset_defaults' ),
                admin_url( 'options-general.php' )
            ),
            'wpk_reset_defaults'
        );
        $save_icon  = '<svg xmlns="http://www.w3.org/2000/svg" width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M19 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h11l5 5v11a2 2 0 0 1-2 2z"/><polyline points="17 21 17 13 7 13 7 21"/><polyline points="7 3 7 8 15 8"/></svg>';
        $reset_icon = '<svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M3 12a9 9 0 1 0 9-9 9.75 9.75 0 0 0-6.74 2.74L3 8"/><path d="M3 3v5h5"/></svg>';
        ?>
        <div class="wpk-submit-row">
            <a href="<?php echo esc_url( $reset_url ); ?>" class="wpk-reset-link"
               onclick="return confirm('<?php echo esc_js( __( 'Reset all settings to their defaults?', 'wp-passkeys' ) ); ?>')"
            ><?php echo $reset_icon; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
            ?> <?php esc_html_e( 'Reset to defaults', 'wp-passkeys' ); ?></a>
            <button type="submit" name="submit" id="submit" class="button wpk-save-btn">
                <?php echo $save_icon; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped ?>
                <?php esc_html_e( 'Save changes', 'wp-passkeys' ); ?>
            </button>
        </div>
        <?php
    }

    // ──────────────────────────────────────────────────────────
    // Shortcodes reference tab
    // ──────────────────────────────────────────────────────────

    private function render_shortcodes_tab(): void {
        $shortcodes = array(
            array(
                'tag'         => '[wpk_login_button]',
                'description' => __( 'Renders the passkey sign-in button for logged-out visitors. Place on any page, post, or widget area.', 'wp-passkeys' ),
                'attrs'       => array(
                    'label'       => __( 'Button text. Default: "Sign in with Passkey".', 'wp-passkeys' ),
                    'redirect_to' => __( 'URL to redirect the user after a successful login. Overrides the Login Redirect URL setting for this button only.', 'wp-passkeys' ),
                    'class'       => __( 'Extra CSS class(es) added to the wrapper element.', 'wp-passkeys' ),
                ),
                'examples'    => array(
                    '[wpk_login_button]',
                    '[wpk_login_button label="Sign in with your passkey"]',
                    '[wpk_login_button redirect_to="https://example.com/dashboard"]',
                ),
            ),
            array(
                'tag'         => '[wpk_register_button]',
                'description' => __( 'Renders the passkey registration button for logged-in eligible users. Invisible to logged-out visitors and ineligible roles.', 'wp-passkeys' ),
                'attrs'       => array(
                    'label' => __( 'Button text. Default: "Register a Passkey".', 'wp-passkeys' ),
                    'class' => __( 'Extra CSS class(es) added to the wrapper element.', 'wp-passkeys' ),
                ),
                'examples'    => array(
                    '[wpk_register_button]',
                    '[wpk_register_button label="Add a passkey to your account"]',
                ),
            ),
        );
        ?>
        <div class="wpk-settings-body wpk-shortcodes-body">
            <div class="wpk-settings-main">

                <?php foreach ( $shortcodes as $sc ) : ?>
                <div class="wpk-settings-card" style="margin-bottom:20px;">
                    <div class="wpk-settings-card__header">
                        <h2><code><?php echo esc_html( $sc['tag'] ); ?></code></h2>
                        <p><?php echo esc_html( $sc['description'] ); ?></p>
                    </div>
                    <div style="padding:0 24px 20px;">

                        <h3 style="font-size:13px;margin:18px 0 8px;"><?php esc_html_e( 'Attributes', 'wp-passkeys' ); ?></h3>
                        <table class="widefat wpk-credentials-table" style="max-width:660px;">
                            <thead>
                                <tr>
                                    <th style="width:160px;"><?php esc_html_e( 'Attribute', 'wp-passkeys' ); ?></th>
                                    <th><?php esc_html_e( 'Description', 'wp-passkeys' ); ?></th>
                                </tr>
                            </thead>
                            <tbody>
                                <?php foreach ( $sc['attrs'] as $attr => $desc ) : ?>
                                <tr>
                                    <td><code><?php echo esc_html( $attr ); ?></code></td>
                                    <td><?php echo esc_html( $desc ); ?></td>
                                </tr>
                                <?php endforeach; ?>
                            </tbody>
                        </table>

                        <h3 style="font-size:13px;margin:18px 0 8px;"><?php esc_html_e( 'Examples', 'wp-passkeys' ); ?></h3>
                        <?php foreach ( $sc['examples'] as $ex ) : ?>
                            <pre class="wpk-code-example"><?php echo esc_html( $ex ); ?></pre>
                        <?php endforeach; ?>

                    </div>
                </div>
                <?php endforeach; ?>

                <div class="wpk-settings-card">
                    <div class="wpk-settings-card__header">
                        <h2><?php esc_html_e( 'Notes', 'wp-passkeys' ); ?></h2>
                    </div>
                    <div style="padding:12px 24px 20px;">
                        <ul style="list-style:disc;padding-left:18px;margin:0;line-height:1.9;">
                            <li><?php esc_html_e( 'Both shortcodes output nothing when passkeys are disabled or the WebAuthn library is missing.', 'wp-passkeys' ); ?></li>
                            <li><?php esc_html_e( '[wpk_login_button] is hidden for already-logged-in users.', 'wp-passkeys' ); ?></li>
                            <li><?php esc_html_e( '[wpk_register_button] is hidden for logged-out visitors and for roles not in the Eligible Roles setting.', 'wp-passkeys' ); ?></li>
                            <li><?php esc_html_e( 'Scripts and styles are only enqueued when the shortcode is actually rendered on the page.', 'wp-passkeys' ); ?></li>
                            <li>
                                <?php
                                printf(
                                    wp_kses(
                                        /* translators: %s settings URL */
                                        __( 'The global login redirect can be configured on the <a href="%s">Advanced tab</a>.', 'wp-passkeys' ),
                                        array( 'a' => array( 'href' => array() ) )
                                    ),
                                    esc_url( admin_url( 'options-general.php?page=wp-passkeys&tab=advanced' ) )
                                );
                                ?>
                            </li>
                        </ul>
                    </div>
                </div>

            </div>
            <aside class="wpk-settings-sidebar">
                <?php $this->render_pro_card(); ?>
            </aside>
        </div>
        <?php
    }

    // ──────────────────────────────────────────────────────────
    // Sidebar cards (REDESIGNED markup)
    // ──────────────────────────────────────────────────────────

    private function render_pro_card(): void {
        $features = array(
            __( 'Unlimited passkeys per user', 'wp-passkeys' ),
            __( 'Passkey-only mode by role', 'wp-passkeys' ),
            __( 'Magic link recovery flow', 'wp-passkeys' ),
            __( 'WooCommerce checkout integration', 'wp-passkeys' ),
            __( 'Gutenberg & Elementor blocks', 'wp-passkeys' ),
            __( 'Device health dashboard', 'wp-passkeys' ),
            __( 'Audit log with export', 'wp-passkeys' ),
            __( 'Conditional access rules', 'wp-passkeys' ),
            __( 'WP-CLI support', 'wp-passkeys' ),
            __( 'White-label & agency tools', 'wp-passkeys' ),
        );
        // Circle-check SVG (Lucide style)
        $check_svg = '<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/><polyline points="22 4 12 14.01 9 11.01"/></svg>';
        ?>
        <div class="wpk-card wpk-card-pro">

            <div class="wpk-pro-header">
                <div class="wpk-pro-icon" aria-hidden="true">
                    <svg xmlns="http://www.w3.org/2000/svg" width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="#fff" stroke-width="1.75" stroke-linecap="round" stroke-linejoin="round"><path d="M12 3l1.88 5.76a1 1 0 0 0 .95.69h6.06l-4.9 3.56a1 1 0 0 0-.36 1.12L17.5 20l-4.9-3.56a1 1 0 0 0-1.18 0L6.5 20l1.87-5.87a1 1 0 0 0-.36-1.12L3.11 9.45h6.06a1 1 0 0 0 .95-.69L12 3z"/></svg>
                </div>
                <div>
                    <span class="wpk-pro-title"><?php esc_html_e( 'WP Passkey Pro', 'wp-passkeys' ); ?></span>
                    <span class="wpk-pro-subtitle"><?php esc_html_e( 'Full experience manager', 'wp-passkeys' ); ?></span>
                </div>
            </div>

            <p class="wpk-pro-desc">
                <?php esc_html_e( 'Upgrade to unlock everything you need to deploy passkeys at scale.', 'wp-passkeys' ); ?>
            </p>

            <ul class="wpk-pro-features">
                <?php foreach ( $features as $f ) : ?>
                    <li>
                        <span class="wpk-pro-check"><?php echo $check_svg; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped ?></span>
                        <?php echo esc_html( $f ); ?>
                    </li>
                <?php endforeach; ?>
            </ul>

            <a href="https://wppasskey.com/pro" class="button wpk-btn-pro" target="_blank" rel="noopener noreferrer">
                <?php esc_html_e( 'Get Pro — from $79/year', 'wp-passkeys' ); ?>
                <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true" style="margin-left:6px;"><line x1="5" y1="12" x2="19" y2="12"/><polyline points="12 5 19 12 12 19"/></svg>
            </a>

            <p class="wpk-pro-guarantee">
                <a href="https://wppasskey.com/pro#guarantee" target="_blank" rel="noopener noreferrer">
                    <?php esc_html_e( '30-day money-back guarantee', 'wp-passkeys' ); ?>
                </a>
            </p>

        </div>
        <?php
    }

    private function render_quick_setup_card(): void {
        ?>
        <div class="wpk-card">
            <h3><?php esc_html_e( 'Quick setup', 'wp-passkeys' ); ?></h3>
            <ol class="wpk-setup-steps">
                <li><?php esc_html_e( 'Enable passkeys above and save.', 'wp-passkeys' ); ?></li>
                <li>
                    <?php
                    printf(
                        /* translators: %s is a link to the user profile */
                        wp_kses(
                            __( 'Go to <a href="%s">Your Profile</a> and register your first passkey.', 'wp-passkeys' ),
                            array( 'a' => array( 'href' => array() ) )
                        ),
                        esc_url( admin_url( 'profile.php#wpk-profile-section' ) )
                    );
                    ?>
                </li>
                <li><?php esc_html_e( 'Sign out and use the "Sign in with Passkey" button on the login page.', 'wp-passkeys' ); ?></li>
                <li><?php esc_html_e( 'Register a backup passkey on a second device.', 'wp-passkeys' ); ?></li>
            </ol>
        </div>
        <?php
    }

    private function render_compatibility_card(): void {
        // Inline SVG brand icons — no external requests, no emoji font dependency.
        $apple_icon = '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.75" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M7 3H5a2 2 0 0 0-2 2v2"/><path d="M17 3h2a2 2 0 0 1 2 2v2"/><path d="M7 21H5a2 2 0 0 1-2-2v-2"/><path d="M17 21h2a2 2 0 0 0 2-2v-2"/><path d="M9 9h.01"/><path d="M15 9h.01"/><path d="M9.5 14.5a3.5 3.5 0 0 0 5 0"/><line x1="12" y1="7" x2="12" y2="9"/></svg>';

        $windows_icon = '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 88 88" fill="currentColor" aria-hidden="true"><path d="M0 12.4L35.7 7.6l.002 34.43-35.66.204L0 12.4zm35.67 33.62l.003 34.44L.002 75.6l-.001-29.82 35.67.242zM40.29 6.882L87.986 0v41.677l-47.695.378.001-35.173zm47.699 36.739l-.011 41.644-47.695-6.672-.066-35.052 47.772.08z"/></svg>';

        $yubikey_icon = '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 100 100" fill="none" stroke="currentColor" stroke-width="6" aria-hidden="true"><rect x="30" y="8" width="40" height="60" rx="8"/><circle cx="50" cy="35" r="10"/><rect x="44" y="68" width="12" height="24" rx="4"/></svg>';

        $icloud_icon = '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="currentColor" aria-hidden="true"><path d="M19.35 10.04A7.49 7.49 0 0 0 12 4C9.11 4 6.6 5.64 5.35 8.04A5.994 5.994 0 0 0 0 14c0 3.31 2.69 6 6 6h13c2.76 0 5-2.24 5-5 0-2.64-2.05-4.78-4.65-4.96z"/></svg>';

        $android_icon = '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="currentColor" aria-hidden="true"><path d="M6 18c0 .55.45 1 1 1h1v3.5c0 .83.67 1.5 1.5 1.5s1.5-.67 1.5-1.5V19h2v3.5c0 .83.67 1.5 1.5 1.5s1.5-.67 1.5-1.5V19h1c.55 0 1-.45 1-1V8H6v10zm-2.5-1C2.67 17 2 17.67 2 18.5v-9C2 8.67 2.67 8 3.5 8S5 8.67 5 9.5v9c0 .83-.67 1.5-1.5 1.5zm17 0c-.83 0-1.5-.67-1.5-1.5v-9C19 8.67 19.67 8 20.5 8S22 8.67 22 9.5v9c0 .83-.67 1.5-1.5 1.5zM15.53 2.16l1.3-1.3c.2-.2.2-.51 0-.71-.2-.2-.51-.2-.71 0l-1.48 1.48A5.952 5.952 0 0 0 12 1c-.96 0-1.86.23-2.66.63L7.88.15c-.2-.2-.51-.2-.71 0-.2.2-.2.51 0 .71l1.31 1.31A5.965 5.965 0 0 0 6 7h12a5.96 5.96 0 0 0-2.47-4.84zM10 5H9V4h1v1zm5 0h-1V4h1v1z"/></svg>';

        $items = array(
            array( $apple_icon,   __( 'Face ID / Touch ID', 'wp-passkeys' ),      __( 'iPhone, iPad, Mac', 'wp-passkeys' ) ),
            array( $windows_icon, __( 'Windows Hello', 'wp-passkeys' ),            __( 'Windows 10 / 11', 'wp-passkeys' ) ),
            array( $yubikey_icon, __( 'Hardware security keys', 'wp-passkeys' ),   __( 'YubiKey, Titan &amp; others', 'wp-passkeys' ) ),
            array( $icloud_icon,  __( 'Cloud password managers', 'wp-passkeys' ),  __( 'iCloud Keychain, Google', 'wp-passkeys' ) ),
            array( $android_icon, __( 'Android biometrics', 'wp-passkeys' ),       __( 'Fingerprint, Face unlock', 'wp-passkeys' ) ),
        );

        $svg_allowed = array(
            'svg'     => array( 'xmlns' => true, 'viewbox' => true, 'fill' => true, 'stroke' => true, 'stroke-width' => true, 'stroke-linecap' => true, 'stroke-linejoin' => true, 'aria-hidden' => true ),
            'path'    => array( 'd' => true, 'fill' => true, 'stroke' => true ),
            'rect'    => array( 'x' => true, 'y' => true, 'width' => true, 'height' => true, 'rx' => true, 'fill' => true ),
            'circle'  => array( 'cx' => true, 'cy' => true, 'r' => true, 'fill' => true ),
            'line'    => array( 'x1' => true, 'y1' => true, 'x2' => true, 'y2' => true, 'stroke' => true ),
        );
        ?>
        <div class="wpk-card">
            <h3><?php esc_html_e( 'Compatibility', 'wp-passkeys' ); ?></h3>
            <ul class="wpk-compat">
                <?php foreach ( $items as $item ) : ?>
                    <li>
                        <span class="wpk-compat__icon" aria-hidden="true"><?php echo wp_kses( $item[0], $svg_allowed ); ?></span>
                        <span>
                            <span class="wpk-compat__label"><?php echo esc_html( $item[1] ); ?></span>
                            <span class="wpk-compat__note"><?php echo wp_kses( $item[2], array() ); ?></span>
                        </span>
                    </li>
                <?php endforeach; ?>
            </ul>
        </div>
        <?php
    }

    // ──────────────────────────────────────────────────────────
    // Field renderers  (UNCHANGED logic, classes used by new CSS)
    // ──────────────────────────────────────────────────────────

    public function field_checkbox( array $args ): void {
        $value = (int) get_option( $args['option'], 1 );
        $label = isset( $args['description'] ) ? esc_html( $args['description'] ) : '';
        printf(
            '<label class="wpk-toggle">' .
            '<input type="checkbox" name="%s" value="1"%s>' .
            '<span class="wpk-toggle__track"><span class="wpk-toggle__thumb"></span></span>' .
            '<span class="wpk-toggle__label">%s</span>' .
            '</label>',
            esc_attr( $args['option'] ),
            checked( 1, $value, false ),
            $label
        );
    }

    public function field_roles( array $args ): void {
        $saved = (array) get_option( $args['option'], array( 'administrator' ) );
        $roles = wp_roles()->get_names();
        echo '<fieldset>';
        foreach ( $roles as $role_key => $role_name ) {
            $checked = in_array( $role_key, $saved, true ) ? ' checked' : '';
            printf(
                '<label><input type="checkbox" name="%s[]" value="%s"%s> %s</label>',
                esc_attr( $args['option'] ),
                esc_attr( $role_key ),
                $checked,
                esc_html( translate_user_role( $role_name ) )
            );
        }
        echo '</fieldset>';
        if ( ! empty( $args['description'] ) ) {
            echo '<p class="description">' . esc_html( $args['description'] ) . '</p>';
        }
    }

    public function field_max_passkeys( array $args ): void {
        $value = (int) get_option( $args['option'], WPK_Passkeys::LITE_MAX_PASSKEYS );
        $value = max( 1, min( WPK_Passkeys::LITE_MAX_PASSKEYS, $value ) );
        printf(
            '<input type="number" name="%s" id="%s" value="%d" min="1" max="%d" class="small-text"> <span class="description" style="margin-left:8px;">%s</span>',
            esc_attr( $args['option'] ),
            esc_attr( $args['option'] ),
            $value,
            WPK_Passkeys::LITE_MAX_PASSKEYS,
            sprintf(
                /* translators: %d lite max */
                esc_html__( 'of %d (Lite limit)', 'wp-passkeys' ),
                WPK_Passkeys::LITE_MAX_PASSKEYS
            )
        );
        echo '<p class="description">' .
            sprintf(
                esc_html__( 'Maximum number of passkeys a single user may register (Lite: 1–%d). Pro removes this cap.', 'wp-passkeys' ),
                WPK_Passkeys::LITE_MAX_PASSKEYS
            ) .
            '</p>';
    }

    public function field_user_verification( array $args ): void {
        $value   = (string) get_option( $args['option'], 'required' );
        $options = array(
            'required'    => __( 'Required — biometric/PIN always requested (recommended)', 'wp-passkeys' ),
            'preferred'   => __( 'Preferred — biometric requested where available', 'wp-passkeys' ),
            'discouraged' => __( 'Discouraged — presence-only (not recommended)', 'wp-passkeys' ),
        );
        echo '<select name="' . esc_attr( $args['option'] ) . '" id="' . esc_attr( $args['option'] ) . '" style="min-width:380px;">';
        foreach ( $options as $k => $label ) {
            printf(
                '<option value="%s"%s>%s</option>',
                esc_attr( $k ),
                selected( $value, $k, false ),
                esc_html( $label )
            );
        }
        echo '</select>';
    }

    public function field_number( array $args ): void {
        $default = $args['default'] ?? 0;
        $value   = (int) get_option( $args['option'], $default );
        printf(
            '<input type="number" name="%s" id="%s" value="%d" min="%d" max="%d" class="small-text">',
            esc_attr( $args['option'] ),
            esc_attr( $args['option'] ),
            $value,
            $args['min'] ?? 0,
            $args['max'] ?? 9999
        );
        if ( ! empty( $args['description'] ) ) {
            echo '<p class="description">' . esc_html( $args['description'] ) . '</p>';
        }
    }

    public function field_text( array $args ): void {
        $value = (string) get_option( $args['option'], '' );
        printf(
            '<input type="text" name="%s" id="%s" value="%s" placeholder="%s" class="regular-text">',
            esc_attr( $args['option'] ),
            esc_attr( $args['option'] ),
            esc_attr( $value ),
            esc_attr( $args['placeholder'] ?? '' )
        );
        if ( ! empty( $args['description'] ) ) {
            echo '<p class="description">' . esc_html( $args['description'] ) . '</p>';
        }
    }

    // ──────────────────────────────────────────────────────────
    // Sanitize callbacks  (UNCHANGED)
    // ──────────────────────────────────────────────────────────

    public function sanitize_roles( $value ): array {
        if ( ! is_array( $value ) ) {
            return array( 'administrator' );
        }
        $valid = array_keys( wp_roles()->get_names() );
        $clean = array_intersect( array_map( 'sanitize_key', $value ), $valid );
        return ! empty( $clean ) ? array_values( $clean ) : array( 'administrator' );
    }

    public function sanitize_max_passkeys( $value ): int {
        return max( 1, min( WPK_Passkeys::LITE_MAX_PASSKEYS, (int) $value ) );
    }

    public function sanitize_user_verification( $value ): string {
        return in_array( $value, array( 'required', 'preferred', 'discouraged' ), true ) ? $value : 'required';
    }

    public function sanitize_rate_window( $value ): int {
        return max( 60, min( 3600, (int) $value ) );
    }

    public function sanitize_rate_attempts( $value ): int {
        return max( 1, min( 50, (int) $value ) );
    }

    public function sanitize_rate_lockout( $value ): int {
        return max( 60, min( 86400, (int) $value ) );
    }

    public function sanitize_challenge_ttl( $value ): int {
        return max( 30, min( 600, (int) $value ) );
    }

    public function sanitize_redirect_url( $value ): string {
        $url = sanitize_text_field( (string) $value );
        if ( $url === '' ) {
            return '';
        }
        return (string) wp_validate_redirect( $url, '' );
    }

    public function sanitize_log_retention( $value ): int {
        return max( 7, min( 365, (int) $value ) );
    }
}
