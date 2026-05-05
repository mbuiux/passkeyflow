<?php
/**
 * PasskeyFlow for Secure Login premium admin settings screen.
 *
 * Drop this in place of your existing settings class file, or copy the markup
 * methods into your current class if your plugin already wires settings elsewhere.
 */

if (!defined('ABSPATH')) {
    exit;
}

class PKFLOW_Settings {
    private $option_group = 'pkflow_settings_group';
    private $page_slug = 'passkeyflow';
    private $notice_transient_prefix = 'pkflow_settings_notice_';

    private function get_notice_transient_key( $user_id ) {
        return $this->notice_transient_prefix . absint( $user_id );
    }

    public function __construct() {
        add_action('admin_menu',            array($this, 'add_admin_menu'));
        add_action('admin_init',            array($this, 'register_settings'));
        add_action('admin_init',            array($this, 'flag_settings_save'), 1);
        add_action('admin_action_update',   array($this, 'flag_settings_save'), 1);
        add_action('admin_enqueue_scripts', array($this, 'enqueue_assets'));
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
        if ( $option_page !== $this->option_group ) {
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
            'message' => __( 'Settings saved.', 'passkeyflow' ),
        );

        set_transient( $this->get_notice_transient_key( $user_id ), $notice, 180 );
    }

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

    public function add_admin_menu() {
        add_options_page(
            __('PasskeyFlow for Secure Login', 'passkeyflow'),
            __('PasskeyFlow for Secure Login', 'passkeyflow'),
            'manage_options',
            $this->page_slug,
            array($this, 'render_settings_page')
        );
    }

    public function enqueue_assets($hook) {
        if ($hook !== 'settings_page_' . $this->page_slug) {
            return;
        }

        $version = defined('PKFLOW_VERSION') ? PKFLOW_VERSION : '1.0.0';
        $css_url = '';

        /*
         * Support the common PasskeyFlow for Secure Login plugin structure first:
         * /admin/css/wpk-admin.css. The other paths are fallbacks for simple
         * copy/paste installs and older generated bundles.
         */
        if (file_exists(plugin_dir_path(dirname(__FILE__)) . 'admin/css/wpk-admin.css')) {
            $css_url = plugin_dir_url(dirname(__FILE__)) . 'admin/css/wpk-admin.css';
        } elseif (file_exists(dirname(__FILE__) . '/wpk-admin.css')) {
            $css_url = plugin_dir_url(__FILE__) . 'wpk-admin.css';
        } elseif (file_exists(plugin_dir_path(dirname(__FILE__)) . 'assets/css/wpk-admin.css')) {
            $css_url = plugin_dir_url(dirname(__FILE__)) . 'assets/css/wpk-admin.css';
        } elseif (file_exists(plugin_dir_path(dirname(__FILE__)) . 'wpk-admin.css')) {
            $css_url = plugin_dir_url(dirname(__FILE__)) . 'wpk-admin.css';
        }

        if ($css_url) {
            wp_enqueue_style('wpk-admin', $css_url, array(), $version);
        }
    }

    public function register_settings() {
        register_setting($this->option_group, 'pkflow_enabled', array(
            'type' => 'boolean',
            'sanitize_callback' => array($this, 'sanitize_checkbox'),
            'default' => true,
        ));

        register_setting($this->option_group, 'pkflow_show_separator', array(
            'type' => 'boolean',
            'sanitize_callback' => array($this, 'sanitize_checkbox'),
            'default' => true,
        ));

        register_setting($this->option_group, 'pkflow_show_setup_notice', array(
            'type' => 'boolean',
            'sanitize_callback' => array($this, 'sanitize_checkbox'),
            'default' => true,
        ));

        register_setting($this->option_group, 'pkflow_enable_woocommerce_support', array(
            'type' => 'boolean',
            'sanitize_callback' => array($this, 'sanitize_checkbox'),
            'default' => true,
        ));

        register_setting($this->option_group, 'pkflow_enable_edd_support', array(
            'type' => 'boolean',
            'sanitize_callback' => array($this, 'sanitize_checkbox'),
            'default' => true,
        ));

        register_setting($this->option_group, 'pkflow_enable_memberpress_support', array(
            'type' => 'boolean',
            'sanitize_callback' => array($this, 'sanitize_checkbox'),
            'default' => true,
        ));

        register_setting($this->option_group, 'pkflow_enable_ultimate_member_support', array(
            'type' => 'boolean',
            'sanitize_callback' => array($this, 'sanitize_checkbox'),
            'default' => true,
        ));

        register_setting($this->option_group, 'pkflow_enable_learndash_support', array(
            'type' => 'boolean',
            'sanitize_callback' => array($this, 'sanitize_checkbox'),
            'default' => true,
        ));

        register_setting($this->option_group, 'pkflow_enable_buddyboss_support', array(
            'type' => 'boolean',
            'sanitize_callback' => array($this, 'sanitize_checkbox'),
            'default' => true,
        ));

        register_setting($this->option_group, 'pkflow_enable_gravityforms_support', array(
            'type' => 'boolean',
            'sanitize_callback' => array($this, 'sanitize_checkbox'),
            'default' => true,
        ));

        register_setting($this->option_group, 'pkflow_enable_pmp_support', array(
            'type' => 'boolean',
            'sanitize_callback' => array($this, 'sanitize_checkbox'),
            'default' => true,
        ));

        register_setting($this->option_group, 'pkflow_eligible_roles', array(
            'type' => 'array',
            'sanitize_callback' => array($this, 'sanitize_roles'),
            'default' => array('administrator'),
        ));

        register_setting($this->option_group, 'pkflow_max_passkeys_per_user', array(
            'type' => 'integer',
            'sanitize_callback' => array($this, 'sanitize_max_passkeys'),
            'default' => 0,
        ));

        register_setting($this->option_group, 'pkflow_user_verification', array(
            'type' => 'string',
            'sanitize_callback' => array($this, 'sanitize_user_verification'),
            'default' => 'required',
        ));

        register_setting($this->option_group, 'pkflow_rp_name', array(
            'type' => 'string',
            'sanitize_callback' => 'sanitize_text_field',
            'default' => '',
        ));

        register_setting($this->option_group, 'pkflow_rp_id', array(
            'type' => 'string',
            'sanitize_callback' => array($this, 'sanitize_rp_id'),
            'default' => '',
        ));

        register_setting($this->option_group, 'pkflow_login_challenge_ttl', array(
            'type' => 'integer',
            'sanitize_callback' => array($this, 'sanitize_challenge_ttl'),
            'default' => 300,
        ));

        register_setting($this->option_group, 'pkflow_registration_challenge_ttl', array(
            'type' => 'integer',
            'sanitize_callback' => array($this, 'sanitize_challenge_ttl'),
            'default' => 300,
        ));

        register_setting($this->option_group, 'pkflow_rate_limit_window', array(
            'type' => 'integer',
            'sanitize_callback' => array($this, 'sanitize_rate_limit_window'),
            'default' => 300,
        ));

        register_setting($this->option_group, 'pkflow_rate_limit_max_failures', array(
            'type' => 'integer',
            'sanitize_callback' => array($this, 'sanitize_rate_limit_max_failures'),
            'default' => 8,
        ));

        register_setting($this->option_group, 'pkflow_rate_limit_lockout', array(
            'type' => 'integer',
            'sanitize_callback' => array($this, 'sanitize_rate_limit_lockout'),
            'default' => 900,
        ));
    }

    public function render_settings_page() {
        if (!current_user_can('manage_options')) {
            wp_die(esc_html__('You do not have permission to access this page.', 'passkeyflow'));
        }

        $active_tab = isset($_GET['tab']) ? sanitize_key(wp_unslash($_GET['tab'])) : 'settings'; // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- read-only tab routing.
        $allowed_tabs = array('settings', 'advanced', 'shortcodes');

        if (!in_array($active_tab, $allowed_tabs, true)) {
            $active_tab = 'settings';
        }

        $base_url = admin_url('options-general.php?page=' . $this->page_slug);

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

        if ( empty( $queued_notices ) && isset( $_GET['settings-updated'] ) ) { // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- read-only notice rendering.
            $updated = sanitize_key( wp_unslash( $_GET['settings-updated'] ) ); // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- read-only notice rendering.
            if ( in_array( $updated, array( '1', 'true' ), true ) ) {
                $queued_notices[] = array(
                    'type'    => 'success',
                    'message' => __( 'Settings saved.', 'passkeyflow' ),
                );
                $notice_source = 'query_arg';
            }
        }

        $show_debug = current_user_can( 'manage_options' )
            && isset( $_GET['pkflow_notice_debug'] ) // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- read-only admin debug toggle.
            && '1' === sanitize_key( wp_unslash( $_GET['pkflow_notice_debug'] ) ); // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- read-only admin debug toggle.

        $debug_payload = array();
        if ( $show_debug ) {
            $debug_payload = array(
                'method'                  => isset( $_SERVER['REQUEST_METHOD'] ) ? sanitize_text_field( wp_unslash( $_SERVER['REQUEST_METHOD'] ) ) : '', // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- read-only diagnostics payload.
                'page'                    => isset( $_GET['page'] ) ? sanitize_key( wp_unslash( $_GET['page'] ) ) : '', // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- read-only diagnostics payload.
                'tab'                     => $active_tab,
                'settings_updated_get'    => isset( $_GET['settings-updated'] ) ? sanitize_text_field( wp_unslash( $_GET['settings-updated'] ) ) : '(absent)', // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- read-only diagnostics payload.
                'post_option_page'        => isset( $_POST['option_page'] ) ? sanitize_text_field( wp_unslash( $_POST['option_page'] ) ) : '(absent)', // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- read-only diagnostics payload.
                'post_action'             => isset( $_POST['action'] ) ? sanitize_text_field( wp_unslash( $_POST['action'] ) ) : '(absent)', // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- read-only diagnostics payload.
                'core_errors_count'       => count( $core_settings_errors ),
                'transient_present'       => $transient_present ? 'yes' : 'no',
                'queued_notices_count'    => count( $queued_notices ),
                'notice_source'           => $notice_source,
                'user_id'                 => $user_id,
            );
        }
        ?>
        <div class="wrap wpk-admin-wrap">
            <?php if ( $show_debug ) : ?>
            <div class="wpk-debug-banner" role="status" aria-live="polite">
                <strong><?php esc_html_e( 'WPK Notice Debug', 'passkeyflow' ); ?></strong>
                <pre><?php echo esc_html( wp_json_encode( $debug_payload, JSON_PRETTY_PRINT ) ); ?></pre>
            </div>
            <?php endif; ?>

            <?php if ( ! empty( $queued_notices ) ) : ?>
            <div class="wpk-notices-wrap">
                <?php foreach ( $queued_notices as $notice ) : ?>
                <div class="wpk-flash wpk-flash--<?php echo esc_attr( $notice['type'] ); ?>" role="alert">
                    <p><?php echo wp_kses_post( $notice['message'] ); ?></p>
                </div>
                <?php endforeach; ?>
            </div>
            <?php endif; ?>

            <div class="wpk-premium-shell">
                <header class="wpk-hero">
                    <div class="wpk-hero__content">
                        <div class="wpk-product-mark">
                            <span class="wpk-product-icon" aria-hidden="true"><svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><path d="M12 10a2 2 0 0 0-2 2c0 1.02-.1 2.51-.26 4"></path><path d="M14 13.12c0 2.38 0 6.38-1 8.88"></path><path d="M17.29 21.02c.12-.6.43-2.3.5-3.02"></path><path d="M2 12a10 10 0 0 1 18-6"></path><path d="M2 16h.01"></path><path d="M21.8 16c.2-2 .131-5.354 0-6"></path><path d="M5 19.5C5.5 18 6 15 6 12a6 6 0 0 1 .34-2"></path><path d="M8.65 22c.21-.66.45-1.32.57-2"></path><path d="M9 6.8a6 6 0 0 1 9 5.2v2"></path></svg></span>
                            <div>
                                <p class="wpk-eyebrow"><?php esc_html_e('Welcome to', 'passkeyflow'); ?></p>
                                <h1><?php esc_html_e('PasskeyFlow for Secure Login', 'passkeyflow'); ?></h1>
                            </div>
                        </div>
                        <p class="wpk-hero__copy">
                            <?php esc_html_e('A premium passwordless authentication control center built for WordPress.', 'passkeyflow'); ?>
                        </p>
                    </div>
                    <div class="wpk-hero__actions">
                        <span class="wpk-status-pill wpk-status-pill--success">
                            <span class="wpk-status-dot" aria-hidden="true"></span>
                            <?php esc_html_e('Ready', 'passkeyflow'); ?>
                        </span>

                    </div>
                </header>

                <nav class="wpk-tabs" aria-label="<?php esc_attr_e('PasskeyFlow for Secure Login settings tabs', 'passkeyflow'); ?>">
                    <?php $this->render_tab_link($base_url, 'settings', __('Settings', 'passkeyflow'), $active_tab); ?>
                    <?php $this->render_tab_link($base_url, 'advanced', __('Advanced', 'passkeyflow'), $active_tab); ?>
                    <?php $this->render_tab_link($base_url, 'shortcodes', __('Shortcodes', 'passkeyflow'), $active_tab); ?>
                </nav>

                <div class="wpk-layout">
                    <main class="wpk-main-panel">
                        <?php if ($active_tab === 'shortcodes') : ?>
                            <?php $this->render_shortcodes_tab(); ?>
                        <?php else : ?>
                            <form method="post" action="options.php" class="wpk-settings-form">
                                <?php settings_fields($this->option_group); ?>
                                <?php $this->render_preserved_hidden_fields($active_tab); ?>
                                <?php $active_tab === 'advanced' ? $this->render_advanced_tab() : $this->render_settings_tab(); ?>
                                <footer class="wpk-form-footer">
                                    <p><?php esc_html_e('Changes apply immediately after saving.', 'passkeyflow'); ?></p>
                                    <?php submit_button(__('Save Settings', 'passkeyflow'), 'primary wpk-save-button', 'submit', false); ?>
                                </footer>
                            </form>
                        <?php endif; ?>
                    </main>

                    <aside class="wpk-sidebar" aria-label="<?php esc_attr_e('PasskeyFlow for Secure Login quick actions', 'passkeyflow'); ?>">
                        <?php $this->render_sidebar_cards(); ?>
                    </aside>
                </div>

                <?php $this->render_shell_footer(); ?>
            </div>
        </div>
        <?php
    }

    private function render_tab_link($base_url, $tab, $label, $active_tab) {
        $classes = 'wpk-tab';
        if ($active_tab === $tab) {
            $classes .= ' is-active';
        }

        printf(
            '<a class="%1$s" href="%2$s">%3$s</a>',
            esc_attr($classes),
            esc_url(add_query_arg('tab', $tab, $base_url)),
            esc_html($label)
        );
    }

    private function render_preserved_hidden_fields($active_tab) {
        if ($active_tab === 'advanced') {
            $enabled = (bool) get_option('pkflow_enabled', true);
            $show_setup_notice = (bool) get_option('pkflow_show_setup_notice', true);
            $integration_settings = class_exists( 'PKFLOW_Integration_Manager' ) && method_exists( 'PKFLOW_Integration_Manager', 'get_settings_registry' )
                ? PKFLOW_Integration_Manager::get_settings_registry()
                : array();
            $roles = (array) get_option('pkflow_eligible_roles', array('administrator'));
            $max_passkeys = absint(get_option('pkflow_max_passkeys_per_user', 0));
            $verification = get_option('pkflow_user_verification', 'required');

            echo '<input type="hidden" name="pkflow_enabled" value="' . esc_attr($enabled ? '1' : '0') . '" />';
            echo '<input type="hidden" name="pkflow_show_setup_notice" value="' . esc_attr($show_setup_notice ? '1' : '0') . '" />';

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

            foreach ($roles as $role) {
                echo '<input type="hidden" name="pkflow_eligible_roles[]" value="' . esc_attr(sanitize_key($role)) . '" />';
            }
            echo '<input type="hidden" name="pkflow_max_passkeys_per_user" value="' . esc_attr((string) $max_passkeys) . '" />';
            echo '<input type="hidden" name="pkflow_user_verification" value="' . esc_attr((string) $verification) . '" />';
            return;
        }

        if ($active_tab === 'settings') {
            $show_separator = (bool) get_option('pkflow_show_separator', true);
            $rp_name = get_option('pkflow_rp_name', '');
            $rp_id = get_option('pkflow_rp_id', '');
            $login_challenge_ttl = absint(get_option('pkflow_login_challenge_ttl', 300));
            $registration_challenge_ttl = absint(get_option('pkflow_registration_challenge_ttl', 300));
            $window = absint(get_option('pkflow_rate_limit_window', 300));
            $max_failures = absint(get_option('pkflow_rate_limit_max_failures', 8));
            $lockout = absint(get_option('pkflow_rate_limit_lockout', 900));

            echo '<input type="hidden" name="pkflow_show_separator" value="' . esc_attr($show_separator ? '1' : '0') . '" />';
            echo '<input type="hidden" name="pkflow_rp_name" value="' . esc_attr((string) $rp_name) . '" />';
            echo '<input type="hidden" name="pkflow_rp_id" value="' . esc_attr((string) $rp_id) . '" />';
            echo '<input type="hidden" name="pkflow_login_challenge_ttl" value="' . esc_attr((string) $login_challenge_ttl) . '" />';
            echo '<input type="hidden" name="pkflow_registration_challenge_ttl" value="' . esc_attr((string) $registration_challenge_ttl) . '" />';
            echo '<input type="hidden" name="pkflow_rate_limit_window" value="' . esc_attr((string) $window) . '" />';
            echo '<input type="hidden" name="pkflow_rate_limit_max_failures" value="' . esc_attr((string) $max_failures) . '" />';
            echo '<input type="hidden" name="pkflow_rate_limit_lockout" value="' . esc_attr((string) $lockout) . '" />';
        }
    }

    private function render_settings_tab() {
        $enabled = (bool) get_option('pkflow_enabled', true);
        $show_setup_notice = (bool) get_option('pkflow_show_setup_notice', true);
        $eligible_roles = (array) get_option('pkflow_eligible_roles', array('administrator'));
        $max_passkeys = absint(get_option('pkflow_max_passkeys_per_user', 0));
        $verification = get_option('pkflow_user_verification', 'required');
        $roles = wp_roles()->roles;
        ?>
        <section class="wpk-section-header">
            <div>
                <p class="wpk-eyebrow"><?php esc_html_e('Settings', 'passkeyflow'); ?></p>
                <h2><?php esc_html_e('Everyday passkey controls', 'passkeyflow'); ?></h2>
            </div>
            <span class="wpk-badge"><?php esc_html_e('Recommended defaults', 'passkeyflow'); ?></span>
        </section>

        <div class="wpk-card wpk-card--setting">
            <div class="wpk-setting-copy">
                <h3><?php esc_html_e('Enable passkeys', 'passkeyflow'); ?></h3>
                <p><?php esc_html_e('Allow eligible users to register and sign in with secure device passkeys.', 'passkeyflow'); ?></p>
            </div>
            <label class="wpk-switch">
                <input type="checkbox" name="pkflow_enabled" value="1" <?php checked($enabled); ?> />
                <span class="wpk-switch__track"><span class="wpk-switch__thumb"></span></span>
                <span class="screen-reader-text"><?php esc_html_e('Enable passkeys', 'passkeyflow'); ?></span>
            </label>
        </div>

        <div class="wpk-card wpk-card--setting">
            <div class="wpk-setting-copy">
                <h3><?php esc_html_e('Show setup alert on profile', 'passkeyflow'); ?></h3>
                <p><?php esc_html_e('Show or hide the admin alert that reminds users to set up a passkey on their profile page.', 'passkeyflow'); ?></p>
            </div>
            <label class="wpk-switch">
                <input type="checkbox" name="pkflow_show_setup_notice" value="1" <?php checked($show_setup_notice); ?> />
                <span class="wpk-switch__track"><span class="wpk-switch__thumb"></span></span>
                <span class="screen-reader-text"><?php esc_html_e('Show setup alert on profile', 'passkeyflow'); ?></span>
            </label>
        </div>

        <?php
        if ( class_exists( 'PKFLOW_Integration_Manager' ) && method_exists( 'PKFLOW_Integration_Manager', 'get_settings_registry' ) ) {
            $integration_settings = PKFLOW_Integration_Manager::get_settings_registry();
            if ( ! empty( $integration_settings ) ) {
                ?>
                <div class="wpk-card">
                    <div class="wpk-card__header">
                        <div>
                            <h3><?php esc_html_e('Integration modules', 'passkeyflow'); ?></h3>
                            <p><?php esc_html_e('Control each integration independently with master and auto-inject switches.', 'passkeyflow'); ?></p>
                        </div>
                    </div>
                    <div class="wpk-integration-settings-grid">
                        <?php foreach ( $integration_settings as $integration_setting ) :
                            $label             = ! empty( $integration_setting['label'] ) ? (string) $integration_setting['label'] : __( 'Integration', 'passkeyflow' );
                            $master_option     = ! empty( $integration_setting['master_option'] ) ? sanitize_key( (string) $integration_setting['master_option'] ) : '';
                            $dependency_active = ! empty( $integration_setting['dependency_active'] );
                            $default_master    = ! empty( $integration_setting['default_master'] );
                            $saved_master_enabled = $master_option ? (bool) get_option( $master_option, $default_master ) : false;
                            $master_enabled       = $dependency_active ? $saved_master_enabled : false;
                            ?>
                            <article class="wpk-integration-setting-card<?php echo $dependency_active ? ' is-active' : ' is-missing'; ?>">
                                <header>
                                    <h4><?php echo esc_html( $label ); ?></h4>
                                    <span class="wpk-integration-status <?php echo $dependency_active ? 'is-active' : 'is-missing'; ?>">
                                        <?php echo $dependency_active ? esc_html__( 'Installed', 'passkeyflow' ) : esc_html__( 'Not installed', 'passkeyflow' ); ?>
                                    </span>
                                </header>
                                <p><?php esc_html_e('Enable this to add passkey blocks, shortcodes, and auto sign-in prompts.', 'passkeyflow'); ?></p>
                                <?php if ( ! $dependency_active && $master_option ) : ?>
                                    <input type="hidden" name="<?php echo esc_attr( $master_option ); ?>" value="0" />
                                <?php endif; ?>
                                <div class="wpk-integration-toggle-row">
                                    <label><?php esc_html_e('Enable module', 'passkeyflow'); ?></label>
                                    <label class="wpk-switch">
                                        <input type="checkbox" name="<?php echo esc_attr( $master_option ); ?>" value="1" <?php checked( $master_enabled ); ?> <?php disabled( ! $dependency_active ); ?> />
                                        <span class="wpk-switch__track"><span class="wpk-switch__thumb"></span></span>
                                        <span class="screen-reader-text"><?php esc_html_e('Enable integration module', 'passkeyflow'); ?></span>
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

        <div class="wpk-card">
            <div class="wpk-card__header">
                <div>
                    <h3><?php esc_html_e('Eligible user roles', 'passkeyflow'); ?></h3>
                    <p><?php esc_html_e('Choose which WordPress roles can create and use passkeys.', 'passkeyflow'); ?></p>
                </div>
            </div>
            <div class="wpk-role-grid">
                <?php foreach ($roles as $role_key => $role) : ?>
                    <label class="wpk-role-chip">
                        <input type="checkbox" name="pkflow_eligible_roles[]" value="<?php echo esc_attr($role_key); ?>" <?php checked(in_array($role_key, $eligible_roles, true)); ?> />
                        <span><?php echo esc_html(translate_user_role($role['name'])); ?></span>
                    </label>
                <?php endforeach; ?>
            </div>
        </div>

        <div class="wpk-card wpk-grid-2">
            <div class="wpk-field">
                <div class="wpk-label-row">
                    <label for="pkflow_max_passkeys_per_user"><?php esc_html_e('Passkeys per user', 'passkeyflow'); ?></label>
                </div>
                <input id="pkflow_max_passkeys_per_user" class="regular-text" type="number" min="0" max="999999" name="pkflow_max_passkeys_per_user" value="<?php echo esc_attr($max_passkeys); ?>" />
                <p><?php esc_html_e('Maximum number of passkeys each user can register. Use 0 for no limit.', 'passkeyflow'); ?></p>
            </div>

            <div class="wpk-field">
                <div class="wpk-label-row">
                    <label for="pkflow_user_verification"><?php esc_html_e('User verification', 'passkeyflow'); ?></label>
                    <span class="wpk-badge wpk-badge--success"><?php esc_html_e('Recommended', 'passkeyflow'); ?></span>
                </div>
                <select id="pkflow_user_verification" name="pkflow_user_verification">
                    <option value="required" <?php selected($verification, 'required'); ?>><?php esc_html_e('Required — biometric or device PIN', 'passkeyflow'); ?></option>
                    <option value="preferred" <?php selected($verification, 'preferred'); ?>><?php esc_html_e('Preferred — use when available', 'passkeyflow'); ?></option>
                    <option value="discouraged" <?php selected($verification, 'discouraged'); ?>><?php esc_html_e('Discouraged — presence only', 'passkeyflow'); ?></option>
                </select>
                <p><?php esc_html_e('Required verification gives the strongest account protection.', 'passkeyflow'); ?></p>
            </div>
        </div>
        <?php
    }

    private function render_advanced_tab() {
        $show_separator = (bool) get_option('pkflow_show_separator', true);
        $rp_name = get_option('pkflow_rp_name', '');
        $rp_id = get_option('pkflow_rp_id', '');
        $login_challenge_ttl = absint(get_option('pkflow_login_challenge_ttl', 300));
        $registration_challenge_ttl = absint(get_option('pkflow_registration_challenge_ttl', 300));
        $window = absint(get_option('pkflow_rate_limit_window', 300));
        $max_failures = absint(get_option('pkflow_rate_limit_max_failures', 8));
        $lockout = absint(get_option('pkflow_rate_limit_lockout', 900));
        ?>
        <section class="wpk-section-header">
            <div>
                <p class="wpk-eyebrow"><?php esc_html_e('Advanced', 'passkeyflow'); ?></p>
                <h2><?php esc_html_e('Technical configuration', 'passkeyflow'); ?></h2>
            </div>
        </section>

        <div class="wpk-card wpk-card--setting">
            <div class="wpk-setting-copy">
                <h3><?php esc_html_e('Show login OR separator', 'passkeyflow'); ?></h3>
                <p><?php esc_html_e('Display the centered OR divider above the passkey button on wp-login.php.', 'passkeyflow'); ?></p>
            </div>
            <label class="wpk-switch">
                <input type="checkbox" name="pkflow_show_separator" value="1" <?php checked($show_separator); ?> />
                <span class="wpk-switch__track"><span class="wpk-switch__thumb"></span></span>
                <span class="screen-reader-text"><?php esc_html_e('Show login OR separator', 'passkeyflow'); ?></span>
            </label>
        </div>

        <div class="wpk-card wpk-grid-2">
            <div class="wpk-field">
                <label for="pkflow_rp_name"><?php esc_html_e('Relying Party Name', 'passkeyflow'); ?></label>
                <input id="pkflow_rp_name" class="regular-text" type="text" name="pkflow_rp_name" value="<?php echo esc_attr($rp_name); ?>" placeholder="<?php echo esc_attr(get_bloginfo('name')); ?>" />
                <p><?php esc_html_e('The name users see in their passkey prompt. Leave blank to use the site name.', 'passkeyflow'); ?></p>
            </div>
            <div class="wpk-field">
                <label for="pkflow_rp_id"><?php esc_html_e('Relying Party ID', 'passkeyflow'); ?></label>
                <input id="pkflow_rp_id" class="regular-text" type="text" name="pkflow_rp_id" value="<?php echo esc_attr($rp_id); ?>" placeholder="<?php echo esc_attr(wp_parse_url(home_url(), PHP_URL_HOST)); ?>" />
                <p><?php esc_html_e('Usually your root domain. Leave blank unless you know you need to customize it.', 'passkeyflow'); ?></p>
            </div>
        </div>

        <div class="wpk-card">
            <div class="wpk-card__header">
                <div>
                    <h3><?php esc_html_e('Passkey challenge timeouts', 'passkeyflow'); ?></h3>
                    <p><?php esc_html_e('Control how long users have to complete passkey login or registration after a challenge is issued.', 'passkeyflow'); ?></p>
                </div>
                <span class="wpk-badge"><?php esc_html_e('Seconds', 'passkeyflow'); ?></span>
            </div>
            <div class="wpk-grid-2">
                <div class="wpk-field">
                    <label for="pkflow_login_challenge_ttl"><?php esc_html_e('Login challenge timeout', 'passkeyflow'); ?></label>
                    <input id="pkflow_login_challenge_ttl" type="number" min="30" max="1200" name="pkflow_login_challenge_ttl" value="<?php echo esc_attr($login_challenge_ttl); ?>" />
                    <p><?php esc_html_e('How long a user has to complete passkey sign-in.', 'passkeyflow'); ?></p>
                </div>
                <div class="wpk-field">
                    <label for="pkflow_registration_challenge_ttl"><?php esc_html_e('Registration challenge timeout', 'passkeyflow'); ?></label>
                    <input id="pkflow_registration_challenge_ttl" type="number" min="30" max="1200" name="pkflow_registration_challenge_ttl" value="<?php echo esc_attr($registration_challenge_ttl); ?>" />
                    <p><?php esc_html_e('How long a user has to finish passkey registration.', 'passkeyflow'); ?></p>
                </div>
            </div>
        </div>

        <div class="wpk-card">
            <div class="wpk-card__header">
                <div>
                    <h3><?php esc_html_e('Rate limiting', 'passkeyflow'); ?></h3>
                    <p><?php esc_html_e('Protect authentication endpoints from repeated failed attempts.', 'passkeyflow'); ?></p>
                </div>
                <span class="wpk-badge wpk-badge--success"><?php esc_html_e('Protected', 'passkeyflow'); ?></span>
            </div>
            <div class="wpk-grid-3">
                <div class="wpk-field">
                    <label for="pkflow_rate_limit_window"><?php esc_html_e('Failure window', 'passkeyflow'); ?></label>
                    <input id="pkflow_rate_limit_window" type="number" min="60" max="3600" name="pkflow_rate_limit_window" value="<?php echo esc_attr($window); ?>" />
                    <p><?php esc_html_e('Seconds.', 'passkeyflow'); ?></p>
                </div>
                <div class="wpk-field">
                    <label for="pkflow_rate_limit_max_failures"><?php esc_html_e('Max failures', 'passkeyflow'); ?></label>
                    <input id="pkflow_rate_limit_max_failures" type="number" min="1" max="50" name="pkflow_rate_limit_max_failures" value="<?php echo esc_attr($max_failures); ?>" />
                    <p><?php esc_html_e('Attempts before lockout.', 'passkeyflow'); ?></p>
                </div>
                <div class="wpk-field">
                    <label for="pkflow_rate_limit_lockout"><?php esc_html_e('Lockout duration', 'passkeyflow'); ?></label>
                    <input id="pkflow_rate_limit_lockout" type="number" min="60" max="86400" name="pkflow_rate_limit_lockout" value="<?php echo esc_attr($lockout); ?>" />
                    <p><?php esc_html_e('Seconds.', 'passkeyflow'); ?></p>
                </div>
            </div>
        </div>

        <?php
    }

    private function render_shortcodes_tab() {
        $shortcodes = array(
            array(
                'title' => __('Login Form', 'passkeyflow'),
                'code' => '[pkflow_login_button]',
                'description' => __('Display a passkey login form on any page.', 'passkeyflow'),
                'placement' => __('Best for custom login pages.', 'passkeyflow'),
            ),
            array(
                'title' => __('Register Button', 'passkeyflow'),
                'code' => '[pkflow_register_button]',
                'description' => __('Let signed-in users register a new passkey.', 'passkeyflow'),
                'placement' => __('Best for account and onboarding pages.', 'passkeyflow'),
            ),
            array(
                'title' => __('Account Passkeys', 'passkeyflow'),
                'code' => '[pkflow_passkey_profile]',
                'description' => __('Show a user-facing passkey management area.', 'passkeyflow'),
                'placement' => __('Best for profile or dashboard pages.', 'passkeyflow'),
            ),
            array(
                'title' => __('Conditional Prompt', 'passkeyflow'),
                'code' => '[pkflow_passkey_prompt]',
                'description' => __('Prompt eligible users to set up passwordless login.', 'passkeyflow'),
                'placement' => __('Best after login or checkout.', 'passkeyflow'),
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
                    'description' => __( 'Integration-specific passkey entry point.', 'passkeyflow' ),
                    'placement'   => __( 'Shown only when the related plugin is active.', 'passkeyflow' ),
                );
            }
        }
        ?>
        <section class="wpk-section-header">
            <div>
                <p class="wpk-eyebrow"><?php esc_html_e('Shortcodes', 'passkeyflow'); ?></p>
                <h2><?php esc_html_e('Drop-in passkey experiences', 'passkeyflow'); ?></h2>
                <p class="wpk-shortcode-tab-note"><?php esc_html_e('Prefer visual editing? Use matching Gutenberg blocks for login, registration, profile prompts, and active integrations or drop in shortcodes wherever you need them.', 'passkeyflow'); ?></p>
            </div>
        </section>

        <div class="wpk-shortcode-grid">
            <?php foreach ($shortcodes as $shortcode) : ?>
                <article class="wpk-shortcode-card">
                    <h3><?php echo esc_html($shortcode['title']); ?></h3>
                    <p><?php echo esc_html($shortcode['description']); ?></p>
                    <code><?php echo esc_html($shortcode['code']); ?></code>
                    <span><?php echo esc_html($shortcode['placement']); ?></span>
                </article>
            <?php endforeach; ?>
        </div>

        <article class="wpk-shortcode-helper-card" aria-label="<?php esc_attr_e( 'Shortcode quick start guide', 'passkeyflow' ); ?>">
            <header class="wpk-shortcode-helper-card__header">
                <h3><?php esc_html_e( 'Quick start: shortcode guide', 'passkeyflow' ); ?></h3>
                <p><?php esc_html_e( 'Paste a shortcode into any page, post, or block that supports shortcodes. Then add options to control labels, redirects, and behavior.', 'passkeyflow' ); ?></p>
            </header>

            <div class="wpk-shortcode-helper-grid">
                <section>
                    <h4><?php esc_html_e( 'How to add one', 'passkeyflow' ); ?></h4>
                    <ol>
                        <li><?php esc_html_e( 'Open the page where you want passkey UI to appear.', 'passkeyflow' ); ?></li>
                        <li><?php esc_html_e( 'Add a Shortcode block (or paste into classic content).', 'passkeyflow' ); ?></li>
                        <li><?php esc_html_e( 'Paste a shortcode from the cards above and update the page.', 'passkeyflow' ); ?></li>
                    </ol>
                </section>

                <section>
                    <h4><?php esc_html_e( 'Most useful options', 'passkeyflow' ); ?></h4>
                    <ul class="wpk-shortcode-helper-list">
                        <li><code>label</code> <?php esc_html_e( 'Change button text.', 'passkeyflow' ); ?></li>
                        <li><code>redirect_to</code> <?php esc_html_e( 'Send users to a specific URL after sign-in.', 'passkeyflow' ); ?></li>
                        <li><code>class</code> <?php esc_html_e( 'Add your own CSS class for styling.', 'passkeyflow' ); ?></li>
                        <li><code>allow_multiple</code> <?php esc_html_e( 'Allow more than one login button on a page (0 or 1).', 'passkeyflow' ); ?></li>
                        <li><code>button_label</code> <?php esc_html_e( 'Set prompt CTA text for passkey setup prompts.', 'passkeyflow' ); ?></li>
                    </ul>
                </section>
            </div>

            <div class="wpk-shortcode-examples">
                <h4><?php esc_html_e( 'Copy-and-paste examples', 'passkeyflow' ); ?></h4>
                <div class="wpk-shortcode-examples__grid">
                    <div>
                        <p><?php esc_html_e( 'Custom login button + redirect', 'passkeyflow' ); ?></p>
                        <code>[pkflow_login_button label="Sign in securely" redirect_to="/my-account/"]</code>
                    </div>
                    <div>
                        <p><?php esc_html_e( 'Multiple login buttons on one page', 'passkeyflow' ); ?></p>
                        <code>[pkflow_login_button allow_multiple="1" class="my-passkey-login"]</code>
                    </div>
                    <div>
                        <p><?php esc_html_e( 'Custom register button label', 'passkeyflow' ); ?></p>
                        <code>[pkflow_register_button label="Add this device"]</code>
                    </div>
                    <div>
                        <p><?php esc_html_e( 'Prompt users to set up passkeys', 'passkeyflow' ); ?></p>
                        <code>[pkflow_passkey_prompt title="Secure your account" button_label="Set up passkey"]</code>
                    </div>
                </div>
            </div>
        </article>
        <?php
    }

    private function render_sidebar_cards() {
        ?>
        <section class="wpk-side-card">
            <h2><?php esc_html_e('Quick setup', 'passkeyflow'); ?></h2>
            <ol class="wpk-checklist">
                <li><?php esc_html_e('Activate the plugin', 'passkeyflow'); ?></li>
                <li><?php esc_html_e('Enable passkeys in Settings', 'passkeyflow'); ?></li>
                <li><?php esc_html_e('Choose eligible roles', 'passkeyflow'); ?></li>
                <li><?php esc_html_e('Register your first passkey in Your Profile', 'passkeyflow'); ?></li>
                <li><?php esc_html_e('Sign out and test the login button', 'passkeyflow'); ?></li>
            </ol>
        </section>

        <?php
        if ( class_exists( 'PKFLOW_Integration_Manager' ) && method_exists( 'PKFLOW_Integration_Manager', 'get_available_integrations' ) ) {
            $available_integrations = PKFLOW_Integration_Manager::get_available_integrations();
            if ( ! empty( $available_integrations ) ) {
                ?>
                <section class="wpk-side-card">
                    <h2><?php esc_html_e('Active integrations', 'passkeyflow'); ?></h2>
                    <p><?php esc_html_e('Passkey modules, shortcodes, and Gutenberg blocks are available for these detected plugins.', 'passkeyflow'); ?></p>
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

    private function render_shell_footer() {
        ?>
        <footer class="wpk-shell-footer" aria-label="<?php esc_attr_e('Maintainer links', 'passkeyflow'); ?>">
            <span class="wpk-shell-footer__label"><?php esc_html_e('Maintained by mbuiux', 'passkeyflow'); ?></span>
            <a class="wpk-shell-footer__link" href="https://profiles.wordpress.org/mbuiux/" target="_blank" rel="noopener noreferrer">
                <span class="wpk-shell-footer__icon" aria-hidden="true">
                    <span class="dashicons dashicons-wordpress" aria-hidden="true"></span>
                </span>
                <span><?php esc_html_e('WordPress.org', 'passkeyflow'); ?></span>
            </a>
            <a class="wpk-shell-footer__link" href="https://github.com/mbuiux/passkeyflow.git" target="_blank" rel="noopener noreferrer">
                <span class="wpk-shell-footer__icon" aria-hidden="true">
                    <svg viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg" focusable="false">
                        <path d="M12 .5C5.65.5.5 5.67.5 12.06c0 5.12 3.3 9.46 7.87 10.99.58.11.79-.26.79-.57v-2.02c-3.2.7-3.88-1.56-3.88-1.56-.52-1.34-1.28-1.69-1.28-1.69-1.05-.72.08-.7.08-.7 1.16.08 1.77 1.2 1.77 1.2 1.03 1.78 2.7 1.27 3.36.97.1-.76.4-1.27.73-1.56-2.56-.29-5.25-1.29-5.25-5.73 0-1.26.45-2.29 1.19-3.1-.12-.29-.51-1.46.11-3.04 0 0 .97-.32 3.18 1.18a10.97 10.97 0 0 1 5.8 0c2.2-1.5 3.17-1.18 3.17-1.18.63 1.58.24 2.75.12 3.04.74.81 1.18 1.84 1.18 3.1 0 4.46-2.69 5.44-5.26 5.72.41.36.78 1.08.78 2.18v3.24c0 .32.21.69.8.57A11.6 11.6 0 0 0 23.5 12.06C23.5 5.67 18.35.5 12 .5Z"/>
                    </svg>
                </span>
                <span><?php esc_html_e('GitHub', 'passkeyflow'); ?></span>
            </a>
        </footer>
        <?php
    }

    public function sanitize_checkbox($value) {
        return !empty($value) ? 1 : 0;
    }

    public function sanitize_roles($roles) {
        if (!is_array($roles)) {
            return array();
        }

        $valid_roles = array_keys(wp_roles()->roles);
        return array_values(array_intersect(array_map('sanitize_key', $roles), $valid_roles));
    }

    public function sanitize_max_passkeys($value) {
        return min(999999, max(0, absint($value)));
    }

    public function sanitize_user_verification($value) {
        $allowed = array('required', 'preferred', 'discouraged');
        return in_array($value, $allowed, true) ? $value : 'required';
    }

    public function sanitize_rp_id($value) {
        $value = strtolower(sanitize_text_field($value));
        return preg_replace('/[^a-z0-9.-]/', '', $value);
    }

    public function sanitize_rate_limit_window($value) {
        return min(3600, max(60, absint($value)));
    }

    public function sanitize_rate_limit_max_failures($value) {
        return min(50, max(1, absint($value)));
    }

    public function sanitize_rate_limit_lockout($value) {
        return min(86400, max(60, absint($value)));
    }

    public function sanitize_challenge_ttl($value) {
        return min(1200, max(30, absint($value)));
    }
}
