<?php
/**
 * WP Passkeys premium admin settings screen.
 *
 * Drop this in place of your existing settings class file, or copy the markup
 * methods into your current class if your plugin already wires settings elsewhere.
 */

if (!defined('ABSPATH')) {
    exit;
}

class WPK_Settings {
    private $option_group = 'wpk_settings_group';
    private $page_slug = 'wp-passkeys';

    public function __construct() {
        add_action('admin_menu', array($this, 'add_admin_menu'));
        add_action('admin_init', array($this, 'register_settings'));
        add_action('admin_enqueue_scripts', array($this, 'enqueue_assets'));
    }

    public function add_admin_menu() {
        add_options_page(
            __('WP Passkeys', 'wp-passkeys'),
            __('WP Passkeys', 'wp-passkeys'),
            'manage_options',
            $this->page_slug,
            array($this, 'render_settings_page')
        );
    }

    public function enqueue_assets($hook) {
        if ($hook !== 'settings_page_' . $this->page_slug) {
            return;
        }

        $version = defined('WPK_VERSION') ? WPK_VERSION : '1.0.0';
        $css_url = '';

        /*
         * Support the common WP Passkeys plugin structure first:
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
        register_setting($this->option_group, 'wpk_enabled', array(
            'type' => 'boolean',
            'sanitize_callback' => array($this, 'sanitize_checkbox'),
            'default' => true,
        ));

        register_setting($this->option_group, 'wpk_eligible_roles', array(
            'type' => 'array',
            'sanitize_callback' => array($this, 'sanitize_roles'),
            'default' => array('administrator'),
        ));

        register_setting($this->option_group, 'wpk_max_passkeys_per_user', array(
            'type' => 'integer',
            'sanitize_callback' => array($this, 'sanitize_max_passkeys'),
            'default' => 5,
        ));

        register_setting($this->option_group, 'wpk_user_verification', array(
            'type' => 'string',
            'sanitize_callback' => array($this, 'sanitize_user_verification'),
            'default' => 'required',
        ));

        register_setting($this->option_group, 'wpk_rp_name', array(
            'type' => 'string',
            'sanitize_callback' => 'sanitize_text_field',
            'default' => '',
        ));

        register_setting($this->option_group, 'wpk_rp_id', array(
            'type' => 'string',
            'sanitize_callback' => array($this, 'sanitize_rp_id'),
            'default' => '',
        ));

        register_setting($this->option_group, 'wpk_rate_limit_window', array(
            'type' => 'integer',
            'sanitize_callback' => array($this, 'sanitize_rate_limit_window'),
            'default' => 300,
        ));

        register_setting($this->option_group, 'wpk_rate_limit_max_failures', array(
            'type' => 'integer',
            'sanitize_callback' => array($this, 'sanitize_rate_limit_max_failures'),
            'default' => 8,
        ));

        register_setting($this->option_group, 'wpk_rate_limit_lockout', array(
            'type' => 'integer',
            'sanitize_callback' => array($this, 'sanitize_rate_limit_lockout'),
            'default' => 900,
        ));
    }

    public function render_settings_page() {
        if (!current_user_can('manage_options')) {
            wp_die(esc_html__('You do not have permission to access this page.', 'wp-passkeys'));
        }

        $active_tab = isset($_GET['tab']) ? sanitize_key(wp_unslash($_GET['tab'])) : 'settings';
        $allowed_tabs = array('settings', 'advanced', 'shortcodes');

        if (!in_array($active_tab, $allowed_tabs, true)) {
            $active_tab = 'settings';
        }

        $base_url = admin_url('options-general.php?page=' . $this->page_slug);
        ?>
        <div class="wrap wpk-admin-wrap">
            <div class="wpk-premium-shell">
                <header class="wpk-hero">
                    <div class="wpk-hero__content">
                        <div class="wpk-product-mark">
                            <span class="wpk-product-icon" aria-hidden="true"><svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><path d="M12 10a2 2 0 0 0-2 2c0 1.02-.1 2.51-.26 4"></path><path d="M14 13.12c0 2.38 0 6.38-1 8.88"></path><path d="M17.29 21.02c.12-.6.43-2.3.5-3.02"></path><path d="M2 12a10 10 0 0 1 18-6"></path><path d="M2 16h.01"></path><path d="M21.8 16c.2-2 .131-5.354 0-6"></path><path d="M5 19.5C5.5 18 6 15 6 12a6 6 0 0 1 .34-2"></path><path d="M8.65 22c.21-.66.45-1.32.57-2"></path><path d="M9 6.8a6 6 0 0 1 9 5.2v2"></path></svg></span>
                            <div>
                                <p class="wpk-eyebrow"><?php esc_html_e('Passkey Hub Pro', 'wp-passkeys'); ?></p>
                                <h1><?php esc_html_e('WP Passkeys', 'wp-passkeys'); ?></h1>
                            </div>
                        </div>
                        <p class="wpk-hero__copy">
                            <?php esc_html_e('A premium passwordless authentication control center built for WordPress.', 'wp-passkeys'); ?>
                        </p>
                    </div>
                    <div class="wpk-hero__actions">
                        <span class="wpk-status-pill wpk-status-pill--success">
                            <span class="wpk-status-dot" aria-hidden="true"></span>
                            <?php esc_html_e('Ready', 'wp-passkeys'); ?>
                        </span>

                    </div>
                </header>

                <?php settings_errors(); ?>

                <nav class="wpk-tabs" aria-label="<?php esc_attr_e('WP Passkeys settings tabs', 'wp-passkeys'); ?>">
                    <?php $this->render_tab_link($base_url, 'settings', __('Settings', 'wp-passkeys'), $active_tab); ?>
                    <?php $this->render_tab_link($base_url, 'advanced', __('Advanced', 'wp-passkeys'), $active_tab); ?>
                    <?php $this->render_tab_link($base_url, 'shortcodes', __('Shortcodes', 'wp-passkeys'), $active_tab); ?>
                </nav>

                <div class="wpk-layout">
                    <main class="wpk-main-panel">
                        <?php if ($active_tab === 'shortcodes') : ?>
                            <?php $this->render_shortcodes_tab(); ?>
                        <?php else : ?>
                            <form method="post" action="options.php" class="wpk-settings-form">
                                <?php settings_fields($this->option_group); ?>
                                <?php $active_tab === 'advanced' ? $this->render_advanced_tab() : $this->render_settings_tab(); ?>
                                <footer class="wpk-form-footer">
                                    <p><?php esc_html_e('Changes apply immediately after saving.', 'wp-passkeys'); ?></p>
                                    <?php submit_button(__('Save Settings', 'wp-passkeys'), 'primary wpk-save-button', 'submit', false); ?>
                                </footer>
                            </form>
                        <?php endif; ?>
                    </main>

                    <aside class="wpk-sidebar" aria-label="<?php esc_attr_e('WP Passkeys quick actions', 'wp-passkeys'); ?>">
                        <?php $this->render_sidebar_cards(); ?>
                    </aside>
                </div>
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

    private function render_settings_tab() {
        $enabled = (bool) get_option('wpk_enabled', true);
        $eligible_roles = (array) get_option('wpk_eligible_roles', array('administrator'));
        $max_passkeys = absint(get_option('wpk_max_passkeys_per_user', 5));
        $verification = get_option('wpk_user_verification', 'required');
        $roles = wp_roles()->roles;
        ?>
        <section class="wpk-section-header">
            <div>
                <p class="wpk-eyebrow"><?php esc_html_e('Settings', 'wp-passkeys'); ?></p>
                <h2><?php esc_html_e('Everyday passkey controls', 'wp-passkeys'); ?></h2>
            </div>
            <span class="wpk-badge wpk-badge--pro"><?php esc_html_e('Premium defaults', 'wp-passkeys'); ?></span>
        </section>

        <div class="wpk-card wpk-card--setting">
            <div class="wpk-setting-copy">
                <h3><?php esc_html_e('Enable passkeys', 'wp-passkeys'); ?></h3>
                <p><?php esc_html_e('Allow eligible users to register and sign in with secure device passkeys.', 'wp-passkeys'); ?></p>
            </div>
            <label class="wpk-switch">
                <input type="checkbox" name="wpk_enabled" value="1" <?php checked($enabled); ?> />
                <span class="wpk-switch__track"><span class="wpk-switch__thumb"></span></span>
                <span class="screen-reader-text"><?php esc_html_e('Enable passkeys', 'wp-passkeys'); ?></span>
            </label>
        </div>

        <div class="wpk-card">
            <div class="wpk-card__header">
                <div>
                    <h3><?php esc_html_e('Eligible user roles', 'wp-passkeys'); ?></h3>
                    <p><?php esc_html_e('Choose which WordPress roles can create and use passkeys.', 'wp-passkeys'); ?></p>
                </div>
            </div>
            <div class="wpk-role-grid">
                <?php foreach ($roles as $role_key => $role) : ?>
                    <label class="wpk-role-chip">
                        <input type="checkbox" name="wpk_eligible_roles[]" value="<?php echo esc_attr($role_key); ?>" <?php checked(in_array($role_key, $eligible_roles, true)); ?> />
                        <span><?php echo esc_html(translate_user_role($role['name'])); ?></span>
                    </label>
                <?php endforeach; ?>
            </div>
        </div>

        <div class="wpk-card wpk-grid-2">
            <div class="wpk-field">
                <div class="wpk-label-row">
                    <label for="wpk_max_passkeys_per_user"><?php esc_html_e('Passkeys per user', 'wp-passkeys'); ?></label>
                    <span class="wpk-badge"><?php esc_html_e('Lite limit: 5', 'wp-passkeys'); ?></span>
                </div>
                <input id="wpk_max_passkeys_per_user" class="regular-text" type="number" min="1" max="5" name="wpk_max_passkeys_per_user" value="<?php echo esc_attr($max_passkeys); ?>" />
                <p><?php esc_html_e('Maximum number of passkeys each user can register.', 'wp-passkeys'); ?></p>
            </div>

            <div class="wpk-field">
                <div class="wpk-label-row">
                    <label for="wpk_user_verification"><?php esc_html_e('User verification', 'wp-passkeys'); ?></label>
                    <span class="wpk-badge wpk-badge--success"><?php esc_html_e('Recommended', 'wp-passkeys'); ?></span>
                </div>
                <select id="wpk_user_verification" name="wpk_user_verification">
                    <option value="required" <?php selected($verification, 'required'); ?>><?php esc_html_e('Required — biometric or device PIN', 'wp-passkeys'); ?></option>
                    <option value="preferred" <?php selected($verification, 'preferred'); ?>><?php esc_html_e('Preferred — use when available', 'wp-passkeys'); ?></option>
                    <option value="discouraged" <?php selected($verification, 'discouraged'); ?>><?php esc_html_e('Discouraged — presence only', 'wp-passkeys'); ?></option>
                </select>
                <p><?php esc_html_e('Required verification gives the strongest account protection.', 'wp-passkeys'); ?></p>
            </div>
        </div>
        <?php
    }

    private function render_advanced_tab() {
        $rp_name = get_option('wpk_rp_name', '');
        $rp_id = get_option('wpk_rp_id', '');
        $window = absint(get_option('wpk_rate_limit_window', 300));
        $max_failures = absint(get_option('wpk_rate_limit_max_failures', 8));
        $lockout = absint(get_option('wpk_rate_limit_lockout', 900));
        ?>
        <section class="wpk-section-header">
            <div>
                <p class="wpk-eyebrow"><?php esc_html_e('Advanced', 'wp-passkeys'); ?></p>
                <h2><?php esc_html_e('Technical configuration', 'wp-passkeys'); ?></h2>
            </div>
        </section>

        <div class="wpk-card wpk-grid-2">
            <div class="wpk-field">
                <label for="wpk_rp_name"><?php esc_html_e('Relying Party Name', 'wp-passkeys'); ?></label>
                <input id="wpk_rp_name" class="regular-text" type="text" name="wpk_rp_name" value="<?php echo esc_attr($rp_name); ?>" placeholder="<?php echo esc_attr(get_bloginfo('name')); ?>" />
                <p><?php esc_html_e('The name users see in their passkey prompt. Leave blank to use the site name.', 'wp-passkeys'); ?></p>
            </div>
            <div class="wpk-field">
                <label for="wpk_rp_id"><?php esc_html_e('Relying Party ID', 'wp-passkeys'); ?></label>
                <input id="wpk_rp_id" class="regular-text" type="text" name="wpk_rp_id" value="<?php echo esc_attr($rp_id); ?>" placeholder="<?php echo esc_attr(wp_parse_url(home_url(), PHP_URL_HOST)); ?>" />
                <p><?php esc_html_e('Usually your root domain. Leave blank unless you know you need to customize it.', 'wp-passkeys'); ?></p>
            </div>
        </div>

        <div class="wpk-card">
            <div class="wpk-card__header">
                <div>
                    <h3><?php esc_html_e('Rate limiting', 'wp-passkeys'); ?></h3>
                    <p><?php esc_html_e('Protect authentication endpoints from repeated failed attempts.', 'wp-passkeys'); ?></p>
                </div>
                <span class="wpk-badge wpk-badge--success"><?php esc_html_e('Protected', 'wp-passkeys'); ?></span>
            </div>
            <div class="wpk-grid-3">
                <div class="wpk-field">
                    <label for="wpk_rate_limit_window"><?php esc_html_e('Failure window', 'wp-passkeys'); ?></label>
                    <input id="wpk_rate_limit_window" type="number" min="60" max="3600" name="wpk_rate_limit_window" value="<?php echo esc_attr($window); ?>" />
                    <p><?php esc_html_e('Seconds.', 'wp-passkeys'); ?></p>
                </div>
                <div class="wpk-field">
                    <label for="wpk_rate_limit_max_failures"><?php esc_html_e('Max failures', 'wp-passkeys'); ?></label>
                    <input id="wpk_rate_limit_max_failures" type="number" min="1" max="50" name="wpk_rate_limit_max_failures" value="<?php echo esc_attr($max_failures); ?>" />
                    <p><?php esc_html_e('Attempts before lockout.', 'wp-passkeys'); ?></p>
                </div>
                <div class="wpk-field">
                    <label for="wpk_rate_limit_lockout"><?php esc_html_e('Lockout duration', 'wp-passkeys'); ?></label>
                    <input id="wpk_rate_limit_lockout" type="number" min="60" max="86400" name="wpk_rate_limit_lockout" value="<?php echo esc_attr($lockout); ?>" />
                    <p><?php esc_html_e('Seconds.', 'wp-passkeys'); ?></p>
                </div>
            </div>
        </div>

        <?php
    }

    private function render_shortcodes_tab() {
        $shortcodes = array(
            array(
                'title' => __('Login Form', 'wp-passkeys'),
                'code' => '[wp_passkey_login]',
                'description' => __('Display a passkey login form on any page.', 'wp-passkeys'),
                'placement' => __('Best for custom login pages.', 'wp-passkeys'),
            ),
            array(
                'title' => __('Register Button', 'wp-passkeys'),
                'code' => '[wp_passkey_register]',
                'description' => __('Let signed-in users register a new passkey.', 'wp-passkeys'),
                'placement' => __('Best for account and onboarding pages.', 'wp-passkeys'),
            ),
            array(
                'title' => __('Account Passkeys', 'wp-passkeys'),
                'code' => '[wp_passkey_profile]',
                'description' => __('Show a user-facing passkey management area.', 'wp-passkeys'),
                'placement' => __('Best for profile or dashboard pages.', 'wp-passkeys'),
            ),
            array(
                'title' => __('Conditional Prompt', 'wp-passkeys'),
                'code' => '[wp_passkey_prompt]',
                'description' => __('Prompt eligible users to set up passwordless login.', 'wp-passkeys'),
                'placement' => __('Best after login or checkout.', 'wp-passkeys'),
            ),
        );
        ?>
        <section class="wpk-section-header">
            <div>
                <p class="wpk-eyebrow"><?php esc_html_e('Shortcodes', 'wp-passkeys'); ?></p>
                <h2><?php esc_html_e('Drop-in passkey experiences', 'wp-passkeys'); ?></h2>
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
        <?php
    }

    private function render_sidebar_cards() {
        ?>
        <section class="wpk-side-card wpk-side-card--pro">
            <span class="wpk-badge wpk-badge--pro"><?php esc_html_e('Pro', 'wp-passkeys'); ?></span>
            <h2><?php esc_html_e('Passkey Hub Pro', 'wp-passkeys'); ?></h2>
            <p><?php esc_html_e('Unlock a premium passwordless experience with unlimited passkeys and advanced controls.', 'wp-passkeys'); ?></p>
            <ul>
                <li><?php esc_html_e('Unlimited passkeys per user', 'wp-passkeys'); ?></li>
                <li><?php esc_html_e('Passkey-only mode per role', 'wp-passkeys'); ?></li>
                <li><?php esc_html_e('Magic-link account recovery', 'wp-passkeys'); ?></li>
                <li><?php esc_html_e('WooCommerce checkout support', 'wp-passkeys'); ?></li>
                <li><?php esc_html_e('Gutenberg &amp; Elementor blocks', 'wp-passkeys'); ?></li>
                <li><?php esc_html_e('Device health dashboard', 'wp-passkeys'); ?></li>
                <li><?php esc_html_e('Full audit log + CSV export', 'wp-passkeys'); ?></li>
                <li><?php esc_html_e('Conditional access by role &amp; URL', 'wp-passkeys'); ?></li>
                <li><?php esc_html_e('WP-CLI commands', 'wp-passkeys'); ?></li>
                <li><?php esc_html_e('White-label &amp; agency tools', 'wp-passkeys'); ?></li>
            </ul>
            <a href="#" class="wpk-button wpk-button--pro"><?php esc_html_e('Upgrade to Pro', 'wp-passkeys'); ?></a>
        </section>

        <section class="wpk-side-card">
            <h2><?php esc_html_e('Quick setup', 'wp-passkeys'); ?></h2>
            <ol class="wpk-checklist">
                <li><?php esc_html_e('Activate the plugin', 'wp-passkeys'); ?></li>
                <li><?php esc_html_e('Enable passkeys in Settings', 'wp-passkeys'); ?></li>
                <li><?php esc_html_e('Choose eligible roles', 'wp-passkeys'); ?></li>
                <li><?php esc_html_e('Register your first passkey in Your Profile', 'wp-passkeys'); ?></li>
                <li><?php esc_html_e('Sign out and test the login button', 'wp-passkeys'); ?></li>
            </ol>
        </section>
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
        return min(5, max(1, absint($value)));
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
}
