<?php
/**
 * PKFLOW_Integration_Manager
 *
 * Adds optional passkey login modules for popular ecosystem plugins.
 * Modules are auto-enabled only when each dependency is active.
 */

if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

class PKFLOW_Integration_Manager {

    private array $registry = array();
    private array $auto_inject_rendered = array();
    private array $registered_blocks = array();

    public function __construct( bool $bootstrap_hooks = true ) {
        $this->registry = $this->build_registry();

        if ( $bootstrap_hooks ) {
            add_action( 'init', array( $this, 'register_integrations' ), 30 );
            add_action( 'enqueue_block_editor_assets', array( $this, 'enqueue_block_editor_assets' ) );
        }
    }

    public static function get_available_integrations(): array {
        $manager = new self( false );
        $labels  = array();

        foreach ( $manager->registry as $key => $config ) {
            if ( empty( $config['dependency_active'] ) ) {
                continue;
            }

            $master_default = isset( $config['default_master'] ) ? (int) $config['default_master'] : 0;
            if ( ! $manager->is_master_enabled( (string) $config['master_option'], $master_default ) ) {
                continue;
            }

            if ( ! empty( $config['dependency_active'] ) ) {
                $labels[] = $manager->get_integration_label( (string) $key );
            }
        }

        return $labels;
    }

    public static function get_integration_shortcodes(): array {
        $manager    = new self( false );
        $shortcodes = array();

        foreach ( $manager->registry as $key => $config ) {
            if ( empty( $config['dependency_active'] ) ) {
                continue;
            }

            $master_default = isset( $config['default_master'] ) ? (int) $config['default_master'] : 0;
            if ( ! $manager->is_master_enabled( (string) $config['master_option'], $master_default ) ) {
                continue;
            }

            $shortcodes[] = array(
                'title' => $manager->get_integration_block_title( (string) $key ),
                'code'  => '[' . $config['shortcode'] . ']',
            );
        }

        return $shortcodes;
    }

    public static function get_settings_registry(): array {
        $manager  = new self( false );
        $settings = array();

        foreach ( $manager->registry as $integration_key => $config ) {
            $master_default = isset( $config['default_master'] ) ? (int) $config['default_master'] : 0;
            $auto_default   = isset( $config['default_auto'] ) ? (int) $config['default_auto'] : 0;

            $settings[] = array(
                'key'               => (string) $integration_key,
                'label'             => $manager->get_integration_label( (string) $integration_key ),
                'master_option'     => (string) $config['master_option'],
                'default_master'    => $master_default,
                'dependency_active' => ! empty( $config['dependency_active'] ),
                'master_enabled'    => $manager->is_master_enabled( (string) $config['master_option'], $master_default ),
            );
        }

        return $settings;
    }

    private function build_registry(): array {
        return array(
            'woocommerce' => array(
                'master_option'      => 'pkflow_enable_woocommerce_support',
                'default_master'     => 1,
                'dependency_active'  => $this->is_woocommerce_active(),
                'shortcode' => 'pkflow_woocommerce_login',
                'block'     => 'passkeyflow/woocommerce-login-card',
            ),
            'edd' => array(
                'master_option'      => 'pkflow_enable_edd_support',
                'default_master'     => 1,
                'dependency_active'  => $this->is_edd_active(),
                'shortcode' => 'pkflow_edd_login',
                'block'     => 'passkeyflow/edd-login-card',
            ),
            'memberpress' => array(
                'master_option'      => 'pkflow_enable_memberpress_support',
                'default_master'     => 1,
                'dependency_active'  => $this->is_memberpress_active(),
                'shortcode' => 'pkflow_memberpress_login',
                'block'     => 'passkeyflow/memberpress-login-card',
            ),
            'ultimate_member' => array(
                'master_option'      => 'pkflow_enable_ultimate_member_support',
                'default_master'     => 1,
                'dependency_active'  => $this->is_ultimate_member_active(),
                'shortcode' => 'pkflow_ultimate_member_login',
                'block'     => 'passkeyflow/ultimate-member-login-card',
            ),
            'learndash' => array(
                'master_option'      => 'pkflow_enable_learndash_support',
                'default_master'     => 1,
                'dependency_active'  => $this->is_learndash_active(),
                'shortcode' => 'pkflow_learndash_login',
                'block'     => 'passkeyflow/learndash-login-card',
            ),
            'buddyboss' => array(
                'master_option'      => 'pkflow_enable_buddyboss_support',
                'default_master'     => 1,
                'dependency_active'  => $this->is_buddyboss_active(),
                'shortcode' => 'pkflow_buddyboss_login',
                'block'     => 'passkeyflow/buddyboss-login-card',
            ),
            'gravityforms' => array(
                'master_option'      => 'pkflow_enable_gravityforms_support',
                'default_master'     => 1,
                'dependency_active'  => $this->is_gravityforms_active(),
                'shortcode' => 'pkflow_gravityforms_login',
                'block'     => 'passkeyflow/gravityforms-login-card',
            ),
            'pmp' => array(
                'master_option'      => 'pkflow_enable_pmp_support',
                'default_master'     => 1,
                'dependency_active'  => $this->is_pmp_active(),
                'shortcode' => 'pkflow_pmp_login',
                'block'     => 'passkeyflow/pmp-login-card',
            ),
        );
    }

    public function register_integrations(): void {
        foreach ( $this->registry as $integration_key => $config ) {
            if ( empty( $config['dependency_active'] ) ) {
                continue;
            }

            $master_default = isset( $config['default_master'] ) ? (int) $config['default_master'] : 0;
            if ( ! $this->is_master_enabled( (string) $config['master_option'], $master_default ) ) {
                continue;
            }

            $this->register_shortcode_for_integration( (string) $integration_key, (string) $config['shortcode'] );
            $this->register_block_for_integration( (string) $integration_key, (string) $config['block'], (string) $config['shortcode'] );

            $this->register_auto_inject_hooks( (string) $integration_key );

            if ( 'gravityforms' === $integration_key ) {
                $this->register_gravityforms_field_support();
            }
        }
    }

    private function register_shortcode_for_integration( string $integration_key, string $shortcode_tag ): void {
        add_shortcode(
            $shortcode_tag,
            function ( $atts ) use ( $integration_key ) {
                $atts = shortcode_atts(
                    array(
                        'label'   => __( 'Sign in with Passkey', 'passkeyflow' ),
                        'context' => 'manual',
                    ),
                    $atts,
                    $integration_key
                );

                $label   = sanitize_text_field( (string) $atts['label'] );
                $context = sanitize_key( (string) $atts['context'] );
                $classes = 'wpk-integration-passkey wpk-integration-passkey--' . esc_attr( $integration_key );

                if ( 'auto-inject' === $context ) {
                    $classes .= ' wpk-integration-passkey--auto-inject';
                }

                return '<div class="' . $classes . '">'
                    . do_shortcode( '[pkflow_login_button allow_multiple="1" label="' . esc_attr( $label ) . '"]' )
                    . '</div>';
            }
        );
    }

    private function register_block_for_integration( string $integration_key, string $block_name, string $shortcode_tag ): void {
        if ( ! function_exists( 'register_block_type' ) ) {
            return;
        }

        $this->register_block_editor_script();

        register_block_type(
            $block_name,
            array(
                'editor_script'   => 'wpk-gutenberg-blocks',
                'editor_style'    => 'wpk-gutenberg-blocks',
                'title'           => $this->get_integration_block_title( $integration_key ),
                'category'        => 'widgets',
                'icon'            => 'shield',
                'keywords'        => array( 'passkey', 'login', $this->get_integration_label( $integration_key ) ),
                'render_callback' => function ( $attributes ) use ( $shortcode_tag ) {
                    $label = isset( $attributes['label'] ) ? sanitize_text_field( (string) $attributes['label'] ) : __( 'Sign in with Passkey', 'passkeyflow' );
                    return do_shortcode( '[' . $shortcode_tag . ' label="' . esc_attr( $label ) . '"]' );
                },
            )
        );

        $this->registered_blocks[] = array(
            'name'        => $block_name,
            'title'       => $this->get_integration_block_title( $integration_key ),
            'description' => sprintf(
                /* translators: %s integration label. */
                __( 'Render a passkey sign-in card for %s flows.', 'passkeyflow' ),
                $this->get_integration_label( $integration_key )
            ),
            'label'       => __( 'Sign in with Passkey', 'passkeyflow' ),
            'keywords'    => array( 'passkey', 'login', $this->get_integration_label( $integration_key ) ),
            'icon'        => 'shield',
            'category'    => 'widgets',
        );
    }

    private function register_block_editor_script(): void {
        if ( wp_script_is( 'wpk-gutenberg-blocks', 'registered' ) ) {
            return;
        }

        wp_register_style(
            'wpk-gutenberg-blocks',
            PKFLOW_PLUGIN_URL . 'admin/css/wpk-gutenberg-blocks.css',
            array(),
            PKFLOW_VERSION
        );

        wp_register_script(
            'wpk-gutenberg-blocks',
            PKFLOW_PLUGIN_URL . 'admin/js/wpk-gutenberg-blocks.js',
            array( 'wp-blocks', 'wp-element', 'wp-i18n', 'wp-block-editor' ),
            PKFLOW_VERSION,
            true
        );
    }

    public function enqueue_block_editor_assets(): void {
        if ( empty( $this->registered_blocks ) ) {
            return;
        }

        $this->register_block_editor_script();

        wp_localize_script(
            'wpk-gutenberg-blocks',
            'WPKIntegrationBlocks',
            array(
                'blocks' => array_values( $this->registered_blocks ),
            )
        );

        wp_enqueue_style( 'wpk-gutenberg-blocks' );
        wp_enqueue_script( 'wpk-gutenberg-blocks' );
    }

    private function get_integration_label( string $integration_key ): string {
        $labels = array(
            'learndash'       => __( 'LearnDash', 'passkeyflow' ),
            'buddyboss'       => __( 'BuddyBoss', 'passkeyflow' ),
            'gravityforms'    => __( 'Gravity Forms', 'passkeyflow' ),
            'pmp'             => __( 'PMPro', 'passkeyflow' ),
            'woocommerce'     => __( 'WooCommerce', 'passkeyflow' ),
            'edd'             => __( 'Easy Digital Downloads', 'passkeyflow' ),
            'memberpress'     => __( 'MemberPress', 'passkeyflow' ),
            'ultimate_member' => __( 'Ultimate Member', 'passkeyflow' ),
        );

        return $labels[ $integration_key ] ?? __( 'Integration', 'passkeyflow' );
    }

    private function get_integration_block_title( string $integration_key ): string {
        return sprintf(
            /* translators: %s integration label. */
            __( '%s Passkey Login', 'passkeyflow' ),
            $this->get_integration_label( $integration_key )
        );
    }

    private function register_auto_inject_hooks( string $integration_key ): void {
        if ( 'learndash' === $integration_key ) {
            add_filter( 'the_content', array( $this, 'inject_learndash_passkey_prompt' ), 15 );
            return;
        }

        if ( 'woocommerce' === $integration_key ) {
            add_action( 'woocommerce_login_form_end', array( $this, 'render_woocommerce_auto_inject' ) );
            add_action( 'woocommerce_after_checkout_registration_form', array( $this, 'render_woocommerce_auto_inject' ) );
            return;
        }

        if ( 'edd' === $integration_key ) {
            add_action( 'edd_login_fields_after', array( $this, 'render_edd_auto_inject' ) );
            add_action( 'edd_purchase_form_after_user_info', array( $this, 'render_edd_auto_inject' ) );
            add_action( 'edd_purchase_form_user_info', array( $this, 'render_edd_auto_inject' ) );
            return;
        }

        if ( 'memberpress' === $integration_key ) {
            add_action( 'mepr-login-form-before-submit', array( $this, 'render_memberpress_auto_inject' ) );
            add_action( 'mepr_before_login_form_submit', array( $this, 'render_memberpress_auto_inject' ) );
            add_action( 'mepr-login-form-after-submit', array( $this, 'render_memberpress_auto_inject' ) );
            return;
        }

        if ( 'ultimate_member' === $integration_key ) {
            add_action( 'um_after_login_fields', array( $this, 'render_ultimate_member_auto_inject' ), 10005 );
            return;
        }

        if ( 'buddyboss' === $integration_key ) {
            add_action( 'bp_after_sidebar_login_form', array( $this, 'render_buddyboss_auto_inject' ) );
            add_action( 'bp_after_login_widget_form', array( $this, 'render_buddyboss_auto_inject' ) );
            return;
        }

        if ( 'pmp' === $integration_key ) {
            add_action( 'pmpro_after_login_fields', array( $this, 'render_pmp_auto_inject' ) );
            return;
        }

        if ( 'gravityforms' === $integration_key ) {
            add_action( 'gform_after_form', array( $this, 'render_gravityforms_auto_inject' ), 20, 2 );
        }
    }

    public function inject_learndash_passkey_prompt( string $content ): string {
        if ( ! $this->should_auto_inject_for_integration( 'learndash' ) ) {
            return $content;
        }

        if ( is_admin() || is_feed() || ! is_singular() || is_user_logged_in() ) {
            return $content;
        }

        $post_type = get_post_type();
        $types     = array( 'sfwd-courses', 'sfwd-lessons', 'sfwd-topic', 'sfwd-quiz', 'groups' );
        if ( ! in_array( $post_type, $types, true ) ) {
            return $content;
        }

        $button = do_shortcode( '[pkflow_learndash_login]' );
        if ( '' === trim( $button ) ) {
            return $content;
        }

        return $button . $content;
    }

    public function render_buddyboss_auto_inject(): void {
        $this->render_integration_auto_inject( 'buddyboss', '[pkflow_buddyboss_login]' );
    }

    public function render_woocommerce_auto_inject(): void {
        $this->render_integration_auto_inject( 'woocommerce', '[pkflow_woocommerce_login]' );
    }

    public function render_edd_auto_inject(): void {
        $this->render_integration_auto_inject( 'edd', '[pkflow_edd_login]' );
    }

    public function render_memberpress_auto_inject(): void {
        $this->render_integration_auto_inject( 'memberpress', '[pkflow_memberpress_login]' );
    }

    public function render_ultimate_member_auto_inject(): void {
        $this->render_integration_auto_inject( 'ultimate_member', '[pkflow_ultimate_member_login]' );
    }

    public function render_pmp_auto_inject(): void {
        $this->render_integration_auto_inject( 'pmp', '[pkflow_pmp_login]' );
    }

    public function render_gravityforms_auto_inject( $form, bool $ajax ): void {
        unset( $ajax );

        if ( ! $this->should_auto_inject_for_integration( 'gravityforms' ) ) {
            return;
        }

        if ( ! $this->is_gravityforms_login_like_form( $form ) ) {
            return;
        }

        $output = do_shortcode( '[pkflow_gravityforms_login]' );
        if ( '' === trim( $output ) ) {
            return;
        }

        echo $output; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
    }

    private function render_integration_auto_inject( string $integration_key, string $shortcode ): void {
        if ( ! $this->should_auto_inject_for_integration( $integration_key ) ) {
            return;
        }

        // Prevent duplicate output from the same callback context, while still
        // allowing the same integration to render in distinct form contexts.
        $render_context = current_filter();
        if ( ! is_string( $render_context ) || '' === $render_context ) {
            $render_context = 'manual';
        }

        $render_key = $integration_key . '|' . $render_context;
        if ( isset( $this->auto_inject_rendered[ $render_key ] ) && $this->auto_inject_rendered[ $render_key ] ) {
            return;
        }

        $shortcode = rtrim( $shortcode, ']' ) . ' context="auto-inject"]';
        $output    = do_shortcode( $shortcode );
        if ( '' === trim( $output ) ) {
            return;
        }

        $this->auto_inject_rendered[ $render_key ] = true;
        echo $output; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
    }

    private function should_auto_inject_for_integration( string $integration_key ): bool {
        if ( is_admin() || is_user_logged_in() ) {
            return false;
        }

        if ( empty( $this->registry[ $integration_key ] ) || ! is_array( $this->registry[ $integration_key ] ) ) {
            return false;
        }

        $config = $this->registry[ $integration_key ];

        $master_default = isset( $config['default_master'] ) ? (int) $config['default_master'] : 0;
        if ( ! $this->is_master_enabled( (string) $config['master_option'], $master_default ) ) {
            return false;
        }

        return $this->is_dependency_active_for_integration( $integration_key );
    }

    private function is_master_enabled( string $option_key, int $default_value = 0 ): bool {
        return (int) get_option( $option_key, $default_value ) === 1;
    }

    private function register_gravityforms_field_support(): void {
        add_action( 'gform_loaded', array( $this, 'register_gravityforms_field' ), 20 );
    }

    public function register_gravityforms_field(): void {
        if ( ! class_exists( 'GF_Field' ) || ! class_exists( 'GF_Fields' ) ) {
            return;
        }

        pkflow_register_gravityforms_passkey_field_class();
        if ( ! class_exists( 'PKFLOW_GF_Field_Passkey' ) ) {
            return;
        }

        GF_Fields::register( new PKFLOW_GF_Field_Passkey() );
    }

    private function is_gravityforms_login_like_form( $form ): bool {
        if ( ! is_array( $form ) || empty( $form['fields'] ) || ! is_array( $form['fields'] ) ) {
            return false;
        }

        $has_password_field   = false;
        $has_identifier_field = false;

        foreach ( $form['fields'] as $field ) {
            if ( ! is_object( $field ) || ! isset( $field->type ) ) {
                continue;
            }

            $type = strtolower( (string) $field->type );
            if ( 'password' === $type ) {
                $has_password_field = true;
                continue;
            }

            if ( in_array( $type, array( 'text', 'email', 'username' ), true ) ) {
                $has_identifier_field = true;
            }
        }

        if ( $has_password_field && $has_identifier_field ) {
            return true;
        }

        $title = isset( $form['title'] ) ? strtolower( sanitize_text_field( (string) $form['title'] ) ) : '';
        if ( '' !== $title && ( strpos( $title, 'login' ) !== false || strpos( $title, 'sign in' ) !== false ) ) {
            return true;
        }

        return false;
    }

    private function is_dependency_active_for_integration( string $integration_key ): bool {
        if ( 'learndash' === $integration_key ) {
            return $this->is_learndash_active();
        }
        if ( 'buddyboss' === $integration_key ) {
            return $this->is_buddyboss_active();
        }
        if ( 'gravityforms' === $integration_key ) {
            return $this->is_gravityforms_active();
        }
        if ( 'pmp' === $integration_key ) {
            return $this->is_pmp_active();
        }
        if ( 'woocommerce' === $integration_key ) {
            return $this->is_woocommerce_active();
        }
        if ( 'edd' === $integration_key ) {
            return $this->is_edd_active();
        }
        if ( 'memberpress' === $integration_key ) {
            return $this->is_memberpress_active();
        }
        if ( 'ultimate_member' === $integration_key ) {
            return $this->is_ultimate_member_active();
        }

        return false;
    }

    private function is_learndash_active(): bool {
        return defined( 'LEARNDASH_VERSION' ) || class_exists( 'SFWD_LMS' );
    }

    private function is_buddyboss_active(): bool {
        return defined( 'BUDDYBOSS_PLATFORM_VERSION' )
            || class_exists( 'BuddyBossPlatform' )
            || defined( 'BP_VERSION' )
            || function_exists( 'buddypress' );
    }

    private function is_gravityforms_active(): bool {
        return class_exists( 'GFForms' );
    }

    private function is_pmp_active(): bool {
        return defined( 'PMPRO_VERSION' ) || function_exists( 'pmpro_getOption' );
    }

    private function is_woocommerce_active(): bool {
        return class_exists( 'WooCommerce' );
    }

    private function is_edd_active(): bool {
        return class_exists( 'Easy_Digital_Downloads' ) || defined( 'EDD_VERSION' );
    }

    private function is_memberpress_active(): bool {
        return class_exists( 'MeprAppCtrl' );
    }

    private function is_ultimate_member_active(): bool {
        return class_exists( 'UM' ) || function_exists( 'UM' );
    }
}

/**
 * Register Gravity Forms custom field class lazily after GF loads.
 */
function pkflow_register_gravityforms_passkey_field_class(): void {
    if ( ! class_exists( 'GF_Field' ) || class_exists( 'PKFLOW_GF_Field_Passkey' ) ) {
        return;
    }

    class PKFLOW_GF_Field_Passkey extends GF_Field {
        public $type = 'passkey';

        public function get_form_editor_field_title() {
            return esc_attr__( 'Passkey Field', 'passkeyflow' );
        }

        public function get_form_editor_button() {
            return array(
                'group' => 'advanced_fields',
                'text'  => $this->get_form_editor_field_title(),
            );
        }

        public function get_form_editor_field_description() {
            return esc_html__( 'Renders a passkey sign-in control for Gravity Forms-powered flows.', 'passkeyflow' );
        }

        public function get_form_editor_field_settings() {
            return array( 'label_setting', 'description_setting' );
        }

        public function get_field_input( $form, $value = '', $entry = null ) {
            unset( $form, $value, $entry );
            return do_shortcode( '[pkflow_gravityforms_login]' );
        }
    }
}
