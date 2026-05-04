<?php
/**
 * WPK_Shortcodes — front-end shortcodes for passkey login and registration.
 *
 * [wpk_login_button]
 *   Renders the passkey sign-in button on any page or post.
 *   Attributes:
 *     label        — Button text. Default: "Sign in with Passkey".
 *     redirect_to  — URL to redirect after login. Default: site home or settings value.
 *     class        — Extra CSS class(es) added to the wrapper div.
 *
 * [wpk_register_button]
 *   Renders the passkey registration button for already-logged-in eligible users.
 *   Attributes:
 *     label  — Button text. Default: "Register a Passkey".
 *     class  — Extra CSS class(es) added to the wrapper div.
 */

if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

class WPK_Shortcodes {

    private static $login_button_rendered = false;

    public function __construct() {
        add_shortcode( 'wpk_login_button',    array( $this, 'render_login_button' ) );
        add_shortcode( 'wpk_register_button', array( $this, 'render_register_button' ) );
        add_shortcode( 'wpk_passkey_profile', array( $this, 'render_passkey_profile' ) );
        add_shortcode( 'wpk_passkey_prompt',  array( $this, 'render_passkey_prompt' ) );

        // Legacy aliases kept for backward compatibility during shortcode migration.
        add_shortcode( 'wp_passkey_profile',  array( $this, 'render_passkey_profile' ) );
        add_shortcode( 'wp_passkey_prompt',   array( $this, 'render_passkey_prompt' ) );
    }

    private function user_has_active_passkey( int $user_id ): bool {
        global $wpdb;

        if ( ! class_exists( 'WPK_Passkeys' ) ) {
            return false;
        }

        $table = $wpdb->prefix . WPK_Passkeys::TABLE_CREDENTIALS;
        $count = (int) $wpdb->get_var( // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching -- custom credentials table presence check.
            $wpdb->prepare(
                "SELECT COUNT(*) FROM {$table} WHERE user_id = %d AND revoked_at IS NULL", // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared -- table name is plugin-controlled constant + prefix.
                $user_id
            )
        );

        return $count > 0;
    }

    private function enqueue_profile_assets(): void {
        if ( ! wp_script_is( 'wpk-profile', 'enqueued' ) ) {
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
                    'labelPlaceholder' => __( 'e.g. iPhone 15, YubiKey 5', 'passkeyflow' ),
                    'starting'         => __( 'Starting passkey registration…', 'passkeyflow' ),
                    'success'          => __( 'Passkey registered successfully.', 'passkeyflow' ),
                    'failed'           => __( 'Passkey registration failed. Try again.', 'passkeyflow' ),
                    'notSupported'     => __( 'This browser does not support passkeys.', 'passkeyflow' ),
                    'mobileHint'       => __( 'Tip: open this page on your phone to save a passkey to iCloud Keychain or Google Password Manager.', 'passkeyflow' ),
                    'confirmRevoke'    => __( 'Revoke this passkey? You will need to re-register to use it again.', 'passkeyflow' ),
                    'revokeFailed'     => __( 'Failed to revoke passkey.', 'passkeyflow' ),
                    'limitReached'     => __( 'You have reached the maximum number of passkeys. Revoke an existing one to add a new one.', 'passkeyflow' ),
                ),
            ) );
        }
        if ( ! wp_style_is( 'wpk-admin', 'enqueued' ) ) {
            wp_enqueue_style( 'wpk-admin', WPK_PLUGIN_URL . 'admin/css/wpk-admin.css', array(), WPK_VERSION );
        }
    }

    public function render_passkey_profile( $atts ): string {
        if ( ! class_exists( 'WPK_Passkeys' ) || ! WPK_Passkeys::is_enabled() ) {
            return '';
        }

        if ( ! is_user_logged_in() ) {
            return '';
        }

        if ( ! class_exists( 'lbuchs\\WebAuthn\\WebAuthn' ) ) {
            return '';
        }

        $user = wp_get_current_user();
        if ( ! WPK_Passkeys::user_is_eligible( $user ) ) {
            return '';
        }

        $this->enqueue_profile_assets();

        $engine = WPK_Passkeys::get_instance();
        if ( ! $engine ) {
            return $this->render_register_button( $atts );
        }

        ob_start();
        $engine->render_profile_section( $user );
        return ob_get_clean();
    }

    public function render_passkey_prompt( $atts ): string {
        if ( ! class_exists( 'WPK_Passkeys' ) || ! WPK_Passkeys::is_enabled() ) {
            return '';
        }

        if ( ! is_user_logged_in() ) {
            return '';
        }

        if ( ! class_exists( 'lbuchs\\WebAuthn\\WebAuthn' ) ) {
            return '';
        }

        $user = wp_get_current_user();
        if ( ! WPK_Passkeys::user_is_eligible( $user ) ) {
            return '';
        }

        $atts = shortcode_atts( array(
            'title'        => __( 'Upgrade your account security with a passkey', 'passkeyflow' ),
            'message'      => __( 'Use Face ID, Touch ID, Windows Hello, or a hardware key for fast passwordless sign-in.', 'passkeyflow' ),
            'button_label' => __( 'Register a Passkey', 'passkeyflow' ),
            'class'        => '',
            'force_show'   => '0',
        ), $atts, 'wpk_passkey_prompt' );

        $force_show = in_array( strtolower( (string) $atts['force_show'] ), array( '1', 'true', 'yes' ), true )
            && current_user_can( 'manage_options' );
        if ( ! $force_show && $this->user_has_active_passkey( (int) $user->ID ) ) {
            return '';
        }

        $title        = sanitize_text_field( $atts['title'] );
        $message      = sanitize_text_field( $atts['message'] );
        $button_label = sanitize_text_field( $atts['button_label'] );
        $extra_class  = implode( ' ', array_map( 'sanitize_html_class', preg_split( '/\s+/', trim( $atts['class'] ) ) ) );

        $register_markup = $this->render_register_button( array(
            'label' => $button_label,
            'class' => 'wpk-passkey-prompt-register',
        ) );

        if ( $register_markup === '' ) {
            return '';
        }

        $wrapper_class = 'wpk-passkey-prompt' . ( $extra_class ? ' ' . $extra_class : '' );

        ob_start();
        ?>
        <section class="<?php echo esc_attr( $wrapper_class ); ?>" aria-label="<?php esc_attr_e( 'Passkey setup prompt', 'passkeyflow' ); ?>">
            <div class="wpk-passkey-prompt__card">
                <p class="wpk-passkey-prompt__eyebrow"><?php esc_html_e( 'Recommended', 'passkeyflow' ); ?></p>
                <h3><?php echo esc_html( $title ); ?></h3>
                <p class="wpk-passkey-prompt__copy"><?php echo esc_html( $message ); ?></p>
                <ul class="wpk-passkey-prompt__benefits" role="list">
                    <li><?php esc_html_e( 'Biometric login in seconds', 'passkeyflow' ); ?></li>
                    <li><?php esc_html_e( 'Stronger protection than passwords', 'passkeyflow' ); ?></li>
                    <li><?php esc_html_e( 'Works across your trusted devices', 'passkeyflow' ); ?></li>
                </ul>
                <div class="wpk-passkey-prompt__actions">
                    <?php echo $register_markup; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped ?>
                </div>
            </div>
        </section>
        <?php
        return ob_get_clean();
    }

    // ──────────────────────────────────────────────────────────
    // [wpk_login_button]
    // ──────────────────────────────────────────────────────────

    public function render_login_button( $atts ): string {
        if ( ! class_exists( 'WPK_Passkeys' ) || ! WPK_Passkeys::is_enabled() ) {
            return '';
        }

        if ( is_user_logged_in() ) {
            return '';
        }

        if ( ! class_exists( 'lbuchs\\WebAuthn\\WebAuthn' ) ) {
            return '';
        }

        $atts = shortcode_atts( array(
            'label'       => __( 'Sign in with Passkey', 'passkeyflow' ),
            'redirect_to' => '',
            'class'       => '',
            'allow_multiple' => '0',
        ), $atts, 'wpk_login_button' );

        $allow_multiple = in_array( strtolower( (string) $atts['allow_multiple'] ), array( '1', 'true', 'yes' ), true );
        if ( ! $allow_multiple && self::$login_button_rendered ) {
            return '';
        }

        $label       = sanitize_text_field( $atts['label'] );
        $redirect_to = $atts['redirect_to'] !== ''
            ? esc_url( $atts['redirect_to'] )
            : '';
        $extra_class = implode( ' ', array_map( 'sanitize_html_class', preg_split( '/\s+/', trim( $atts['class'] ) ) ) );

        // Enqueue assets if not already queued.
        if ( ! wp_script_is( 'wpk-login', 'enqueued' ) ) {
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
                    'notSupported' => __( 'Passkeys are unavailable here. Use HTTPS (or localhost) in a passkey-capable browser, or sign in with your password.', 'passkeyflow' ),
                    'genericError' => __( 'Passkey sign-in failed. Please try again or use your password.', 'passkeyflow' ),
                    'signingIn'    => __( 'Signing in…', 'passkeyflow' ),
                ),
            ) );
        }
        if ( ! wp_style_is( 'wpk-login', 'enqueued' ) ) {
            wp_enqueue_style( 'wpk-login', WPK_PLUGIN_URL . 'admin/css/wpk-admin.css', array(), WPK_VERSION );
        }

        $wrapper_class = 'wpk-shortcode-login-wrap' . ( $extra_class ? ' ' . $extra_class : '' );
        self::$login_button_rendered = true;

        ob_start();
        ?>
        <div class="<?php echo esc_attr( $wrapper_class ); ?>">
            <button type="button"
                    class="wpk-passkey-btn wpk-sc-btn wpk-signin-passkey"
                    data-wpk-passkey-login-btn="1"
                    aria-label="<?php esc_attr_e( 'Sign in with a passkey (Face ID, Touch ID, or security key)', 'passkeyflow' ); ?>"
                    <?php if ( $redirect_to ) : ?>data-redirect="<?php echo esc_attr( $redirect_to ); ?>"<?php endif; ?>>
                <span class="wpk-passkey-icon" aria-hidden="true">
                    <svg xmlns="http://www.w3.org/2000/svg" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                        <path d="M12.4 2.7a2.5 2.5 0 0 1 3.4 0l5.5 5.5a2.5 2.5 0 0 1 0 3.4l-3.7 3.7a2.5 2.5 0 0 1-3.4 0L8.7 9.8a2.5 2.5 0 0 1 0-3.4z"/>
                        <path d="m14 7 3 3"/>
                        <path d="m9.4 10.6-6.814 6.814A2 2 0 0 0 2 18.828V21a1 1 0 0 0 1 1h3a1 1 0 0 0 1-1v-1a1 1 0 0 1 1-1h1a1 1 0 0 0 1-1v-1a1 1 0 0 1 1-1h.172a2 2 0 0 0 1.414-.586l.814-.814"/>
                    </svg>
                </span>
                <?php echo esc_html( $label ); ?>
            </button>
            <p class="wpk-login-message wpk-is-hidden"
               aria-live="polite"></p>
        </div>
        <?php
        return ob_get_clean();
    }

    // ──────────────────────────────────────────────────────────
    // [wpk_register_button]
    // ──────────────────────────────────────────────────────────

    public function render_register_button( $atts ): string {
        if ( ! class_exists( 'WPK_Passkeys' ) || ! WPK_Passkeys::is_enabled() ) {
            return '';
        }

        if ( ! is_user_logged_in() ) {
            return '';
        }

        if ( ! class_exists( 'lbuchs\\WebAuthn\\WebAuthn' ) ) {
            return '';
        }

        $user = wp_get_current_user();

        if ( ! WPK_Passkeys::user_is_eligible( $user ) ) {
            return '';
        }

        $atts = shortcode_atts( array(
            'label' => __( 'Register a Passkey', 'passkeyflow' ),
            'class' => '',
        ), $atts, 'wpk_register_button' );

        $label       = sanitize_text_field( $atts['label'] );
        $extra_class = implode( ' ', array_map( 'sanitize_html_class', preg_split( '/\s+/', trim( $atts['class'] ) ) ) );

        $this->enqueue_profile_assets();

        $wrapper_class = 'wpk-shortcode-register-wrap' . ( $extra_class ? ' ' . $extra_class : '' );
        $instance_id   = wp_unique_id( 'wpk-passkey-register-' );
        $input_id      = $instance_id . '-label';
        $message_id    = $instance_id . '-message';

        ob_start();
        ?>
        <div class="<?php echo esc_attr( $wrapper_class ); ?>">
            <div class="wpk-profile-register-controls">
                <label for="<?php echo esc_attr( $input_id ); ?>" class="screen-reader-text"><?php esc_html_e( 'Device label (optional)', 'passkeyflow' ); ?></label>
                <input type="text"
                       id="<?php echo esc_attr( $input_id ); ?>"
                       class="wpk-profile-label-input"
                       placeholder="<?php esc_attr_e( 'Device label (optional)', 'passkeyflow' ); ?>"
                       maxlength="100" />
                <div class="wpk-register-actions">
                    <button type="button" class="wpk-profile-btn" data-wpk-passkey-register="1" data-wpk-passkey-input-id="<?php echo esc_attr( $input_id ); ?>" data-wpk-passkey-message-id="<?php echo esc_attr( $message_id ); ?>" aria-describedby="<?php echo esc_attr( $message_id ); ?>">
                        <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M12 10a2 2 0 0 0-2 2c0 1.02-.1 2.51-.26 4"/><path d="M14 13.12c0 2.38 0 6.38-1 8.88"/><path d="M17.29 21.02c.12-.6.43-2.3.5-3.02"/><path d="M2 12a10 10 0 0 1 18-6"/><path d="M2 16h.01"/><path d="M21.8 16c.2-2 .131-5.354 0-6"/><path d="M5 19.5C5.5 18 6 15 6 12a6 6 0 0 1 .34-2"/><path d="M8.65 22c.21-.66.45-1.32.57-2"/><path d="M9 6.8a6 6 0 0 1 9 5.2v2"/></svg>
                        <?php echo esc_html( $label ); ?>
                    </button>
                    <p id="<?php echo esc_attr( $message_id ); ?>" class="wpk-profile-tip" aria-live="polite"></p>
                </div>
            </div>
        </div>
        <?php
        return ob_get_clean();
    }
}
