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

    public function __construct() {
        add_shortcode( 'wpk_login_button',    array( $this, 'render_login_button' ) );
        add_shortcode( 'wpk_register_button', array( $this, 'render_register_button' ) );
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
            'label'       => __( 'Sign in with Passkey', 'wp-passkeys' ),
            'redirect_to' => '',
            'class'       => '',
        ), $atts, 'wpk_login_button' );

        $label       = sanitize_text_field( $atts['label'] );
        $redirect_to = $atts['redirect_to'] !== ''
            ? esc_url( $atts['redirect_to'] )
            : '';
        $extra_class = sanitize_html_class( $atts['class'] );

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
                    'notSupported' => __( 'Passkeys are not supported in this browser.', 'wp-passkeys' ),
                    'genericError' => __( 'Passkey sign-in failed. Please try again or use your password.', 'wp-passkeys' ),
                    'signingIn'    => __( 'Signing in…', 'wp-passkeys' ),
                ),
            ) );
        }
        if ( ! wp_style_is( 'wpk-login', 'enqueued' ) ) {
            wp_enqueue_style( 'wpk-login', WPK_PLUGIN_URL . 'admin/css/wpk-admin.css', array(), WPK_VERSION );
        }

        $wrapper_class = 'wpk-shortcode-login-wrap' . ( $extra_class ? ' ' . $extra_class : '' );

        ob_start();
        ?>
        <div class="<?php echo esc_attr( $wrapper_class ); ?>">
            <button type="button"
                    id="wpk-signin-passkey"
                    class="wpk-passkey-btn wpk-sc-btn"
                    aria-label="<?php esc_attr_e( 'Sign in with a passkey (Face ID, Touch ID, or security key)', 'wp-passkeys' ); ?>"
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
            <p id="wpk-passkey-login-message"
               class="wpk-login-message"
               aria-live="polite"
               style="display:none;"></p>
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
        $wpk  = new WPK_Passkeys();

        // Use reflection to access private is_eligible_user().
        // Instead, we expose a static helper below — simpler.
        if ( ! WPK_Passkeys::user_is_eligible( $user ) ) {
            return '';
        }

        $atts = shortcode_atts( array(
            'label' => __( 'Register a Passkey', 'wp-passkeys' ),
            'class' => '',
        ), $atts, 'wpk_register_button' );

        $label       = sanitize_text_field( $atts['label'] );
        $extra_class = sanitize_html_class( $atts['class'] );

        // Enqueue assets if not already queued.
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
        }
        if ( ! wp_style_is( 'wpk-admin', 'enqueued' ) ) {
            wp_enqueue_style( 'wpk-admin', WPK_PLUGIN_URL . 'admin/css/wpk-admin.css', array(), WPK_VERSION );
        }

        $wrapper_class = 'wpk-shortcode-register-wrap' . ( $extra_class ? ' ' . $extra_class : '' );

        ob_start();
        ?>
        <div class="<?php echo esc_attr( $wrapper_class ); ?>">
            <div class="wpk-register-wrap">
                <input type="text"
                       id="wpk-passkey-label"
                       class="wpk-label-input"
                       placeholder="<?php esc_attr_e( 'Device label (optional)', 'wp-passkeys' ); ?>"
                       maxlength="100" />
                <div class="wpk-register-actions">
                    <button type="button" class="wpk-passkey-btn wpk-sc-btn" id="wpk-passkey-register">
                        <?php echo esc_html( $label ); ?>
                    </button>
                    <p id="wpk-passkey-profile-message" class="wpk-inline-message" aria-live="polite"></p>
                </div>
            </div>
        </div>
        <?php
        return ob_get_clean();
    }
}
