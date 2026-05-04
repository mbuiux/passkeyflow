<?php
/**
 * WPK_Login_Form — injects the passkey button into wp-login.php
 * and stores any redirect_to cookie for post-login handling.
 */

if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

class WPK_Login_Form {

    public function __construct() {
        add_action( 'login_form',  array( $this, 'render_passkey_button' ) );
        add_action( 'login_init',  array( $this, 'store_redirect_cookie' ) );
    }

    /**
     * Renders the "Sign in with Passkey" button below the default login form.
     * Only shown when the WebAuthn library is available and passkeys are enabled.
     */
    public function render_passkey_button(): void {
        if ( ! class_exists( 'WPK_Passkeys' ) || ! WPK_Passkeys::is_enabled() ) {
            return;
        }

        if ( ! class_exists( 'lbuchs\\WebAuthn\\WebAuthn' ) ) {
            return;
        }

        $show_sep = (int) get_option( 'wpk_show_separator', 1 ) === 1;

        ?>

        <div id="wpk-login-passkey-block">
            <?php if ( $show_sep ) : ?>
            <div class="wpk-login-separator" role="separator" aria-label="<?php esc_attr_e( 'or', 'passkeyflow' ); ?>">
                <span><?php esc_html_e( 'OR', 'passkeyflow' ); ?></span>
            </div>
            <?php endif; ?>

            <div class="<?php echo esc_attr( 'wpk-login-passkey-wrap' . ( $show_sep ? '' : ' wpk-no-separator' ) ); ?>">
                <button type="button"
                        id="wpk-signin-passkey"
                        class="button button-large wpk-passkey-btn"
                        aria-label="<?php esc_attr_e( 'Sign in with a passkey (Face ID, Touch ID, or security key)', 'passkeyflow' ); ?>">
                    <span class="wpk-passkey-icon" aria-hidden="true">
                        <svg xmlns="http://www.w3.org/2000/svg" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                            <path d="M12.4 2.7a2.5 2.5 0 0 1 3.4 0l5.5 5.5a2.5 2.5 0 0 1 0 3.4l-3.7 3.7a2.5 2.5 0 0 1-3.4 0L8.7 9.8a2.5 2.5 0 0 1 0-3.4z"/>
                            <path d="m14 7 3 3"/>
                            <path d="m9.4 10.6-6.814 6.814A2 2 0 0 0 2 18.828V21a1 1 0 0 0 1 1h3a1 1 0 0 0 1-1v-1a1 1 0 0 1 1-1h1a1 1 0 0 0 1-1v-1a1 1 0 0 1 1-1h.172a2 2 0 0 0 1.414-.586l.814-.814"/>
                        </svg>
                    </span>
                    <?php esc_html_e( 'Sign in with Passkey', 'passkeyflow' ); ?>
                </button>
                <p id="wpk-passkey-login-message"
                   class="wpk-login-message wpk-is-hidden"
                   aria-live="polite"
                   ></p>
            </div>
        </div>
        <?php
    }

    /**
     * Stores the redirect_to parameter as a short-lived httponly cookie so the
     * passkey AJAX login handler can honour it without JS state.
     */
    public function store_redirect_cookie(): void {
        if ( ! isset( $_GET['redirect_to'] ) ) { // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- read-only redirect hint capture, no stateful privileged action.
            return;
        }

        $redirect_raw = wp_unslash( $_GET['redirect_to'] ); // phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- sanitized via esc_url_raw/wp_validate_redirect.
        if ( ! is_string( $redirect_raw ) ) {
            return;
        }

        $redirect = wp_validate_redirect( esc_url_raw( $redirect_raw ), '' );
        if ( $redirect === '' ) {
            return;
        }

        setcookie( 'wpk_redirect_to', $redirect, array(
            'expires'  => time() + 3600,
            'path'     => defined( 'COOKIEPATH' )   ? (string) COOKIEPATH   : '/',
            'domain'   => defined( 'COOKIE_DOMAIN' ) ? (string) COOKIE_DOMAIN : '',
            'secure'   => is_ssl(),
            'httponly' => true,
            'samesite' => 'Lax',
        ) );
    }
}
