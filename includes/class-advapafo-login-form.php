<?php
// phpcs:ignoreFile WordPress.Files.FileName.InvalidClassFileName -- legacy file naming kept for backward compatibility.
/**
 * ADVAPAFO_Login_Form — injects the passkey button into wp-login.php.
 *
 * @package ADVAPAFO
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Renders passkey controls on the default WordPress login form.
 */
class ADVAPAFO_Login_Form {
	/**
	 * Register login form hooks.
	 */

	public function __construct() {
		add_action( 'login_form', array( $this, 'render_passkey_button' ) );
	}

	/**
	 * Renders the "Sign in with Passkey" button below the default login form.
	 * Only shown when the WebAuthn library is available and passkeys are enabled.
	 */
	public function render_passkey_button(): void {
		if ( ! class_exists( 'ADVAPAFO_Passkeys' ) || ! ADVAPAFO_Passkeys::is_enabled() ) {
			return;
		}

		if ( ! class_exists( 'lbuchs\\WebAuthn\\WebAuthn' ) ) {
			return;
		}

		$show_sep = (int) get_option( 'advapafo_show_separator', 1 ) === 1;

		?>

		<div id="advapafo-login-passkey-block">
			<?php if ( $show_sep ) : ?>
			<div class="advapafo-login-separator" role="separator" aria-label="<?php esc_attr_e( 'or', 'advanced-passkey-login' ); ?>">
				<span><?php esc_html_e( 'OR', 'advanced-passkey-login' ); ?></span>
			</div>
			<?php endif; ?>

			<div class="<?php echo esc_attr( 'advapafo-login-passkey-wrap' . ( $show_sep ? '' : ' advapafo-no-separator' ) ); ?>">
				<button type="button"
						id="advapafo-signin-passkey"
						class="button button-large advapafo-passkey-btn"
						aria-label="<?php esc_attr_e( 'Sign in with a passkey (Face ID, Touch ID, or security key)', 'advanced-passkey-login' ); ?>">
					<span class="advapafo-passkey-icon" aria-hidden="true">
						<svg xmlns="http://www.w3.org/2000/svg" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
							<path d="M12.4 2.7a2.5 2.5 0 0 1 3.4 0l5.5 5.5a2.5 2.5 0 0 1 0 3.4l-3.7 3.7a2.5 2.5 0 0 1-3.4 0L8.7 9.8a2.5 2.5 0 0 1 0-3.4z"/>
							<path d="m14 7 3 3"/>
							<path d="m9.4 10.6-6.814 6.814A2 2 0 0 0 2 18.828V21a1 1 0 0 0 1 1h3a1 1 0 0 0 1-1v-1a1 1 0 0 1 1-1h1a1 1 0 0 0 1-1v-1a1 1 0 0 1 1-1h.172a2 2 0 0 0 1.414-.586l.814-.814"/>
						</svg>
					</span>
					<?php esc_html_e( 'Sign in with Passkey', 'advanced-passkey-login' ); ?>
				</button>
				<p id="advapafo-passkey-login-message"
					class="advapafo-login-message advapafo-is-hidden"
					aria-live="polite"
					></p>
			</div>
		</div>
		<?php
	}

}
