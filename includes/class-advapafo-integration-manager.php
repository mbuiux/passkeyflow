<?php
/**
 * Advanced Passkeys for Secure Login integration manager.
 *
 * @package ADVAPAFO
 */

// phpcs:disable WordPress.Files.FileName.InvalidClassFileName -- legacy file naming kept for backward compatibility.
// phpcs:disable Universal.Files.SeparateFunctionsFromOO.Mixed -- file includes one bootstrap helper function for GF lazy registration.

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Adds optional passkey login modules for popular ecosystem plugins.
 */
class ADVAPAFO_Integration_Manager {
	/**
	 * Integration configuration registry.
	 *
	 * @var array<string, array<string, mixed>>
	 */

	private array $registry = array();

	/**
	 * Tracks one-time auto-injection per integration key.
	 *
	 * @var array<string, bool>
	 */
	private array $auto_inject_rendered = array();

	/**
	 * Tracks dynamic blocks registered in the current request.
	 *
	 * @var array<int, array<string, mixed>>
	 */
	private array $registered_blocks = array();

	/**
	 * Constructor.
	 *
	 * @param bool $bootstrap_hooks Whether to register hooks immediately.
	 */
	public function __construct( bool $bootstrap_hooks = true ) {
		$this->registry = $this->build_registry();

		if ( $bootstrap_hooks ) {
			add_action( 'init', array( $this, 'register_integrations' ), 30 );
			add_action( 'enqueue_block_editor_assets', array( $this, 'enqueue_block_editor_assets' ) );
		}
	}

	/**
	 * Return integration labels for currently active integrations.
	 *
	 * @return array<int, string>
	 */
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

	/**
	 * Return integration shortcodes for docs/help views.
	 *
	 * @return array<int, array<string, string>>
	 */
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

	/**
	 * Return settings metadata for each integration.
	 *
	 * @return array<int, array<string, mixed>>
	 */
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

	/**
	 * Build integration configuration registry.
	 *
	 * @return array<string, array<string, mixed>>
	 */
	private function build_registry(): array {
		return array(
			'woocommerce'     => array(
				'master_option'     => 'advapafo_enable_woocommerce_support',
				'default_master'    => 1,
				'dependency_active' => $this->is_woocommerce_active(),
				'shortcode'         => 'advapafo_woocommerce_login',
				'block'             => 'advanced-passkey-login/woocommerce-login-card',
			),
			'edd'             => array(
				'master_option'     => 'advapafo_enable_edd_support',
				'default_master'    => 1,
				'dependency_active' => $this->is_edd_active(),
				'shortcode'         => 'advapafo_edd_login',
				'block'             => 'advanced-passkey-login/edd-login-card',
			),
			'memberpress'     => array(
				'master_option'     => 'advapafo_enable_memberpress_support',
				'default_master'    => 1,
				'dependency_active' => $this->is_memberpress_active(),
				'shortcode'         => 'advapafo_memberpress_login',
				'block'             => 'advanced-passkey-login/memberpress-login-card',
			),
			'ultimate_member' => array(
				'master_option'     => 'advapafo_enable_ultimate_member_support',
				'default_master'    => 1,
				'dependency_active' => $this->is_ultimate_member_active(),
				'shortcode'         => 'advapafo_ultimate_member_login',
				'block'             => 'advanced-passkey-login/ultimate-member-login-card',
			),
			'learndash'       => array(
				'master_option'     => 'advapafo_enable_learndash_support',
				'default_master'    => 1,
				'dependency_active' => $this->is_learndash_active(),
				'shortcode'         => 'advapafo_learndash_login',
				'block'             => 'advanced-passkey-login/learndash-login-card',
			),
			'buddyboss'       => array(
				'master_option'     => 'advapafo_enable_buddyboss_support',
				'default_master'    => 1,
				'dependency_active' => $this->is_buddyboss_active(),
				'shortcode'         => 'advapafo_buddyboss_login',
				'block'             => 'advanced-passkey-login/buddyboss-login-card',
			),
			'gravityforms'    => array(
				'master_option'     => 'advapafo_enable_gravityforms_support',
				'default_master'    => 1,
				'dependency_active' => $this->is_gravityforms_active(),
				'shortcode'         => 'advapafo_gravityforms_login',
				'block'             => 'advanced-passkey-login/gravityforms-login-card',
			),
			'pmp'             => array(
				'master_option'     => 'advapafo_enable_pmp_support',
				'default_master'    => 1,
				'dependency_active' => $this->is_pmp_active(),
				'shortcode'         => 'advapafo_pmp_login',
				'block'             => 'advanced-passkey-login/pmp-login-card',
			),
		);
	}

	/**
	 * Register shortcodes, blocks, and hooks for active integrations.
	 */
	public function register_integrations(): void {
		$this->register_core_blocks();

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

	/**
	 * Register core Advanced Passkeys for Secure Login blocks that do not depend on external integrations.
	 */
	private function register_core_blocks(): void {
		if ( ! function_exists( 'register_block_type' ) ) {
			return;
		}

		$this->register_block_editor_script();

		register_block_type(
			'advanced-passkey-login/login-button',
			array(
				'editor_script'   => 'advapafo-gutenberg-blocks',
				'editor_style'    => 'advapafo-gutenberg-blocks',
				'title'           => __( 'Passkey Login Button', 'advanced-passkey-login' ),
				'category'        => 'widgets',
				'icon'            => 'shield',
				'keywords'        => array( 'passkey', 'login', 'passwordless' ),
				'render_callback' => static function ( $attributes ) {
					$label = isset( $attributes['label'] ) ? sanitize_text_field( (string) $attributes['label'] ) : __( 'Sign in with Passkey', 'advanced-passkey-login' );
					$redirect_to   = isset( $attributes['redirect_to'] ) ? esc_url_raw( (string) $attributes['redirect_to'] ) : '';
					$extra_class   = isset( $attributes['class'] ) ? self::sanitize_class_list( (string) $attributes['class'] ) : '';
					$allow_multiple = ! empty( $attributes['allow_multiple'] ) ? '1' : '0';

					$shortcode = '[advapafo_login_button label="' . esc_attr( $label ) . '" allow_multiple="' . $allow_multiple . '"';
					if ( '' !== $redirect_to ) {
						$shortcode .= ' redirect_to="' . esc_attr( $redirect_to ) . '"';
					}
					if ( '' !== $extra_class ) {
						$shortcode .= ' class="' . esc_attr( $extra_class ) . '"';
					}
					$shortcode .= ']';

					return do_shortcode( $shortcode );
				},
			)
		);

		$this->registered_blocks[] = array(
			'name'             => 'advanced-passkey-login/login-button',
			'title'            => __( 'Passkey Login Button', 'advanced-passkey-login' ),
			'description'      => __( 'Render a passkey sign-in button.', 'advanced-passkey-login' ),
			'label'            => __( 'Sign in with Passkey', 'advanced-passkey-login' ),
			'keywords'         => array( 'passkey', 'login', 'passwordless' ),
			'icon'             => 'shield',
			'category'         => 'widgets',
			'attributes'       => array(
				'label'          => array(
					'type'    => 'string',
					'default' => __( 'Sign in with Passkey', 'advanced-passkey-login' ),
				),
				'redirect_to'    => array(
					'type'    => 'string',
					'default' => '',
				),
				'class'          => array(
					'type'    => 'string',
					'default' => '',
				),
				'allow_multiple' => array(
					'type'    => 'boolean',
					'default' => false,
				),
			),
			'inspector_fields' => array(
				array(
					'name'        => 'label',
					'type'        => 'text',
					'label'       => __( 'Button label', 'advanced-passkey-login' ),
					'placeholder' => __( 'Sign in with Passkey', 'advanced-passkey-login' ),
				),
				array(
					'name'        => 'redirect_to',
					'type'        => 'url',
					'label'       => __( 'Redirect URL', 'advanced-passkey-login' ),
					'placeholder' => home_url( '/' ),
					'help'        => __( 'Optional URL to redirect users after a successful passkey login.', 'advanced-passkey-login' ),
				),
				array(
					'name'        => 'class',
					'type'        => 'text',
					'label'       => __( 'Extra CSS classes', 'advanced-passkey-login' ),
					'placeholder' => __( 'my-custom-class', 'advanced-passkey-login' ),
				),
				array(
					'name'  => 'allow_multiple',
					'type'  => 'toggle',
					'label' => __( 'Allow multiple login buttons on the same page', 'advanced-passkey-login' ),
				),
			),
		);

		register_block_type(
			'advanced-passkey-login/register-button',
			array(
				'editor_script'   => 'advapafo-gutenberg-blocks',
				'editor_style'    => 'advapafo-gutenberg-blocks',
				'title'           => __( 'Passkey Register Button', 'advanced-passkey-login' ),
				'category'        => 'widgets',
				'icon'            => 'shield',
				'keywords'        => array( 'passkey', 'register', 'onboarding' ),
				'render_callback' => static function ( $attributes ) {
					$label       = isset( $attributes['label'] ) ? sanitize_text_field( (string) $attributes['label'] ) : __( 'Register a Passkey', 'advanced-passkey-login' );
					$extra_class = isset( $attributes['class'] ) ? self::sanitize_class_list( (string) $attributes['class'] ) : '';

					$shortcode = '[advapafo_register_button label="' . esc_attr( $label ) . '"';
					if ( '' !== $extra_class ) {
						$shortcode .= ' class="' . esc_attr( $extra_class ) . '"';
					}
					$shortcode .= ']';

					return do_shortcode( $shortcode );
				},
			)
		);

		$this->registered_blocks[] = array(
			'name'             => 'advanced-passkey-login/register-button',
			'title'            => __( 'Passkey Register Button', 'advanced-passkey-login' ),
			'description'      => __( 'Render a passkey registration button for eligible signed-in users.', 'advanced-passkey-login' ),
			'label'            => __( 'Register a Passkey', 'advanced-passkey-login' ),
			'keywords'         => array( 'passkey', 'register', 'onboarding' ),
			'icon'             => 'shield',
			'category'         => 'widgets',
			'attributes'       => array(
				'label' => array(
					'type'    => 'string',
					'default' => __( 'Register a Passkey', 'advanced-passkey-login' ),
				),
				'class' => array(
					'type'    => 'string',
					'default' => '',
				),
			),
			'inspector_fields' => array(
				array(
					'name'        => 'label',
					'type'        => 'text',
					'label'       => __( 'Button label', 'advanced-passkey-login' ),
					'placeholder' => __( 'Register a Passkey', 'advanced-passkey-login' ),
				),
				array(
					'name'        => 'class',
					'type'        => 'text',
					'label'       => __( 'Extra CSS classes', 'advanced-passkey-login' ),
					'placeholder' => __( 'my-custom-class', 'advanced-passkey-login' ),
				),
			),
		);

		register_block_type(
			'advanced-passkey-login/passkey-profile',
			array(
				'editor_script'   => 'advapafo-gutenberg-blocks',
				'editor_style'    => 'advapafo-gutenberg-blocks',
				'title'           => __( 'Account Passkeys', 'advanced-passkey-login' ),
				'category'        => 'widgets',
				'icon'            => 'shield',
				'keywords'        => array( 'passkey', 'profile', 'account' ),
				'render_callback' => static function () {
					return do_shortcode( '[advapafo_passkey_profile]' );
				},
			)
		);

		$this->registered_blocks[] = array(
			'name'             => 'advanced-passkey-login/passkey-profile',
			'title'            => __( 'Account Passkeys', 'advanced-passkey-login' ),
			'description'      => __( 'Render the account passkey management section.', 'advanced-passkey-login' ),
			'label'            => __( 'Manage Passkeys', 'advanced-passkey-login' ),
			'keywords'         => array( 'passkey', 'profile', 'account' ),
			'icon'             => 'shield',
			'category'         => 'widgets',
			'attributes'       => array(),
			'inspector_fields' => array(),
		);

		register_block_type(
			'advanced-passkey-login/setup-prompt',
			array(
				'editor_script'   => 'advapafo-gutenberg-blocks',
				'editor_style'    => 'advapafo-gutenberg-blocks',
				'title'           => __( 'Passkey Setup Prompt', 'advanced-passkey-login' ),
				'category'        => 'widgets',
				'icon'            => 'shield',
				'keywords'        => array( 'passkey', 'security', 'onboarding' ),
				'render_callback' => static function ( $attributes ) {
					$title        = isset( $attributes['title'] ) ? sanitize_text_field( (string) $attributes['title'] ) : __( 'Upgrade your account security with a passkey', 'advanced-passkey-login' );
					$message      = isset( $attributes['message'] ) ? sanitize_text_field( (string) $attributes['message'] ) : __( 'Use Face ID, Touch ID, Windows Hello, or a hardware key for fast passwordless sign-in.', 'advanced-passkey-login' );
					$button_label = isset( $attributes['button_label'] ) ? sanitize_text_field( (string) $attributes['button_label'] ) : __( 'Register a Passkey', 'advanced-passkey-login' );
					$extra_class  = isset( $attributes['class'] ) ? self::sanitize_class_list( (string) $attributes['class'] ) : '';
					$force_show   = ! empty( $attributes['force_show'] ) ? '1' : '0';

					$shortcode  = '[advapafo_passkey_prompt title="' . esc_attr( $title ) . '" message="' . esc_attr( $message ) . '" button_label="' . esc_attr( $button_label ) . '" force_show="' . $force_show . '"';
					if ( '' !== $extra_class ) {
						$shortcode .= ' class="' . esc_attr( $extra_class ) . '"';
					}
					$shortcode .= ']';

					return do_shortcode( $shortcode );
				},
			)
		);

		$this->registered_blocks[] = array(
			'name'             => 'advanced-passkey-login/setup-prompt',
			'title'            => __( 'Passkey Setup Prompt', 'advanced-passkey-login' ),
			'description'      => __( 'Render a passkey onboarding card for eligible logged-in users.', 'advanced-passkey-login' ),
			'label'            => __( 'Register a Passkey', 'advanced-passkey-login' ),
			'keywords'         => array( 'passkey', 'security', 'onboarding' ),
			'icon'             => 'shield',
			'category'         => 'widgets',
			'attributes'       => array(
				'title'        => array(
					'type'    => 'string',
					'default' => __( 'Upgrade your account security with a passkey', 'advanced-passkey-login' ),
				),
				'message'      => array(
					'type'    => 'string',
					'default' => __( 'Use Face ID, Touch ID, Windows Hello, or a hardware key for fast passwordless sign-in.', 'advanced-passkey-login' ),
				),
				'button_label' => array(
					'type'    => 'string',
					'default' => __( 'Register a Passkey', 'advanced-passkey-login' ),
				),
				'class'        => array(
					'type'    => 'string',
					'default' => '',
				),
				'force_show'   => array(
					'type'    => 'boolean',
					'default' => false,
				),
			),
			'inspector_fields' => array(
				array(
					'name'        => 'title',
					'type'        => 'text',
					'label'       => __( 'Card title', 'advanced-passkey-login' ),
					'placeholder' => __( 'Upgrade your account security with a passkey', 'advanced-passkey-login' ),
				),
				array(
					'name'        => 'message',
					'type'        => 'textarea',
					'label'       => __( 'Card message', 'advanced-passkey-login' ),
					'placeholder' => __( 'Use Face ID, Touch ID, Windows Hello, or a hardware key for fast passwordless sign-in.', 'advanced-passkey-login' ),
				),
				array(
					'name'        => 'button_label',
					'type'        => 'text',
					'label'       => __( 'Button label', 'advanced-passkey-login' ),
					'placeholder' => __( 'Register a Passkey', 'advanced-passkey-login' ),
				),
				array(
					'name'        => 'class',
					'type'        => 'text',
					'label'       => __( 'Extra CSS classes', 'advanced-passkey-login' ),
					'placeholder' => __( 'my-custom-class', 'advanced-passkey-login' ),
				),
				array(
					'name'  => 'force_show',
					'type'  => 'toggle',
					'label' => __( 'Force show for administrators (debug)', 'advanced-passkey-login' ),
				),
			),
		);
	}

	/**
	 * Sanitize a user-provided class list for shortcode attributes.
	 *
	 * @param string $raw_class Raw class list.
	 * @return string
	 */
	private static function sanitize_class_list( string $raw_class ): string {
		$parts = preg_split( '/\s+/', trim( $raw_class ) );
		if ( ! is_array( $parts ) ) {
			return '';
		}

		$parts = array_filter(
			array_map( 'sanitize_html_class', $parts ),
			static function ( string $value ): bool {
				return '' !== $value;
			}
		);

		return implode( ' ', $parts );
	}

	/**
	 * Register integration shortcode handler.
	 *
	 * @param string $integration_key Integration key.
	 * @param string $shortcode_tag   Shortcode tag.
	 */
	private function register_shortcode_for_integration( string $integration_key, string $shortcode_tag ): void {
		add_shortcode(
			$shortcode_tag,
			function ( $atts ) use ( $integration_key ) {
				$atts = shortcode_atts(
					array(
						'label'   => __( 'Sign in with Passkey', 'advanced-passkey-login' ),
						'context' => 'manual',
					),
					$atts,
					$integration_key
				);

				$label   = sanitize_text_field( (string) $atts['label'] );
				$context = sanitize_key( (string) $atts['context'] );
				$classes = 'advapafo-integration-passkey advapafo-integration-passkey--' . esc_attr( $integration_key );

				if ( 'auto-inject' === $context ) {
					$classes .= ' advapafo-integration-passkey--auto-inject';
				}

				return '<div class="' . $classes . '">'
					. do_shortcode( '[advapafo_login_button allow_multiple="1" label="' . esc_attr( $label ) . '"]' )
					. '</div>';
			}
		);
	}

	/**
	 * Register integration block type.
	 *
	 * @param string $integration_key Integration key.
	 * @param string $block_name      Block name.
	 * @param string $shortcode_tag   Shortcode tag.
	 */
	private function register_block_for_integration( string $integration_key, string $block_name, string $shortcode_tag ): void {
		if ( ! function_exists( 'register_block_type' ) ) {
			return;
		}

		$this->register_block_editor_script();

		register_block_type(
			$block_name,
			array(
				'editor_script'   => 'advapafo-gutenberg-blocks',
				'editor_style'    => 'advapafo-gutenberg-blocks',
				'title'           => $this->get_integration_block_title( $integration_key ),
				'category'        => 'widgets',
				'icon'            => 'shield',
				'keywords'        => array( 'passkey', 'login', $this->get_integration_label( $integration_key ) ),
				'render_callback' => function ( $attributes ) use ( $shortcode_tag ) {
					$label = isset( $attributes['label'] ) ? sanitize_text_field( (string) $attributes['label'] ) : __( 'Sign in with Passkey', 'advanced-passkey-login' );
					$context = isset( $attributes['context'] ) ? sanitize_key( (string) $attributes['context'] ) : 'manual';
					if ( ! in_array( $context, array( 'manual', 'auto-inject' ), true ) ) {
						$context = 'manual';
					}

					return do_shortcode( '[' . $shortcode_tag . ' label="' . esc_attr( $label ) . '" context="' . esc_attr( $context ) . '"]' );
				},
			)
		);

		$this->registered_blocks[] = array(
			'name'             => $block_name,
			'title'            => $this->get_integration_block_title( $integration_key ),
			'description'      => sprintf(
				/* translators: %s integration label. */
				__( 'Render a passkey sign-in card for %s flows.', 'advanced-passkey-login' ),
				$this->get_integration_label( $integration_key )
			),
			'label'            => __( 'Sign in with Passkey', 'advanced-passkey-login' ),
			'keywords'         => array( 'passkey', 'login', $this->get_integration_label( $integration_key ) ),
			'icon'             => 'shield',
			'category'         => 'widgets',
			'attributes'       => array(
				'label'   => array(
					'type'    => 'string',
					'default' => __( 'Sign in with Passkey', 'advanced-passkey-login' ),
				),
				'context' => array(
					'type'    => 'string',
					'default' => 'manual',
				),
			),
			'inspector_fields' => array(
				array(
					'name'        => 'label',
					'type'        => 'text',
					'label'       => __( 'Button label', 'advanced-passkey-login' ),
					'placeholder' => __( 'Sign in with Passkey', 'advanced-passkey-login' ),
				),
				array(
					'name'    => 'context',
					'type'    => 'select',
					'label'   => __( 'Render context', 'advanced-passkey-login' ),
					'options' => array(
						array(
							'label' => __( 'Manual', 'advanced-passkey-login' ),
							'value' => 'manual',
						),
						array(
							'label' => __( 'Auto-inject styling', 'advanced-passkey-login' ),
							'value' => 'auto-inject',
						),
					),
				),
			),
		);
	}

	/**
	 * Register shared block editor assets.
	 */
	private function register_block_editor_script(): void {
		if ( wp_script_is( 'advapafo-gutenberg-blocks', 'registered' ) ) {
			return;
		}

		wp_register_style(
			'advapafo-gutenberg-blocks',
			ADVAPAFO_PLUGIN_URL . 'admin/css/advapafo-gutenberg-blocks.css',
			array(),
			ADVAPAFO_VERSION
		);

		wp_register_script(
			'advapafo-gutenberg-blocks',
			ADVAPAFO_PLUGIN_URL . 'admin/js/advapafo-gutenberg-blocks.js',
			array( 'wp-blocks', 'wp-element', 'wp-i18n', 'wp-block-editor', 'wp-components' ),
			ADVAPAFO_VERSION,
			true
		);
	}

	/**
	 * Enqueue block editor assets and localized block definitions.
	 */
	public function enqueue_block_editor_assets(): void {
		if ( empty( $this->registered_blocks ) ) {
			return;
		}

		$this->register_block_editor_script();

		wp_localize_script(
			'advapafo-gutenberg-blocks',
			'ADVAPAFOIntegrationBlocks',
			array(
				'blocks' => array_values( $this->registered_blocks ),
			)
		);

		wp_enqueue_style( 'advapafo-gutenberg-blocks' );
		wp_enqueue_script( 'advapafo-gutenberg-blocks' );
	}

	/**
	 * Resolve integration display label.
	 *
	 * @param string $integration_key Integration key.
	 * @return string
	 */
	private function get_integration_label( string $integration_key ): string {
		$labels = array(
			'learndash'       => __( 'LearnDash', 'advanced-passkey-login' ),
			'buddyboss'       => __( 'BuddyBoss', 'advanced-passkey-login' ),
			'gravityforms'    => __( 'Gravity Forms', 'advanced-passkey-login' ),
			'pmp'             => __( 'PMPro', 'advanced-passkey-login' ),
			'woocommerce'     => __( 'WooCommerce', 'advanced-passkey-login' ),
			'edd'             => __( 'Easy Digital Downloads', 'advanced-passkey-login' ),
			'memberpress'     => __( 'MemberPress', 'advanced-passkey-login' ),
			'ultimate_member' => __( 'Ultimate Member', 'advanced-passkey-login' ),
		);

		return $labels[ $integration_key ] ?? __( 'Integration', 'advanced-passkey-login' );
	}

	/**
	 * Build integration block title.
	 *
	 * @param string $integration_key Integration key.
	 * @return string
	 */
	private function get_integration_block_title( string $integration_key ): string {
		return sprintf(
			/* translators: %s integration label. */
			__( '%s Passkey Login', 'advanced-passkey-login' ),
			$this->get_integration_label( $integration_key )
		);
	}

	/**
	 * Register automatic injection hooks for an integration.
	 *
	 * @param string $integration_key Integration key.
	 */
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

	/**
	 * Inject LearnDash passkey prompt into supported content.
	 *
	 * @param string $content Post content.
	 * @return string
	 */
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

		$button = do_shortcode( '[advapafo_learndash_login]' );
		if ( '' === trim( $button ) ) {
			return $content;
		}

		return $button . $content;
	}

	/**
	 * Render BuddyBoss auto-injected passkey prompt.
	 */
	public function render_buddyboss_auto_inject(): void {
		$this->render_integration_auto_inject( 'buddyboss', '[advapafo_buddyboss_login]' );
	}

	/**
	 * Render WooCommerce auto-injected passkey prompt.
	 */
	public function render_woocommerce_auto_inject(): void {
		$this->render_integration_auto_inject( 'woocommerce', '[advapafo_woocommerce_login]' );
	}

	/**
	 * Render EDD auto-injected passkey prompt.
	 */
	public function render_edd_auto_inject(): void {
		$this->render_integration_auto_inject( 'edd', '[advapafo_edd_login]' );
	}

	/**
	 * Render MemberPress auto-injected passkey prompt.
	 */
	public function render_memberpress_auto_inject(): void {
		$this->render_integration_auto_inject( 'memberpress', '[advapafo_memberpress_login]' );
	}

	/**
	 * Render Ultimate Member auto-injected passkey prompt.
	 */
	public function render_ultimate_member_auto_inject(): void {
		$this->render_integration_auto_inject( 'ultimate_member', '[advapafo_ultimate_member_login]' );
	}

	/**
	 * Render Paid Memberships Pro auto-injected passkey prompt.
	 */
	public function render_pmp_auto_inject(): void {
		$this->render_integration_auto_inject( 'pmp', '[advapafo_pmp_login]' );
	}

	/**
	 * Render Gravity Forms auto-injected passkey prompt.
	 *
	 * @param mixed $form Form array from Gravity Forms.
	 * @param bool  $ajax Ajax render context.
	 */
	public function render_gravityforms_auto_inject( $form, bool $ajax ): void {
		unset( $ajax );

		if ( ! $this->should_auto_inject_for_integration( 'gravityforms' ) ) {
			return;
		}

		if ( ! $this->is_gravityforms_login_like_form( $form ) ) {
			return;
		}

		$output = do_shortcode( '[advapafo_gravityforms_login]' );
		if ( '' === trim( $output ) ) {
			return;
		}

		echo wp_kses_post( $output );
	}

	/**
	 * Render integration shortcode output when auto-injection applies.
	 *
	 * @param string $integration_key Integration key.
	 * @param string $shortcode       Base shortcode.
	 */
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
		echo wp_kses_post( $output );
	}

	/**
	 * Check whether auto-injection should run for an integration.
	 *
	 * @param string $integration_key Integration key.
	 * @return bool
	 */
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

	/**
	 * Check whether a master integration toggle is enabled.
	 *
	 * @param string $option_key    Option key.
	 * @param int    $default_value Default option value.
	 * @return bool
	 */
	private function is_master_enabled( string $option_key, int $default_value = 0 ): bool {
		return (int) get_option( $option_key, $default_value ) === 1;
	}

	/**
	 * Register Gravity Forms custom field bootstrap hook.
	 */
	private function register_gravityforms_field_support(): void {
		add_action( 'gform_loaded', array( $this, 'register_gravityforms_field' ), 20 );
	}

	/**
	 * Register Gravity Forms passkey field type.
	 */
	public function register_gravityforms_field(): void {
		if ( ! class_exists( 'GF_Field' ) || ! class_exists( 'GF_Fields' ) ) {
			return;
		}

		advapafo_register_gravityforms_passkey_field_class();
		if ( ! class_exists( 'ADVAPAFO_GF_Field_Passkey' ) ) {
			return;
		}

		GF_Fields::register( new ADVAPAFO_GF_Field_Passkey() );
	}

	/**
	 * Determine whether a Gravity Form appears login-like.
	 *
	 * @param mixed $form Gravity Forms payload.
	 * @return bool
	 */
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

	/**
	 * Check dependency state for a given integration key.
	 *
	 * @param string $integration_key Integration key.
	 * @return bool
	 */
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

	/**
	 * Check LearnDash dependency availability.
	 *
	 * @return bool
	 */
	private function is_learndash_active(): bool {
		return defined( 'LEARNDASH_VERSION' ) || class_exists( 'SFWD_LMS' );
	}

	/**
	 * Check BuddyBoss dependency availability.
	 *
	 * @return bool
	 */
	private function is_buddyboss_active(): bool {
		return defined( 'BUDDYBOSS_PLATFORM_VERSION' )
			|| class_exists( 'BuddyBossPlatform' )
			|| defined( 'BP_VERSION' )
			|| function_exists( 'buddypress' );
	}

	/**
	 * Check Gravity Forms dependency availability.
	 *
	 * @return bool
	 */
	private function is_gravityforms_active(): bool {
		return class_exists( 'GFForms' );
	}

	/**
	 * Check Paid Memberships Pro dependency availability.
	 *
	 * @return bool
	 */
	private function is_pmp_active(): bool {
		return defined( 'PMPRO_VERSION' ) || function_exists( 'pmpro_getOption' );
	}

	/**
	 * Check WooCommerce dependency availability.
	 *
	 * @return bool
	 */
	private function is_woocommerce_active(): bool {
		return class_exists( 'WooCommerce' );
	}

	/**
	 * Check Easy Digital Downloads dependency availability.
	 *
	 * @return bool
	 */
	private function is_edd_active(): bool {
		return class_exists( 'Easy_Digital_Downloads' ) || defined( 'EDD_VERSION' );
	}

	/**
	 * Check MemberPress dependency availability.
	 *
	 * @return bool
	 */
	private function is_memberpress_active(): bool {
		return class_exists( 'MeprAppCtrl' );
	}

	/**
	 * Check Ultimate Member dependency availability.
	 *
	 * @return bool
	 */
	private function is_ultimate_member_active(): bool {
		return class_exists( 'UM' ) || function_exists( 'UM' );
	}
}

/**
 * Register Gravity Forms custom field class lazily after GF loads.
 */
function advapafo_register_gravityforms_passkey_field_class(): void {
	// phpcs:disable Universal.Files.SeparateFunctionsFromOO.Mixed,Generic.Files.OneObjectStructurePerFile.MultipleFound
	if ( ! class_exists( 'GF_Field' ) || class_exists( 'ADVAPAFO_GF_Field_Passkey' ) ) {
		return;
	}

	/**
	 * Gravity Forms field that renders the passkey login control.
	 */
	class ADVAPAFO_GF_Field_Passkey extends GF_Field {
		/**
		 * Gravity Forms field type key.
		 *
		 * @var string
		 */
		public $type = 'passkey';

		/**
		 * Get form editor field title.
		 *
		 * @return string
		 */
		public function get_form_editor_field_title() {
			return esc_attr__( 'Passkey Field', 'advanced-passkey-login' );
		}

		/**
		 * Get form editor button config.
		 *
		 * @return array<string, string>
		 */
		public function get_form_editor_button() {
			return array(
				'group' => 'advanced_fields',
				'text'  => $this->get_form_editor_field_title(),
			);
		}

		/**
		 * Get form editor field description.
		 *
		 * @return string
		 */
		public function get_form_editor_field_description() {
			return esc_html__( 'Renders a passkey sign-in control for Gravity Forms-powered flows.', 'advanced-passkey-login' );
		}

		/**
		 * Get field settings exposed in the editor.
		 *
		 * @return array<int, string>
		 */
		public function get_form_editor_field_settings() {
			return array( 'label_setting', 'description_setting' );
		}

		/**
		 * Render frontend field input markup.
		 *
		 * @param mixed $form  Form payload.
		 * @param mixed $value Field value.
		 * @param mixed $entry Entry payload.
		 * @return string
		 */
		public function get_field_input( $form, $value = '', $entry = null ) {
			unset( $form, $value, $entry );
			return do_shortcode( '[advapafo_gravityforms_login]' );
		}
	}
	// phpcs:enable Universal.Files.SeparateFunctionsFromOO.Mixed,Generic.Files.OneObjectStructurePerFile.MultipleFound
}
