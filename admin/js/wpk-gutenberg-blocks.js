(function (wp) {
    if (!wp || !wp.blocks || !wp.element || !wp.i18n || !wp.blockEditor) {
        return;
    }

    var registerBlockType = wp.blocks.registerBlockType;
    var createElement = wp.element.createElement;
    var __ = wp.i18n.__;
    var InspectorControls = wp.blockEditor.InspectorControls;
    var RichText = wp.blockEditor.RichText;

    var registry = (window.WPKIntegrationBlocks && Array.isArray(window.WPKIntegrationBlocks.blocks))
        ? window.WPKIntegrationBlocks.blocks
        : [];

    if (!registry.length) {
        return;
    }

    registry.forEach(function (blockConfig) {
        if (!blockConfig || !blockConfig.name) {
            return;
        }

        registerBlockType(blockConfig.name, {
            title: blockConfig.title || __('Passkey Login', 'passkeyflow'),
            description: blockConfig.description || __('Render a passkey sign-in control.', 'passkeyflow'),
            icon: blockConfig.icon || 'shield',
            category: blockConfig.category || 'widgets',
            keywords: Array.isArray(blockConfig.keywords) ? blockConfig.keywords : ['passkey', 'login'],
            attributes: {
                label: {
                    type: 'string',
                    default: blockConfig.label || __('Sign in with Passkey', 'passkeyflow')
                }
            },
            edit: function (props) {
                var label = props.attributes.label || blockConfig.label || __('Sign in with Passkey', 'passkeyflow');

                return createElement(
                    'div',
                    { className: 'wpk-block-editor-card' },
                    createElement(
                        InspectorControls,
                        null,
                        createElement(
                            'div',
                            { className: 'components-panel__body is-opened', style: { padding: '12px' } },
                            createElement('strong', null, __('Passkey button label', 'passkeyflow')),
                            createElement(RichText, {
                                tagName: 'p',
                                value: label,
                                onChange: function (newLabel) {
                                    props.setAttributes({ label: newLabel });
                                },
                                placeholder: __('Sign in with Passkey', 'passkeyflow'),
                                allowedFormats: []
                            })
                        )
                    ),
                    createElement('p', { className: 'wpk-block-editor-card__title' }, blockConfig.title || __('Passkey Login', 'passkeyflow')),
                    createElement('p', { className: 'wpk-block-editor-card__hint' }, __('Preview of the passkey CTA shown for this integration.', 'passkeyflow')),
                    createElement('button', {
                        type: 'button',
                        className: 'button button-primary',
                        disabled: true
                    }, label)
                );
            },
            save: function () {
                return null;
            }
        });
    });
})(window.wp);
