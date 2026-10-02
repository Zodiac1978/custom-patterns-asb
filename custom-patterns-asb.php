<?php
/**
 * Plugin Name: Custom Patterns for Antispam Bee
 * Description: Add custom patterns for Antispam Bee.
 * Plugin URI:  https://torstenlandsiedel.de
 * Version:     1.5.0
 * Author:      Torsten Landsiedel
 * Author URI:  https://torstenlandsiedel.de
 * Requires PHP: 8.0
 * License:     GPL v2 or later
 * License URI: https://www.gnu.org/licenses/gpl-2.0.html
 * Update URI:  https://github.com/Zodiac1978/custom-patterns-asb
 * GitHub Plugin URI: https://github.com/Zodiac1978/custom-patterns-asb
 * Text Domain: custom-patterns-asb
 * Domain Path: /languages
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit; // Exit if accessed directly.
}

/**
 * Name of the option containing the enabled pattern IDs.
 */
const CUSTOM_PATTERNS_ASB_OPTION = 'custom_patterns_asb_enabled_patterns';

add_filter( 'antispam_bee_patterns', 'antispam_bee_add_custom_patterns' );
add_action( 'admin_init', 'custom_patterns_asb_register_settings' );
add_action( 'admin_menu', 'custom_patterns_asb_add_settings_page' );

/**
 * Return all patterns provided by this plugin, including their UI metadata.
 *
 * A pattern containing multiple fields uses Antispam Bee's AND semantics.
 *
 * @return array<string, array{label: string, description: string, pattern: array<string, string>}>
 */
function custom_patterns_asb_get_pattern_definitions() {
	return array(
		'two-uppercase-letters' => array(
			'label'       => __( 'Exactly two uppercase letters', 'custom-patterns-asb' ),
			'description' => __( 'Detects comments whose content consists of exactly two ASCII uppercase letters.', 'custom-patterns-asb' ),
			'pattern'     => array( 'body' => '^(?-i:[A-Z]{2})$' ),
		),
		'spam-email-providers' => array(
			'label'       => __( 'Mail.ru and Yandex addresses', 'custom-patterns-asb' ),
			'description' => __( 'Blocks email addresses from Mail.ru and selected Yandex domains.', 'custom-patterns-asb' ),
			'pattern'     => array( 'email' => '@(?:mail\.ru|yandex\.(?:ru|com|by|kz))$' ),
		),
		'ru-bid-email-domains' => array(
			'label'       => __( 'Email domains ending in .ru or .bid', 'custom-patterns-asb' ),
			'description' => __( 'Detects email addresses using the .ru or .bid top-level domain.', 'custom-patterns-asb' ),
			'pattern'     => array( 'email' => '^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.(?:ru|bid)$' ),
		),
		'numbered-adult-domain-author' => array(
			'label'       => __( 'Adult domain in the author name', 'custom-patterns-asb' ),
			'description' => __( 'Detects domains such as xxx123.top or sex123.xyz in the author name.', 'custom-patterns-asb' ),
			'pattern'     => array( 'author' => '(xxx|sex)(\d\d\d)\.(top|xyz)' ),
		),
		'numbered-adult-domain-email' => array(
			'label'       => __( 'Adult domain in the email address', 'custom-patterns-asb' ),
			'description' => __( 'Detects domains such as xxx123.top or sex123.xyz in the email address.', 'custom-patterns-asb' ),
			'pattern'     => array( 'email' => '(xxx|sex)(\d\d\d)\.(top|xyz)' ),
		),
		'numbered-adult-domain-host' => array(
			'label'       => __( 'Adult domain in the website', 'custom-patterns-asb' ),
			'description' => __( 'Detects domains such as xxx123.top or sex123.xyz in the submitted website.', 'custom-patterns-asb' ),
			'pattern'     => array( 'host' => '(xxx|sex)(\d\d\d)\.(top|xyz)' ),
		),
		'numbered-adult-domain-body' => array(
			'label'       => __( 'Adult domain in the comment', 'custom-patterns-asb' ),
			'description' => __( 'Detects domains such as xxx123.top or sex123.xyz in the comment text.', 'custom-patterns-asb' ),
			'pattern'     => array( 'body' => '(xxx|sex)(\d\d\d)\.(top|xyz)' ),
		),
		'random-letter-strings' => array(
			'label'       => __( 'Random letter strings', 'custom-patterns-asb' ),
			'description' => __( 'Detects 30 lowercase letters in the comment together with 10 or 11 lowercase letters in the author name.', 'custom-patterns-asb' ),
			'pattern'     => array(
				'body'   => '^[a-z]{30}$',
				'author' => '^[a-z]{10,11}$',
			),
		),
		'clickbank-link' => array(
			'label'       => __( 'ClickBank affiliate link', 'custom-patterns-asb' ),
			'description' => __( 'Detects ClickBank affiliate links using the link text “click here”.', 'custom-patterns-asb' ),
			'pattern'     => array( 'body' => '<a\b[^>]*href=["\']https?:\/\/[^"\']+\.hop\.clickbank\.net[^"\']*["\'][^>]*>\s*click here\s*<\/a>' ),
		),
		'weight-loss-template' => array(
			'label'       => __( 'Weight-loss advertisement', 'custom-patterns-asb' ),
			'description' => __( 'Detects recurring English weight-loss advertisements with a call-to-action link.', 'custom-patterns-asb' ),
			'pattern'     => array( 'body' => '\b(?:weight loss|excess weight)\b.{0,700}\b(?:\d+\s*kg|game-changer)\b.{0,700}<a\b[^>]*>\s*click here\s*<\/a>' ),
		),
		'post-summary-template' => array(
			'label'       => __( 'Generic post-summary comment', 'custom-patterns-asb' ),
			'description' => __( 'Detects English post-summary comments containing “for more details” and a call-to-action link.', 'custom-patterns-asb' ),
			'pattern'     => array( 'body' => '\b(?:your|this) post\b.{0,350}\bfor more details\b.{0,150}<a\b[^>]*>\s*click here\s*<\/a>' ),
		),
		'elavil-domain' => array(
			'label'       => __( 'Elavil spam domain', 'custom-patterns-asb' ),
			'description' => __( 'Detects Elavil advertisements when they originate from the repeatedly observed domain.', 'custom-patterns-asb' ),
			'pattern'     => array(
				'body' => '\belavil\b',
				'host' => '^(?:https?:\/\/)?(?:www\.)?elavil365y\.com(?:\/|$)',
			),
		),
		'host-without-dot' => array(
			'label'       => __( 'Website without a dot in its hostname', 'custom-patterns-asb' ),
			'description' => __( 'Detects invalid author websites whose hostname does not contain a dot.', 'custom-patterns-asb' ),
			'pattern'     => array( 'host' => '^(?:https?:\/\/)?[^.\/\s]+\/?$' ),
		),
		'numeric-author' => array(
			'label'       => __( 'Numeric-only author name', 'custom-patterns-asb' ),
			'description' => __( 'Detects author names consisting of at least five digits and nothing else.', 'custom-patterns-asb' ),
			'pattern'     => array( 'author' => '^\d{5,}$' ),
		),
		'buy-link' => array(
			'label'       => __( 'Purchase solicitation with a link', 'custom-patterns-asb' ),
			'description' => __( 'Detects English purchase solicitations that also contain an HTML link.', 'custom-patterns-asb' ),
			'pattern'     => array( 'body' => '^(?=.*\bbuy\b)(?=.*<a\b)' ),
		),
		'pharma-email' => array(
			'label'       => __( 'Pharmaceutical and casino terms in the email address', 'custom-patterns-asb' ),
			'description' => __( 'Detects Viagra, Cialis, or Casino in the email address.', 'custom-patterns-asb' ),
			'pattern'     => array( 'email' => 'viagra|(?<!spe)cialis|casino' ),
		),
		'pharma-host' => array(
			'label'       => __( 'Pharmaceutical and casino terms in the website', 'custom-patterns-asb' ),
			'description' => __( 'Detects Viagra, Cialis, or Casino in the submitted website.', 'custom-patterns-asb' ),
			'pattern'     => array( 'host' => 'viagra|(?<!spe)cialis|casino' ),
		),
		'traffic-pharma-body' => array(
			'label'       => __( 'Traffic and pharmaceutical terms in the comment', 'custom-patterns-asb' ),
			'description' => __( 'Detects common English traffic advertisements as well as Viagra or Cialis in the comment text.', 'custom-patterns-asb' ),
			'pattern'     => array( 'body' => 'target[t]?ed (?:visitors|traffic)|viagra|(?<!spe)cialis' ),
		),
		'three-links' => array(
			'label'       => __( 'At least three links', 'custom-patterns-asb' ),
			'description' => __( 'Detects comments containing at least three HTTP(S) or FTP(S) links.', 'custom-patterns-asb' ),
			'pattern'     => array( 'body' => '(?:https?|ftps?):\/\/.*?(?:https?|ftps?):\/\/.*?(?:https?|ftps?):\/\/' ),
		),
		'non-latin-characters' => array(
			'label'       => __( 'Non-Latin characters', 'custom-patterns-asb' ),
			'description' => __( 'Detects numerous non-Latin writing systems, including Cyrillic, Arabic, and Japanese.', 'custom-patterns-asb' ),
			'pattern'     => array( 'body' => '\p{Arabic}|\p{Armenian}|\p{Bengali}|\p{Bopomofo}|\p{Braille}|\p{Buhid}|\p{Canadian_Aboriginal}|\p{Cherokee}|\p{Cyrillic}|\p{Devanagari}|\p{Ethiopic}|\p{Georgian}|\p{Greek}|\p{Gujarati}|\p{Gurmukhi}|\p{Han}|\p{Hangul}|\p{Hanunoo}|\p{Hebrew}|\p{Hiragana}|\p{Kannada}|\p{Katakana}|\p{Khmer}|\p{Lao}|\p{Limbu}|\p{Malayalam}|\p{Mongolian}|\p{Myanmar}|\p{Ogham}|\p{Oriya}|\p{Runic}|\p{Sinhala}|\p{Syriac}|\p{Tagalog}|\p{Tagbanwa}|\p{Tamil}|\p{Telugu}|\p{Thaana}|\p{Thai}|\p{Tibetan}|\p{Yi}' ),
		),
	);
}

/**
 * Return the IDs of the enabled patterns.
 *
 * All patterns are enabled until the settings have been saved for the first
 * time, preserving the plugin's behavior after an update.
 *
 * @return string[]
 */
function custom_patterns_asb_get_enabled_pattern_ids() {
	$definitions = custom_patterns_asb_get_pattern_definitions();
	$enabled     = get_option( CUSTOM_PATTERNS_ASB_OPTION, null );

	if ( null === $enabled ) {
		return array_keys( $definitions );
	}

	return custom_patterns_asb_sanitize_enabled_patterns( $enabled );
}

/**
 * Allow only IDs that belong to current plugin patterns.
 *
 * @param mixed $value Submitted option value.
 * @return string[]
 */
function custom_patterns_asb_sanitize_enabled_patterns( $value ) {
	if ( ! is_array( $value ) ) {
		return array();
	}

	$submitted = array_map( 'sanitize_key', $value );
	$known_ids = array_keys( custom_patterns_asb_get_pattern_definitions() );

	// array_intersect keeps the stable order used on the settings page.
	return array_values( array_intersect( $known_ids, $submitted ) );
}

/**
 * Add the enabled custom RegExp patterns to Antispam Bee.
 *
 * @param array $patterns All RegExp patterns from Antispam Bee.
 * @return array All RegExp patterns including the enabled custom patterns.
 */
function antispam_bee_add_custom_patterns( $patterns ) {
	$enabled = custom_patterns_asb_get_enabled_pattern_ids();

	foreach ( custom_patterns_asb_get_pattern_definitions() as $id => $definition ) {
		if ( in_array( $id, $enabled, true ) ) {
			$patterns[] = $definition['pattern'];
		}
	}

	return $patterns;
}

/**
 * Register the plugin option with the WordPress Settings API.
 */
function custom_patterns_asb_register_settings() {
	register_setting(
		'custom_patterns_asb',
		CUSTOM_PATTERNS_ASB_OPTION,
		array(
			'type'              => 'array',
			'sanitize_callback' => 'custom_patterns_asb_sanitize_enabled_patterns',
			'default'           => array_keys( custom_patterns_asb_get_pattern_definitions() ),
		)
	);
}

/**
 * Add the settings submenu page.
 */
function custom_patterns_asb_add_settings_page() {
	add_options_page(
		__( 'Custom Patterns for Antispam Bee', 'custom-patterns-asb' ),
		__( 'Antispam Bee Patterns', 'custom-patterns-asb' ),
		'manage_options',
		'custom-patterns-asb',
		'custom_patterns_asb_render_settings_page'
	);
}

/**
 * Render the settings page.
 */
function custom_patterns_asb_render_settings_page() {
	if ( ! current_user_can( 'manage_options' ) ) {
		return;
	}

	$definitions = custom_patterns_asb_get_pattern_definitions();
	$enabled     = custom_patterns_asb_get_enabled_pattern_ids();
	?>
	<div class="wrap">
		<h1><?php echo esc_html( get_admin_page_title() ); ?></h1>
		<?php settings_errors(); ?>
		<p><?php esc_html_e( 'Select the patterns that Antispam Bee should additionally use for spam detection. Patterns with multiple fields match only when all listed conditions are met.', 'custom-patterns-asb' ); ?></p>
		<style>
			.custom-patterns-asb-table th:first-child { width: 4em; }
			.custom-patterns-asb-table td { vertical-align: top; }
			.custom-patterns-asb-table code { overflow-wrap: anywhere; word-break: break-word; }
		</style>
		<form action="options.php" method="post">
			<?php settings_fields( 'custom_patterns_asb' ); ?>
			<input type="hidden" name="<?php echo esc_attr( CUSTOM_PATTERNS_ASB_OPTION ); ?>[]" value="">
			<table class="widefat striped custom-patterns-asb-table">
				<thead>
					<tr>
						<th scope="col"><?php esc_html_e( 'Enabled', 'custom-patterns-asb' ); ?></th>
						<th scope="col"><?php esc_html_e( 'Pattern', 'custom-patterns-asb' ); ?></th>
						<th scope="col"><?php esc_html_e( 'Field and regular expression', 'custom-patterns-asb' ); ?></th>
					</tr>
				</thead>
				<tbody>
					<?php foreach ( $definitions as $id => $definition ) : ?>
						<tr>
							<td>
								<label>
									<input
										type="checkbox"
										name="<?php echo esc_attr( CUSTOM_PATTERNS_ASB_OPTION ); ?>[]"
										value="<?php echo esc_attr( $id ); ?>"
										<?php checked( in_array( $id, $enabled, true ) ); ?>
									>
									<span class="screen-reader-text">
										<?php
										/* translators: %s: Pattern name. */
										echo esc_html( sprintf( __( 'Enable “%s”', 'custom-patterns-asb' ), $definition['label'] ) );
										?>
									</span>
								</label>
							</td>
							<td>
								<strong><?php echo esc_html( $definition['label'] ); ?></strong>
								<p class="description"><?php echo esc_html( $definition['description'] ); ?></p>
							</td>
							<td>
								<?php foreach ( $definition['pattern'] as $field => $regexp ) : ?>
									<div><strong><?php echo esc_html( custom_patterns_asb_get_field_label( $field ) ); ?>:</strong> <code><?php echo esc_html( $regexp ); ?></code></div>
								<?php endforeach; ?>
							</td>
						</tr>
					<?php endforeach; ?>
				</tbody>
			</table>
			<?php submit_button( __( 'Save selection', 'custom-patterns-asb' ) ); ?>
		</form>
	</div>
	<?php
}

/**
 * Return the UI label for an Antispam Bee pattern field.
 *
 * @param string $field Pattern field key.
 * @return string
 */
function custom_patterns_asb_get_field_label( $field ) {
	$labels = array(
		'author' => __( 'Author name', 'custom-patterns-asb' ),
		'body'   => __( 'Comment', 'custom-patterns-asb' ),
		'email'  => __( 'Email address', 'custom-patterns-asb' ),
		'host'   => __( 'Website', 'custom-patterns-asb' ),
	);

	return isset( $labels[ $field ] ) ? $labels[ $field ] : $field;
}
