<?php
/**
 * Plugin Name: Custom Patterns for Antispam Bee
 * Description: Add custom patterns for Antispam Bee.
 * Plugin URI:  https://torstenlandsiedel.de
 * Version:     1.4.1
 * Author:      Torsten Landsiedel
 * Author URI:  https://torstenlandsiedel.de
 * Requires PHP: 8.0
 * License:     GPL v2 or later
 * License URI: https://www.gnu.org/licenses/gpl-2.0.html
 * Update URI:  https://github.com/Zodiac1978/custom-patterns-asb
 * GitHub Plugin URI: https://github.com/Zodiac1978/custom-patterns-asb
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit; // Exit if accessed directly.
}

/**
 * Antispam Bee filter for custom RegExp patterns
 */
add_filter( 'antispam_bee_patterns', 'antispam_bee_add_custom_patterns' );

/**
 * Add more RegExp patterns
 *
 * @param array $patterns All RegExp patterns from ASB.
 * @return array All RegExp patterns including the custom patterns.
 */
function antispam_bee_add_custom_patterns( $patterns ) {
	// Body text consisting of exactly two ASCII uppercase letters.
	// Disable Antispam Bee's case-insensitive modifier locally.
	$patterns[] = array(
		'body' => '^(?-i:[A-Z]{2})$',
	);

	// Spammy email providers (Gmail is intentionally not included).
	$patterns[] = array(
		'email' => '@(?:mail\.ru|yandex\.(?:ru|com|by|kz))$',
	);

	// Every comment with a .ru/.bid top-level domain.
	// @link: http://www.online-erfolgreich.net/webseite-und-technik/spam-bekaempfen-mit-antispam-bee-und-regulaere-ausdruecke-via-plugin-hook/
	$patterns[] = array(
		'email' => '^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.(?:ru|bid)$',
	);

	// Spam text in author name.
	$patterns[] = array(
		'author' => '(xxx|sex)(\d\d\d)\.(top|xyz)',
	);
	// Spam text in email.
	$patterns[] = array(
		'email' => '(xxx|sex)(\d\d\d)\.(top|xyz)',
	);
	// Spam text in hostname.
	$patterns[] = array(
		'host' => '(xxx|sex)(\d\d\d)\.(top|xyz)',
	);
	// Spam text in body.
	$patterns[] = array(
		'body' => '(xxx|sex)(\d\d\d)\.(top|xyz)',
	);

	// Random-string spam with exactly 30 letters in the body and 10 or 11 in the name.
	$patterns[] = array(
		'body'   => '^[a-z]{30}$',
		'author' => '^[a-z]{10,11}$',
	);

	// ClickBank affiliate spam with a generic call-to-action link.
	$patterns[] = array(
		'body' => '<a\b[^>]*href=["\']https?:\/\/[^"\']+\.hop\.clickbank\.net[^"\']*["\'][^>]*>\s*click here\s*<\/a>',
	);

	// Weight-loss template spam with additional context and a call-to-action link.
	$patterns[] = array(
		'body' => '\b(?:weight loss|excess weight)\b.{0,700}\b(?:\d+\s*kg|game-changer)\b.{0,700}<a\b[^>]*>\s*click here\s*<\/a>',
	);

	// Generic post-summary template spam with a call-to-action link.
	$patterns[] = array(
		'body' => '\b(?:your|this) post\b.{0,350}\bfor more details\b.{0,150}<a\b[^>]*>\s*click here\s*<\/a>',
	);

	// Elavil spam from a repeatedly observed domain.
	$patterns[] = array(
		'body' => '\belavil\b',
		'host' => '^(?:https?:\/\/)?(?:www\.)?elavil365y\.com(?:\/|$)',
	);

	// Invalid author URL without a dot in its host name.
	$patterns[] = array(
		'host' => '^(?:https?:\/\/)?[^.\/\s]+\/?$',
	);

	// Numeric-only bot names.
	$patterns[] = array(
		'author' => '^\d{5,}$',
	);

	// Purchase solicitation combined with an HTML link.
	$patterns[] = array(
		'body' => '^(?=.*\bbuy\b)(?=.*<a\b)',
	);

	// Spam text in email.
	$patterns[] = array(
		'email' => 'viagra|(?<!spe)cialis|casino',
	);

	// Spam text in host/url.
	$patterns[] = array(
		'host' => 'viagra|(?<!spe)cialis|casino',
	);

	// Spam text in body.
	$patterns[] = array(
		'body' => 'target[t]?ed (?:visitors|traffic)|viagra|(?<!spe)cialis',
	);

	// 3 or more links in body
	// http://www.online-erfolgreich.net/webseite-und-technik/spam-bekaempfen-mit-antispam-bee-und-regulaere-ausdruecke-via-plugin-hook/
	$patterns[] = array(
		'body' => '(?:https?|ftps?):\/\/.*?(?:https?|ftps?):\/\/.*?(?:https?|ftps?):\/\/',
	);

	// non latin characters (like Cyrillic, Japanese, etc.) in body
	// @link: http://www.regular-expressions.info/unicode.html
	$patterns[] = array(
		'body' => '\p{Arabic}|\p{Armenian}|\p{Bengali}|\p{Bopomofo}|\p{Braille}|\p{Buhid}|\p{Canadian_Aboriginal}|\p{Cherokee}|\p{Cyrillic}|\p{Devanagari}|\p{Ethiopic}|\p{Georgian}|\p{Greek}|\p{Gujarati}|\p{Gurmukhi}|\p{Han}|\p{Hangul}|\p{Hanunoo}|\p{Hebrew}|\p{Hiragana}|\p{Kannada}|\p{Katakana}|\p{Khmer}|\p{Lao}|\p{Limbu}|\p{Malayalam}|\p{Mongolian}|\p{Myanmar}|\p{Ogham}|\p{Oriya}|\p{Runic}|\p{Sinhala}|\p{Syriac}|\p{Tagalog}|\p{Tagbanwa}|\p{Tamil}|\p{Telugu}|\p{Thaana}|\p{Thai}|\p{Tibetan}|\p{Yi}',
	);

	return $patterns;
}
