<?php
/**
 * Plugin Name: Custom Patterns for Antispam Bee
 * Description: Add custom patterns for Antispam Bee.
 * Plugin URI:  https://torstenlandsiedel.de
 * Version:     1.3
 * Author:      Torsten Landsiedel
 * Author URI:  https://torstenlandsiedel.de
 * Licence:     GPL 2
 * License URI: http://opensource.org/licenses/GPL-2.0
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
 * @param   Array $patterns All RegExp patterns from ASB.
 */
function antispam_bee_add_custom_patterns( $patterns ) {
	// Body text with two or less characters.
	$patterns[] = array(
		'body' => '^(?=.{0,2}$).*',
	);

	// Spammy email addresses (gmail would be here too, but this is not useful for an european blog).
	$patterns[] = array(
		'email' => '@mail\.ru|@yandex\.$',
	);

	// every comment with .ru/.bid top level doman
	// @link: http://www.online-erfolgreich.net/webseite-und-technik/spam-bekaempfen-mit-antispam-bee-und-regulaere-ausdruecke-via-plugin-hook/
	$patterns[] = array(
		'email' => '(^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.(ru|bid)+$)',
	);

	// Spam text in author name.
	$patterns[] = array(
		'author' => '(xxx|sex)(\d\d\d).(top|xyz)',
	);
	// Spam text in email.
	$patterns[] = array(
		'email' => '(xxx|sex)(\d\d\d).(top|xyz)',
	);
	// Spam text in hostname.
	$patterns[] = array(
		'host' => '(xxx|sex)(\d\d\d).(top|xyz)',
	);
	// Spam text in body.
	$patterns[] = array(
		'body' => '(xxx|sex)(\d\d\d).(top|xyz)',
	);

	// Crazy spam with exactly 10 chars in name and 30 chars in body.
	$patterns[] = array(
		'body'   => '\b[a-z]{30}\b',
		'author' => '\b[a-z]{10}\b',
	);

	// Spam text in email.
	$patterns[] = array(
		'email' => 'viagra|cialis|casino',
	);

	// Spam text in host/url.
	$patterns[] = array(
		'host' => 'viagra|cialis|casino',
	);

	// Spam text in body.
	$patterns[] = array(
		'body' => 'target[t]?ed (visitors|traffic)|viagra|cialis',
	);

	// 3 or more links in body
	// http://www.online-erfolgreich.net/webseite-und-technik/spam-bekaempfen-mit-antispam-bee-und-regulaere-ausdruecke-via-plugin-hook/
	$patterns[] = array(
		'body' => '(.*(http|https|ftp|ftps)\:\/\/){3,}',
	);

	// non latin characters (like Cyrillic, Japanese, etc.) in body
	// @link: http://www.regular-expressions.info/unicode.html
	$patterns[] = array(
		'body' => '\p{Arabic}|\p{Armenian}|\p{Bengali}|\p{Bopomofo}|\p{Braille}|\p{Buhid}|\p{Canadian_Aboriginal}|\p{Cherokee}|\p{Cyrillic}|\p{Devanagari}|\p{Ethiopic}|\p{Georgian}|\p{Greek}|\p{Gujarati}|\p{Gurmukhi}|\p{Han}|\p{Hangul}|\p{Hanunoo}|\p{Hebrew}|\p{Hiragana}|\p{Inherited}|\p{Kannada}|\p{Katakana}|\p{Khmer}|\p{Lao}|\p{Limbu}|\p{Malayalam}|\p{Mongolian}|\p{Myanmar}|\p{Ogham}|\p{Oriya}|\p{Runic}|\p{Sinhala}|\p{Syriac}|\p{Tagalog}|\p{Tagbanwa}|\p{Tamil}|\p{Telugu}|\p{Thaana}|\p{Thai}|\p{Tibetan}|\p{Yi}',
	);

	return $patterns;
}
