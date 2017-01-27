<?php
/**
 * Plugin Name: Custom Patterns for Antispam Bee
 * Description: Add custom patterns for Antispam Bee.
 * Plugin URI:  http://torstenlandsiedel.de
 * Version:     1.2
 * Author:      Torsten Landsiedel
 * Author URI:  http://torstenlandsiedel.de
 * Licence:     GPL 2
 * License URI: http://opensource.org/licenses/GPL-2.0
 * GitHub Plugin URI: https://github.com/Zodiac1978/custom-patterns-asb
 */
 
if ( ! defined( 'ABSPATH' ) ) exit; // Exit if accessed directly


/**
 * Antispam Bee filter for custom RegExp patterns
 */
add_filter( 'antispam_bee_patterns', 'antispam_bee_add_custom_patterns'	);


function antispam_bee_add_custom_patterns($patterns) {
	// body text with two or less characters
	$patterns[] = array(
		'body' => '^(?=.{0,2}$).*',
	);

	// spammy email addresses (gmail would be here too, but this is not useful for an european blog)
	$patterns[] = array(
		'email'	=> '@mail\.ru|@yandex\.$',
	);

	// every comment with .ru/.bid top level domain
	// See: http://www.online-erfolgreich.net/webseite-und-technik/spam-bekaempfen-mit-antispam-bee-und-regulaere-ausdruecke-via-plugin-hook/
	$patterns[] = array(
		'email' => '(^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.(ru|bid)+$)'
	);

	// spam text in email
	$patterns[] = array(
		'email' => 'viagra|cialis|casino',
	);

	// spam text in host/url
	$patterns[] = array(
		'host' => 'viagra|cialis|casino',
	);

	// spam text in body
	$patterns[] = array(
		'body' => 'target[t]?ed (visitors|traffic)|viagra|cialis',
	);

	// 3 or more links in body
	// See: http://www.online-erfolgreich.net/webseite-und-technik/spam-bekaempfen-mit-antispam-bee-und-regulaere-ausdruecke-via-plugin-hook/
	$patterns[] = array(
		'body' => '(.*(http|https|ftp|ftps)\:\/\/){3,}',
	);

	// non latin characters (like Cyricllic, Japanese, etc.) in body
	// http://www.regular-expressions.info/unicode.html
	// If you have visitors in those languages just delete these from the pattern
	$patterns[] = array(
		'body' => '\p{Arabic}|\p{Armenian}|\p{Bengali}|\p{Bopomofo}|\p{Braille}|\p{Buhid}|\p{Canadian_Aboriginal}|\p{Cherokee}|\p{Cyrillic}|\p{Devanagari}|\p{Ethiopic}|\p{Georgian}|\p{Greek}|\p{Gujarati}|\p{Gurmukhi}|\p{Han}|\p{Hangul}|\p{Hanunoo}|\p{Hebrew}|\p{Hiragana}|\p{Inherited}|\p{Kannada}|\p{Katakana}|\p{Khmer}|\p{Lao}|\p{Limbu}|\p{Malayalam}|\p{Mongolian}|\p{Myanmar}|\p{Ogham}|\p{Oriya}|\p{Runic}|\p{Sinhala}|\p{Syriac}|\p{Tagalog}|\p{Tagbanwa}|\p{Tamil}|\p{Telugu}|\p{Thaana}|\p{Thai}|\p{Tibetan}|\p{Yi}',
	);

	return $patterns;
}
