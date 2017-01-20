<?php
/**
 * Plugin Name: Custom Pattern for Antispam Bee
 * Description: Add custom patterns for Antispam Bee.
 * Plugin URI:  http://torstenlandsiedel.de
 * Version:     1.1
 * Author:      Torsten Landsiedel
 * Author URI:  http://torstenlandsiedel.de
 * Licence:     GPL 2
 * License URI: http://opensource.org/licenses/GPL-2.0
 */
 
if ( ! defined( 'ABSPATH' ) ) exit; // Exit if accessed directly

/**
 * Antispam Bee filter for custom RegExp patterns
 */

function antispam_bee_patterns() {
	add_filter( 'antispam_bee_patterns', 'antispam_bee_add_custom_patterns'	);
}
add_action(	'init',	'antispam_bee_patterns' );

function antispam_bee_add_custom_patterns($patterns) {
	// Pattern for body text with two or less characters.
	$patterns[] = array(
		'body' => '^(?=.{0,2}$).*'
	);

	// Patterns for phony email addresses.
	$patterns[] = array(
		'email'	=> '@mail\.ru|@yandex\.$',
	);

	// Patterns for spam text in body
	$patterns[] = array(
		'body' => 'target[t]?ed (visitors|traffic)|viagra|cialis',
	);

	return $patterns;
}