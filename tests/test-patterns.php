<?php
/**
 * Lightweight regression tests for the custom patterns.
 *
 * Run with: php tests/test-patterns.php
 */

define( 'ABSPATH', __DIR__ );

/**
 * WordPress stub used while loading the plugin.
 *
 * @param string   $hook     Filter name.
 * @param callable $callback Filter callback.
 */
function add_filter( $hook, $callback ) { // phpcs:ignore Generic.CodeAnalysis.UnusedFunctionParameter.FoundAfterLastUsed
}

require dirname( __DIR__ ) . '/custom-patterns-asb.php';

$patterns = antispam_bee_add_custom_patterns( array() );
$failures = array();

foreach ( $patterns as $pattern_index => $pattern ) {
	foreach ( $pattern as $field => $regexp ) {
		if ( false === preg_match( '/' . $regexp . '/isu', '' ) ) {
			$failures[] = sprintf( 'invalid pattern %d (%s)', $pattern_index, $field );
		}
	}
}

/**
 * Match a comment using the same AND semantics and modifiers as Antispam Bee.
 *
 * @param array $pattern Pattern fields.
 * @param array $comment Comment fields.
 * @return bool
 */
function custom_patterns_asb_matches( $pattern, $comment ) {
	foreach ( $pattern as $field => $regexp ) {
		if ( empty( $comment[ $field ] ) || 1 !== preg_match( '/' . $regexp . '/isu', $comment[ $field ] ) ) {
			return false;
		}

	}

	return true;
}

/**
 * Check whether any custom pattern matches a comment.
 *
 * @param array $patterns Patterns to test.
 * @param array $comment  Comment fields.
 * @return bool
 */
function custom_patterns_asb_is_spam( $patterns, $comment ) {
	foreach ( $patterns as $pattern ) {
		if ( custom_patterns_asb_matches( $pattern, $comment ) ) {
			return true;
		}

	}

	return false;
}

$cases = array(
	array(
		'label'    => 'random strings with a 10-character author',
		'expected' => true,
		'comment'  => array(
			'author' => 'swfudqcutm',
			'body'   => 'xfiooautfgyhdipgujuekbjwgxqyda',
		),
	),
	array(
		'label'    => 'random strings with an 11-character author',
		'expected' => true,
		'comment'  => array(
			'author' => 'abcdefghijk',
			'body'   => 'abcdefghijklmnopqrstuvwxyzabcd',
		),
	),
	array(
		'label'    => 'random strings embedded in real text',
		'expected' => false,
		'comment'  => array(
			'author' => 'abcdefghij',
			'body'   => 'Prefix abcdefghijklmnopqrstuvwxyzabcd suffix',
		),
	),
	array(
		'label'    => 'ClickBank call-to-action link',
		'expected' => true,
		'comment'  => array(
			'body' => '<a href="https://affiliate.hop.clickbank.net/offer" rel="nofollow ugc">Click here</a>',
		),
	),
	array(
		'label'    => 'ClickBank link with descriptive anchor text',
		'expected' => false,
		'comment'  => array(
			'body' => '<a href="https://affiliate.hop.clickbank.net/offer">Product documentation</a>',
		),
	),
	array(
		'label'    => 'weight-loss template across line breaks',
		'expected' => true,
		'comment'  => array(
			'body' => "From 85kg to 55kg - this weight loss product is a true game-changer.\n<a href=\"https://example.com\">click here</a>",
		),
	),
	array(
		'label'    => 'legitimate weight-loss discussion without a call to action',
		'expected' => false,
		'comment'  => array(
			'body' => 'Your article about weight loss helped me understand the topic.',
		),
	),
	array(
		'label'    => 'generic post-summary template',
		'expected' => true,
		'comment'  => array(
			'body' => 'Your post emphasizes an important point. For more details, <a href="https://example.com">Click here</a>.',
		),
	),
	array(
		'label'    => 'ordinary praise without the full template',
		'expected' => false,
		'comment'  => array(
			'body' => 'Your post was helpful. Thanks for publishing it.',
		),
	),
	array(
		'label'    => 'ru top-level domain',
		'expected' => true,
		'comment'  => array(
			'email' => 'person@example.ru',
		),
	),
	array(
		'label'    => 'repeated ru top-level domain fragment',
		'expected' => false,
		'comment'  => array(
			'email' => 'person@example.ruru',
		),
	),
	array(
		'label'    => 'spam domain with a literal dot',
		'expected' => true,
		'comment'  => array(
			'body' => 'Visit xxx123.top today',
		),
	),
	array(
		'label'    => 'spam domain with a non-dot separator',
		'expected' => false,
		'comment'  => array(
			'body' => 'Visit xxx123Xtop today',
		),
	),
	array(
		'label'    => 'inherited combining character without another blocked script',
		'expected' => false,
		'comment'  => array(
			'body' => "Cafe\xCC\x81 is written with a combining accent.",
		),
	),
	array(
		'label'    => 'supported Yandex domain',
		'expected' => true,
		'comment'  => array(
			'email' => 'person@yandex.com',
		),
	),
	array(
		'label'    => 'unknown Yandex domain',
		'expected' => false,
		'comment'  => array(
			'email' => 'person@yandex.invalid',
		),
	),
	array(
		'label'    => 'pharma term embedded in a spam domain',
		'expected' => true,
		'comment'  => array(
			'host' => 'https://www.acheterviagrafr24.com/',
		),
	),
	array(
		'label'    => 'cialis substring in specialist',
		'expected' => false,
		'comment'  => array(
			'body' => 'A specialist answered the question.',
		),
	),
	array(
		'label'    => 'three links using different protocols',
		'expected' => true,
		'comment'  => array(
			'body' => 'https://one.example ftp://two.example http://three.example',
		),
	),
	array(
		'label'    => 'only two links',
		'expected' => false,
		'comment'  => array(
			'body' => 'https://one.example and http://two.example',
		),
	),
);

foreach ( $cases as $case ) {
	$actual = custom_patterns_asb_is_spam( $patterns, $case['comment'] );

	if ( $case['expected'] !== $actual ) {
		$failures[] = $case['label'];
	}
}

if ( $failures ) {
	fwrite( STDERR, 'Failed: ' . implode( ', ', $failures ) . PHP_EOL );
	exit( 1 );
}

echo 'All ' . count( $cases ) . ' pattern tests passed.' . PHP_EOL;
