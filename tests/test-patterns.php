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

/**
 * WordPress action stub used while loading the plugin.
 *
 * @param string   $hook     Action name.
 * @param callable $callback Action callback.
 */
function add_action( $hook, $callback ) { // phpcs:ignore Generic.CodeAnalysis.UnusedFunctionParameter.FoundAfterLastUsed
}

/**
 * Return an option from the test store.
 *
 * @param string $name    Option name.
 * @param mixed  $default Default value.
 * @return mixed
 */
function get_option( $name, $default = false ) {
	global $custom_patterns_asb_test_options;

	return array_key_exists( $name, $custom_patterns_asb_test_options ) ? $custom_patterns_asb_test_options[ $name ] : $default;
}

/**
 * Minimal sanitize_key() replacement for the standalone test.
 *
 * @param string $key Value to sanitize.
 * @return string
 */
function sanitize_key( $key ) {
	return preg_replace( '/[^a-z0-9_\-]/', '', strtolower( (string) $key ) );
}

/**
 * Minimal translation function replacement for the standalone test.
 *
 * @param string $text   Source text.
 * @param string $domain Text domain.
 * @return string
 */
function __( $text, $domain = 'default' ) { // phpcs:ignore Generic.CodeAnalysis.UnusedFunctionParameter.FoundAfterLastUsed
	return $text;
}

$custom_patterns_asb_test_options = array();

require dirname( __DIR__ ) . '/custom-patterns-asb.php';

$patterns = antispam_bee_add_custom_patterns( array() );
$failures = array();

if ( 21 !== count( $patterns ) ) {
	$failures[] = 'all patterns are enabled by default';
}

$custom_patterns_asb_test_options[ CUSTOM_PATTERNS_ASB_OPTION ] = array( 'numeric-author' );
$selected_patterns = antispam_bee_add_custom_patterns( array() );

if ( array( array( 'author' => '^\d{5,}$' ) ) !== $selected_patterns ) {
	$failures[] = 'saved pattern selection is applied';
}

$custom_patterns_asb_test_options[ CUSTOM_PATTERNS_ASB_OPTION ] = array();

if ( array() !== antispam_bee_add_custom_patterns( array() ) ) {
	$failures[] = 'all patterns can be disabled';
}

$sanitized = custom_patterns_asb_sanitize_enabled_patterns(
	array( 'three-links', 'unknown-pattern', 'NUMERIC-AUTHOR', 'three-links' )
);

if ( array( 'numeric-author', 'three-links' ) !== $sanitized ) {
	$failures[] = 'pattern selection is sanitized and ordered';
}

unset( $custom_patterns_asb_test_options[ CUSTOM_PATTERNS_ASB_OPTION ] );

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
		'label'    => 'two-uppercase-letter spam body',
		'expected' => true,
		'comment'  => array(
			'body' => 'QF',
		),
	),
	array(
		'label'    => 'mixed-case two-letter comment',
		'expected' => false,
		'comment'  => array(
			'body' => 'Ok',
		),
	),
	array(
		'label'    => 'capitalized two-letter word',
		'expected' => false,
		'comment'  => array(
			'body' => 'Ja',
		),
	),
	array(
		'label'    => 'single uppercase letter',
		'expected' => false,
		'comment'  => array(
			'body' => 'Q',
		),
	),
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
		'label'    => 'Gmail username with too few characters',
		'expected' => true,
		'comment'  => array(
			'email' => 'abcde@gmail.com',
		),
	),
	array(
		'label'    => 'Gmail username with too many characters',
		'expected' => true,
		'comment'  => array(
			'email' => 'abcdefghijklmnopqrstuvwxyz12345@gmail.com',
		),
	),
	array(
		'label'    => 'Gmail username with a leading dot',
		'expected' => true,
		'comment'  => array(
			'email' => '.abcdef@gmail.com',
		),
	),
	array(
		'label'    => 'Gmail username with a trailing dot',
		'expected' => true,
		'comment'  => array(
			'email' => 'abcdef.@gmail.com',
		),
	),
	array(
		'label'    => 'Gmail username with consecutive dots',
		'expected' => true,
		'comment'  => array(
			'email' => 'abc..def@gmail.com',
		),
	),
	array(
		'label'    => 'Gmail username with an invalid character',
		'expected' => true,
		'comment'  => array(
			'email' => 'abc_def@gmail.com',
		),
	),
	array(
		'label'    => 'invalid Googlemail username',
		'expected' => true,
		'comment'  => array(
			'email' => 'abc..def@googlemail.com',
		),
	),
	array(
		'label'    => 'valid minimum-length Gmail username',
		'expected' => false,
		'comment'  => array(
			'email' => 'abcdef@gmail.com',
		),
	),
	array(
		'label'    => 'valid maximum-length Gmail username',
		'expected' => false,
		'comment'  => array(
			'email' => 'abcdefghijklmnopqrstuvwxyz1234@gmail.com',
		),
	),
	array(
		'label'    => 'valid Gmail address with many dots',
		'expected' => false,
		'comment'  => array(
			'email' => 'j.o.h.n.s.m.i.t.h@gmail.com',
		),
	),
	array(
		'label'    => 'valid Gmail plus alias',
		'expected' => false,
		'comment'  => array(
			'email' => 'john.smith+news@gmail.com',
		),
	),
	array(
		'label'    => 'valid Googlemail address',
		'expected' => false,
		'comment'  => array(
			'email' => 'john.smith@googlemail.com',
		),
	),
	array(
		'label'    => 'invalid syntax on another email provider',
		'expected' => false,
		'comment'  => array(
			'email' => 'abc..def@example.com',
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
	array(
		'label'    => 'Elavil spam from the observed domain',
		'expected' => true,
		'comment'  => array(
			'body' => 'elavil anxiety dosage',
			'host' => 'elavil365y.com',
		),
	),
	array(
		'label'    => 'Elavil discussion on another domain',
		'expected' => false,
		'comment'  => array(
			'body' => 'A medical article discussing Elavil and anxiety.',
			'host' => 'https://example.org/',
		),
	),
	array(
		'label'    => 'author URL without a dot',
		'expected' => true,
		'comment'  => array(
			'host' => 'https://not-a-domain/',
		),
	),
	array(
		'label'    => 'valid author URL with a dot',
		'expected' => false,
		'comment'  => array(
			'host' => 'https://example.org/',
		),
	),
	array(
		'label'    => 'numeric-only bot name',
		'expected' => true,
		'comment'  => array(
			'author' => '817689',
		),
	),
	array(
		'label'    => 'numeric-only comment remains allowed',
		'expected' => false,
		'comment'  => array(
			'body' => '10240',
		),
	),
	array(
		'label'    => 'buy solicitation with an HTML link',
		'expected' => true,
		'comment'  => array(
			'body' => '<a href="https://example.org/product">Buy this product</a>',
		),
	),
	array(
		'label'    => 'buy without an HTML link',
		'expected' => false,
		'comment'  => array(
			'body' => 'Where can I buy this book?',
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
