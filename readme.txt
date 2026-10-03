=== Custom Patterns for Antispam Bee ===
Contributors: zodiac1978
Donate link: https://www.paypal.com/cgi-bin/webscr?cmd=_s-xclick&hosted_button_id=LCH9UVV7RKDFY
Tags: antispam, comments, spam, antispam bee, regular expressions
Requires PHP: 8.0
Stable tag: 1.6.0
License: GPLv2 or later
License URI: https://www.gnu.org/licenses/gpl-2.0.html

Adds configurable custom spam-detection patterns to Antispam Bee.

== Description ==

Custom Patterns for Antispam Bee adds site-specific regular-expression patterns to the [Antispam Bee](https://wordpress.org/plugins/antispam-bee/) spam filter.

The supplied patterns detect recurring signals such as certain email providers and domains, suspicious author data, common spam templates, multiple links, and selected non-Latin writing systems. Every pattern can be enabled or disabled individually under **Settings > Antispam Bee Patterns**. All patterns are enabled by default on a new installation and after updating from a version earlier than 1.5.0.

These rules are intentionally opinionated and may not suit every site. Review the enabled patterns for your audience; for example, the non-Latin pattern should be disabled on sites expecting comments in the affected writing systems.

The plugin requires Antispam Bee. Updates are distributed through GitHub and can be installed automatically with [Git Updater](https://github.com/afragen/git-updater).

== Installation ==

1. Install and activate Antispam Bee.
2. Upload the plugin directory to `/wp-content/plugins/`, or install a release archive through the WordPress plugin screen.
3. Activate “Custom Patterns for Antispam Bee”.
4. Review the active rules under **Settings > Antispam Bee Patterns**.

== Frequently Asked Questions ==

= Does this plugin work without Antispam Bee? =

No. It adds patterns through Antispam Bee's `antispam_bee_patterns` filter and therefore requires Antispam Bee to perform the spam checks.

= Are all patterns suitable for every site? =

No. The collection is based on spam observed on particular sites and is deliberately site-specific. Disable any pattern that could reject legitimate comments from your audience.

= How do I receive updates? =

The plugin is hosted on GitHub. Install Git Updater if you want to receive its releases through the WordPress update screen.

== Changelog ==

= 1.6.0 =

* Added validation for Gmail and Googlemail addresses that do not follow Google's username syntax.
* Added exact matches for Gmail and Yahoo lookalike domains observed in submitted spam.
* Added regression tests for the new email patterns.
* Added this WordPress-style readme and reconstructed the release history from the repository.

= 1.5.0 =

* Added a settings page for enabling and disabling individual patterns.
* Kept every pattern enabled by default for new installations and upgrades.
* Added translatable labels and descriptions for the pattern settings.

= 1.4.1 =

* Narrowed the short-comment rule to comments consisting of exactly two uppercase ASCII letters.
* Added regression tests for the refined rule.
* Added a donation link to the project documentation.

= 1.4.0 =

* Added patterns for ClickBank links, recurring weight-loss and post-summary templates, Elavil domain spam, invalid author URLs, numeric author names, and purchase solicitations containing links.
* Improved existing provider, random-string, pharmaceutical, link-count, and domain patterns.
* Added the initial pattern regression test suite.
* Added Composer metadata and the GitHub update URI.
* Raised the minimum PHP version to 8.0.

= 1.3 =

* Added patterns for numbered adult domains and paired random-letter strings.
* Corrected the Antispam Bee field name used for author matching.
* Updated the code to WordPress coding conventions and changed the repository folder structure.

= 1.2 =

* Added patterns for `.ru` and `.bid` email domains, pharmaceutical and casino terms, three or more links, and selected non-Latin writing systems.
* Registered the Antispam Bee filter directly instead of waiting for WordPress initialization.

= 1.1.1 =

* Corrected the plugin name and added metadata for GitHub-based updates.

= 1.1 =

* Initial version recorded in the repository.
* Added patterns for very short comments, selected email providers, traffic offers, and pharmaceutical terms.

