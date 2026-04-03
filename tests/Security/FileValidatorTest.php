<?php

namespace Legitrum\Analyzer\Tests\Security;

use Legitrum\Analyzer\Security\FileValidator;
use PHPUnit\Framework\TestCase;

class FileValidatorTest extends TestCase
{
    private FileValidator $validator;

    private string $fixtureDir;

    protected function setUp(): void
    {
        $this->validator = new FileValidator(true);
        $this->fixtureDir = sys_get_temp_dir() . DIRECTORY_SEPARATOR . 'filevalidator_test_' . uniqid();
        mkdir($this->fixtureDir, 0755, true);
    }

    protected function tearDown(): void
    {
        $this->removeDir($this->fixtureDir);
    }

    public function testRejectsUnreadableFiles(): void
    {
        $path = $this->fixtureDir . DIRECTORY_SEPARATOR . 'nope.php';
        // File does not exist — unreadable
        $result = $this->validator->validate($path);

        $this->assertTrue($result->rejected);
        $this->assertSame('unreadable', $result->reason);
    }

    public function testRejectsZipPolyglotPhp(): void
    {
        $path = $this->fixtureDir . DIRECTORY_SEPARATOR . 'polyglot.php';
        file_put_contents($path, "\x50\x4B\x03\x04" . '<?php echo "hidden";');

        $result = $this->validator->validate($path);

        $this->assertTrue($result->rejected);
        $this->assertSame('suspicious_binary_header', $result->reason);
    }

    public function testRejectsElfBinary(): void
    {
        $path = $this->fixtureDir . DIRECTORY_SEPARATOR . 'binary.php';
        file_put_contents($path, "\x7F\x45\x4C\x46" . str_repeat("\x00", 100));

        $result = $this->validator->validate($path);

        $this->assertTrue($result->rejected);
        $this->assertSame('suspicious_binary_header', $result->reason);
    }

    public function testRejectsPeExecutable(): void
    {
        $path = $this->fixtureDir . DIRECTORY_SEPARATOR . 'malware.php';
        file_put_contents($path, "\x4D\x5A" . str_repeat("\x00", 100));

        $result = $this->validator->validate($path);

        $this->assertTrue($result->rejected);
        $this->assertSame('suspicious_binary_header', $result->reason);
    }

    public function testRejectsPngAsPhp(): void
    {
        $path = $this->fixtureDir . DIRECTORY_SEPARATOR . 'image.php';
        file_put_contents($path, "\x89\x50\x4E\x47" . str_repeat("\x00", 100));

        $result = $this->validator->validate($path);

        $this->assertTrue($result->rejected);
        $this->assertSame('suspicious_binary_header', $result->reason);
    }

    public function testRejectsMagicMismatchPhp(): void
    {
        $path = $this->fixtureDir . DIRECTORY_SEPARATOR . 'notphp.php';
        file_put_contents($path, 'This is just plain text, not PHP');

        $result = $this->validator->validate($path);

        $this->assertTrue($result->rejected);
        $this->assertStringStartsWith('magic_mismatch', $result->reason);
    }

    public function testAcceptsValidPhpFile(): void
    {
        $path = $this->fixtureDir . DIRECTORY_SEPARATOR . 'valid.php';
        file_put_contents($path, '<?php echo "hello";');

        $result = $this->validator->validate($path);

        $this->assertTrue($result->valid);
        $this->assertFalse($result->rejected);
    }

    public function testAcceptsShortTagPhp(): void
    {
        $path = $this->fixtureDir . DIRECTORY_SEPARATOR . 'short.php';
        file_put_contents($path, '<?= "hello" ?>');

        $result = $this->validator->validate($path);

        $this->assertTrue($result->valid);
    }

    public function testAcceptsJsonFile(): void
    {
        $path = $this->fixtureDir . DIRECTORY_SEPARATOR . 'data.json';
        file_put_contents($path, '{"key": "value"}');

        $result = $this->validator->validate($path);

        $this->assertTrue($result->valid);
    }

    public function testCachesResults(): void
    {
        $path = $this->fixtureDir . DIRECTORY_SEPARATOR . 'cached.php';
        file_put_contents($path, '<?php echo 1;');

        $result1 = $this->validator->validate($path);
        $result2 = $this->validator->validate($path);

        $this->assertSame($result1, $result2);

        $summary = $this->validator->getSummary();
        $this->assertSame(1, $summary['files_validated']);
    }

    public function testDisabledValidatorPassesEverything(): void
    {
        $disabled = new FileValidator(false);
        $path = $this->fixtureDir . DIRECTORY_SEPARATOR . 'anything.php';
        file_put_contents($path, 'not valid php at all');

        $result = $disabled->validate($path);

        $this->assertTrue($result->valid);
        $this->assertFalse($result->rejected);
    }

    public function testSummaryCountsCorrectly(): void
    {
        $valid = $this->fixtureDir . DIRECTORY_SEPARATOR . 'ok.php';
        file_put_contents($valid, '<?php echo 1;');

        $bad = $this->fixtureDir . DIRECTORY_SEPARATOR . 'bad.php';
        file_put_contents($bad, "\x50\x4B\x03\x04evil");

        $missing = $this->fixtureDir . DIRECTORY_SEPARATOR . 'gone.php';

        $this->validator->validate($valid);
        $this->validator->validate($bad);
        $this->validator->validate($missing);

        $summary = $this->validator->getSummary();
        $this->assertSame(3, $summary['files_validated']);
        $this->assertSame(2, $summary['rejected']);
    }

    private function removeDir(string $dir): void
    {
        if (! is_dir($dir)) {
            return;
        }

        $items = scandir($dir);
        foreach ($items as $item) {
            if ($item === '.' || $item === '..') {
                continue;
            }
            $path = $dir . DIRECTORY_SEPARATOR . $item;
            if (is_dir($path)) {
                $this->removeDir($path);
            } else {
                unlink($path);
            }
        }
        rmdir($dir);
    }
}
