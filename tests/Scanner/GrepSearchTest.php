<?php

namespace Legitrum\Analyzer\Tests\Scanner;

use InvalidArgumentException;
use Legitrum\Analyzer\Scanner\GrepSearch;
use Legitrum\Analyzer\Security\FileValidator;
use PHPUnit\Framework\TestCase;

class GrepSearchTest extends TestCase
{
    private GrepSearch $grep;

    private string $fixtureDir;

    protected function setUp(): void
    {
        $this->grep = new GrepSearch();
        $this->fixtureDir = sys_get_temp_dir() . DIRECTORY_SEPARATOR . 'grepsearch_test_' . uniqid();
        mkdir($this->fixtureDir, 0755, true);

        // Allow system temp dir for testing on non-Linux systems
        $normalizedTemp = str_replace('\\', '/', realpath(sys_get_temp_dir()));
        GrepSearch::addAllowedBaseDir($normalizedTemp);
    }

    protected function tearDown(): void
    {
        $this->removeDir($this->fixtureDir);
        GrepSearch::resetAllowedBaseDirs();
    }

    public function testRejectsInvalidProjectPath(): void
    {
        $this->expectException(InvalidArgumentException::class);

        $this->grep->findRelevantFiles([], ['test'], '/nonexistent/path/' . uniqid());
    }

    public function testRejectsPathTraversalWithDotDot(): void
    {
        // Create a file outside the project dir
        $outsideDir = sys_get_temp_dir() . DIRECTORY_SEPARATOR . 'grepsearch_outside_' . uniqid();
        mkdir($outsideDir, 0755, true);
        file_put_contents($outsideDir . DIRECTORY_SEPARATOR . 'secret.txt', 'sensitive data');

        // Create a legit file inside
        file_put_contents($this->fixtureDir . DIRECTORY_SEPARATOR . 'legit.php', '<?php echo "hello";');

        $files = [
            [
                'absolute_path' => $this->fixtureDir . DIRECTORY_SEPARATOR . '..' . DIRECTORY_SEPARATOR . basename($outsideDir) . DIRECTORY_SEPARATOR . 'secret.txt',
                'path' => '../secret.txt',
                'lines' => 1,
            ],
            [
                'absolute_path' => $this->fixtureDir . DIRECTORY_SEPARATOR . 'legit.php',
                'path' => 'legit.php',
                'lines' => 1,
            ],
        ];

        $result = $this->grep->findRelevantFiles($files, ['hello'], $this->fixtureDir);

        // Only the legit file should be returned, not the traversal path
        $this->assertCount(1, $result);
        $this->assertSame('legit.php', $result[0]['path']);

        $this->removeDir($outsideDir);
    }

    public function testRejectsSymlinkOutsideProject(): void
    {
        if (DIRECTORY_SEPARATOR === '\\') {
            $this->markTestSkipped('Symlink tests unreliable on Windows without elevated privileges');
        }

        $outsideDir = sys_get_temp_dir() . DIRECTORY_SEPARATOR . 'grepsearch_symlink_' . uniqid();
        mkdir($outsideDir, 0755, true);
        file_put_contents($outsideDir . DIRECTORY_SEPARATOR . 'secret.txt', 'password=admin');

        $link = $this->fixtureDir . DIRECTORY_SEPARATOR . 'linked.txt';
        symlink($outsideDir . DIRECTORY_SEPARATOR . 'secret.txt', $link);

        $files = [
            [
                'absolute_path' => $link,
                'path' => 'linked.txt',
                'lines' => 1,
            ],
        ];

        $result = $this->grep->findRelevantFiles($files, ['password'], $this->fixtureDir);

        $this->assertCount(0, $result);

        $this->removeDir($outsideDir);
    }

    public function testFiltersEmptyAndOversizedPatterns(): void
    {
        file_put_contents($this->fixtureDir . DIRECTORY_SEPARATOR . 'app.php', '<?php echo "match";');

        $files = [
            [
                'absolute_path' => $this->fixtureDir . DIRECTORY_SEPARATOR . 'app.php',
                'path' => 'app.php',
                'lines' => 1,
            ],
        ];

        // Empty string and oversized pattern should be filtered out
        $patterns = ['', str_repeat('a', 1001), 'match'];

        $result = $this->grep->findRelevantFiles($files, $patterns, $this->fixtureDir);

        $this->assertCount(1, $result);
        $this->assertSame(['match'], $result[0]['matched_patterns']);
    }

    public function testRejectsEtcPasswdTraversal(): void
    {
        file_put_contents($this->fixtureDir . DIRECTORY_SEPARATOR . 'app.php', '<?php echo "safe";');

        $files = [
            [
                'absolute_path' => $this->fixtureDir . DIRECTORY_SEPARATOR . '../../../../../../etc/passwd',
                'path' => '../../../../../../etc/passwd',
                'lines' => 1,
            ],
            [
                'absolute_path' => $this->fixtureDir . DIRECTORY_SEPARATOR . 'app.php',
                'path' => 'app.php',
                'lines' => 1,
            ],
        ];

        $result = $this->grep->findRelevantFiles($files, ['safe'], $this->fixtureDir);

        $paths = array_column($result, 'path');
        $this->assertNotContains('../../../../../../etc/passwd', $paths);
    }

    public function testRejectsBinaryPolyglotFiles(): void
    {
        // Create a .php file that starts with a ZIP header (polyglot)
        $polyglotPath = $this->fixtureDir . DIRECTORY_SEPARATOR . 'malicious.php';
        file_put_contents($polyglotPath, "\x50\x4B\x03\x04" . '<?php echo "hidden";');

        // Create a legit PHP file
        file_put_contents($this->fixtureDir . DIRECTORY_SEPARATOR . 'legit.php', '<?php echo "visible";');

        $grep = new GrepSearch();
        $grep->setValidator(new FileValidator());

        $files = [
            [
                'absolute_path' => $polyglotPath,
                'path' => 'malicious.php',
                'lines' => 1,
            ],
            [
                'absolute_path' => $this->fixtureDir . DIRECTORY_SEPARATOR . 'legit.php',
                'path' => 'legit.php',
                'lines' => 1,
            ],
        ];

        $result = $grep->findRelevantFiles($files, ['echo'], $this->fixtureDir);

        $paths = array_column($result, 'path');
        $this->assertNotContains('malicious.php', $paths, 'Polyglot file should be rejected by FileValidator');
        $this->assertContains('legit.php', $paths);
    }

    public function testRejectsNonIntegerPatterns(): void
    {
        file_put_contents($this->fixtureDir . DIRECTORY_SEPARATOR . 'app.php', '<?php echo "test";');

        $files = [
            [
                'absolute_path' => $this->fixtureDir . DIRECTORY_SEPARATOR . 'app.php',
                'path' => 'app.php',
                'lines' => 1,
            ],
        ];

        // Non-string patterns should be filtered
        $patterns = [123, null, true, 'test'];

        $result = $this->grep->findRelevantFiles($files, $patterns, $this->fixtureDir);

        $this->assertCount(1, $result);
        $this->assertSame(['test'], $result[0]['matched_patterns']);
    }

    public function testNormalOperationUnchanged(): void
    {
        file_put_contents($this->fixtureDir . DIRECTORY_SEPARATOR . 'controller.php', '<?php class UserController { public function login() {} }');
        file_put_contents($this->fixtureDir . DIRECTORY_SEPARATOR . 'model.php', '<?php class User { public $name; }');

        $files = [
            [
                'absolute_path' => $this->fixtureDir . DIRECTORY_SEPARATOR . 'controller.php',
                'path' => 'controller.php',
                'lines' => 1,
            ],
            [
                'absolute_path' => $this->fixtureDir . DIRECTORY_SEPARATOR . 'model.php',
                'path' => 'model.php',
                'lines' => 1,
            ],
        ];

        $result = $this->grep->findRelevantFiles($files, ['login', 'UserController'], $this->fixtureDir);

        // controller.php matches both patterns (score 2), model.php matches none
        $this->assertCount(1, $result);
        $this->assertSame(2, $result[0]['relevance_score']);
        $this->assertSame('controller.php', $result[0]['path']);
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
            if (is_link($path)) {
                unlink($path);
            } elseif (is_dir($path)) {
                $this->removeDir($path);
            } else {
                unlink($path);
            }
        }
        rmdir($dir);
    }
}
