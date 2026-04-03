<?php

namespace Legitrum\Analyzer\Tests\Scanner;

use InvalidArgumentException;
use Legitrum\Analyzer\Scanner\FileIndexer;
use PHPUnit\Framework\TestCase;

class FileIndexerTest extends TestCase
{
    private FileIndexer $indexer;

    private string $fixtureDir;

    protected function setUp(): void
    {
        $this->indexer = new FileIndexer();
        $this->fixtureDir = sys_get_temp_dir() . DIRECTORY_SEPARATOR . 'fileindexer_test_' . uniqid();
        mkdir($this->fixtureDir, 0755, true);
    }

    protected function tearDown(): void
    {
        $this->removeDir($this->fixtureDir);
    }

    public function testRejectsProductionEnvironment(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('not allowed');

        $this->indexer->index($this->fixtureDir, 'production');
    }

    public function testRejectsUnknownEnvironment(): void
    {
        $this->expectException(InvalidArgumentException::class);

        $this->indexer->index($this->fixtureDir, 'custom-env');
    }

    public function testAcceptsDevelopmentEnvironment(): void
    {
        file_put_contents($this->fixtureDir . DIRECTORY_SEPARATOR . 'app.php', '<?php echo 1;');

        $result = $this->indexer->index($this->fixtureDir, 'development');

        $this->assertCount(1, $result);
    }

    public function testAcceptsStagingEnvironment(): void
    {
        file_put_contents($this->fixtureDir . DIRECTORY_SEPARATOR . 'app.php', '<?php echo 1;');

        $result = $this->indexer->index($this->fixtureDir, 'staging');

        $this->assertCount(1, $result);
    }

    public function testDefaultsToDevelopment(): void
    {
        file_put_contents($this->fixtureDir . DIRECTORY_SEPARATOR . 'app.php', '<?php echo 1;');

        $result = $this->indexer->index($this->fixtureDir);

        $this->assertCount(1, $result);
    }

    public function testSkipsProductionPathsInDevelopment(): void
    {
        // Create a production config path
        $prodDir = $this->fixtureDir . DIRECTORY_SEPARATOR . 'config' . DIRECTORY_SEPARATOR . 'production';
        mkdir($prodDir, 0755, true);
        file_put_contents($prodDir . DIRECTORY_SEPARATOR . 'database.php', '<?php return [];');

        // Create a normal file
        file_put_contents($this->fixtureDir . DIRECTORY_SEPARATOR . 'app.php', '<?php echo 1;');

        $result = $this->indexer->index($this->fixtureDir, 'development');

        $paths = array_column($result, 'path');
        $this->assertContains('app.php', $paths);
        $this->assertNotContains('config/production/database.php', $paths);
    }

    public function testSkipsProdDeployPaths(): void
    {
        $prodDir = $this->fixtureDir . DIRECTORY_SEPARATOR . 'deploy' . DIRECTORY_SEPARATOR . 'prod';
        mkdir($prodDir, 0755, true);
        file_put_contents($prodDir . DIRECTORY_SEPARATOR . 'deploy.yaml', "deploy: true\n");

        $result = $this->indexer->index($this->fixtureDir, 'staging');

        $paths = array_column($result, 'path');
        $this->assertNotContains('deploy/prod/deploy.yaml', $paths);
    }

    public function testRejectsProjectPathInsideProductionDir(): void
    {
        $prodDir = $this->fixtureDir . DIRECTORY_SEPARATOR . 'deploy' . DIRECTORY_SEPARATOR . 'production';
        mkdir($prodDir, 0755, true);
        file_put_contents($prodDir . DIRECTORY_SEPARATOR . 'app.php', '<?php echo 1;');

        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('production directory');

        $this->indexer->index($prodDir);
    }

    public function testEnvVarBypassAttemptsFail(): void
    {
        // These env vars should have no effect on validation
        putenv('SKIP_ENV_CHECK=1');
        putenv('FORCE=1');

        $this->expectException(InvalidArgumentException::class);
        $this->indexer->index($this->fixtureDir, 'production');

        putenv('SKIP_ENV_CHECK');
        putenv('FORCE');
    }

    public function testCaseInsensitiveProductionPathDetection(): void
    {
        $prodDir = $this->fixtureDir . DIRECTORY_SEPARATOR . 'config' . DIRECTORY_SEPARATOR . 'Production';
        mkdir($prodDir, 0755, true);
        file_put_contents($prodDir . DIRECTORY_SEPARATOR . 'db.php', '<?php return [];');

        file_put_contents($this->fixtureDir . DIRECTORY_SEPARATOR . 'app.php', '<?php echo 1;');

        $result = $this->indexer->index($this->fixtureDir);

        $paths = array_column($result, 'path');
        $this->assertNotContains('config/Production/db.php', $paths);
    }

    public function testSkipsSecretsDirectory(): void
    {
        $secretsDir = $this->fixtureDir . DIRECTORY_SEPARATOR . 'secrets';
        mkdir($secretsDir, 0755, true);
        file_put_contents($secretsDir . DIRECTORY_SEPARATOR . 'keys.json', '{}');

        file_put_contents($this->fixtureDir . DIRECTORY_SEPARATOR . 'app.php', '<?php echo 1;');

        $result = $this->indexer->index($this->fixtureDir);

        $paths = array_column($result, 'path');
        $this->assertNotContains('secrets/keys.json', $paths);
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
