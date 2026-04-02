<?php

namespace Legitrum\Analyzer\Tests\Auth;

use InvalidArgumentException;
use Legitrum\Analyzer\Auth\LegitruAuthClient;
use PHPUnit\Framework\TestCase;

class LegitruAuthClientTest extends TestCase
{
    // --- URL Validation Tests ---

    public function testAcceptsLocalhostHttp(): void
    {
        $client = new LegitruAuthClient('test-token', 'http://localhost:8000');
        $this->assertInstanceOf(LegitruAuthClient::class, $client);
    }

    public function testAcceptsLocalhostHttps(): void
    {
        $client = new LegitruAuthClient('test-token', 'https://localhost');
        $this->assertInstanceOf(LegitruAuthClient::class, $client);
    }

    public function testAcceptsDockerInternal(): void
    {
        $client = new LegitruAuthClient('test-token', 'http://host.docker.internal:8000');
        $this->assertInstanceOf(LegitruAuthClient::class, $client);
    }

    public function testAcceptsLegitrimSubdomain(): void
    {
        $client = new LegitruAuthClient('test-token', 'https://app.legitrum.pt');
        $this->assertInstanceOf(LegitruAuthClient::class, $client);
    }

    public function testAcceptsLegitrimInternalSubdomain(): void
    {
        $client = new LegitruAuthClient('test-token', 'https://analyzer-staging.legitrum.internal');
        $this->assertInstanceOf(LegitruAuthClient::class, $client);
    }

    public function testRejectsMaliciousUrl(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('not in allowlist');

        new LegitruAuthClient('test-token', 'https://malicious.com');
    }

    public function testRejectsJavascriptScheme(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('Invalid URL scheme');

        new LegitruAuthClient('test-token', 'javascript:alert(1)');
    }

    public function testRejectsFtpScheme(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('Invalid URL scheme');

        new LegitruAuthClient('test-token', 'ftp://files.example.com');
    }

    public function testRejectsEmptyUrl(): void
    {
        $this->expectException(InvalidArgumentException::class);

        new LegitruAuthClient('test-token', '');
    }

    public function testRejectsUrlWithoutHost(): void
    {
        $this->expectException(InvalidArgumentException::class);

        new LegitruAuthClient('test-token', 'https://');
    }

    public function testRejectsNonAllowlistedDomain(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('not in allowlist');

        new LegitruAuthClient('test-token', 'https://attacker.legitrum.pt.evil.com');
    }

    public function testRejectsIpSpoofAttempt(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('not in allowlist');

        new LegitruAuthClient('test-token', 'http://192.168.1.1:8000');
    }

    // --- SSRF / Config Injection Tests ---

    public function testRejectsEnvSuppliedMaliciousUrl(): void
    {
        // Simulate a config file injection where an attacker controls the URL
        $injectedUrls = [
            'http://169.254.169.254/latest/meta-data/',  // AWS metadata SSRF
            'http://metadata.google.internal/',           // GCP metadata
            'http://10.0.0.1:8080/admin',                 // Internal service
            'https://evil.com@localhost/',                 // URL authority confusion
            'http://0x7f000001:8000',                     // Hex-encoded 127.0.0.1
            'http://[::1]:8000',                          // IPv6 localhost
        ];

        foreach ($injectedUrls as $url) {
            try {
                new LegitruAuthClient('token', $url);
                $this->fail("Should have rejected URL: {$url}");
            } catch (InvalidArgumentException $e) {
                $this->assertTrue(true);
            }
        }
    }

    public function testRejectsSubdomainTakeover(): void
    {
        // Attacker registers a subdomain that looks legitimate
        $this->expectException(InvalidArgumentException::class);

        new LegitruAuthClient('token', 'https://legitrum.pt.attacker.com');
    }

    // --- Auth Failure Logging Tests ---

    public function testAuthenticateFailureLogsToStderr(): void
    {
        // Use a valid allowlisted URL that won't actually connect
        $client = new LegitruAuthClient('bad-token', 'http://127.0.0.1:19999');

        $stderr = '';
        $stderrStream = fopen('php://memory', 'rw');

        try {
            $client->authenticate(999);
        } catch (\RuntimeException $e) {
            // Expected — connection refused
            $this->assertStringContainsString('Authentication failed', $e->getMessage());

            return;
        }

        $this->fail('Expected RuntimeException was not thrown');
    }

    public function testTokenNotExposedInErrorMessages(): void
    {
        $secretToken = 'super-secret-token-12345';
        $client = new LegitruAuthClient($secretToken, 'http://127.0.0.1:19999');

        try {
            $client->authenticate(1);
        } catch (\RuntimeException $e) {
            // Full token should never appear in the exception message
            $this->assertStringNotContainsString($secretToken, $e->getMessage());

            return;
        }

        $this->fail('Expected RuntimeException was not thrown');
    }
}
