<?php

namespace Legitrum\Analyzer\Tests\Security;

use Legitrum\Analyzer\Auth\LegitruAuthClient;
use PHPUnit\Framework\TestCase;

/**
 * Verifies that TLS encryption options are correctly configured
 * on all network clients in the application.
 */
class EncryptionComplianceTest extends TestCase
{
    public function testNonLocalClientEnforcesTls12(): void
    {
        $client = new LegitruAuthClient('test-token', 'https://app.legitrum.pt');

        $ref = new \ReflectionClass($client);
        $prop = $ref->getProperty('client');
        $prop->setAccessible(true);
        $guzzle = $prop->getValue($client);

        $config = $guzzle->getConfig();

        // Certificate verification must be enabled for non-local
        $this->assertTrue($config['verify'], 'Certificate verification must be enabled for non-local servers');

        // TLS 1.2 minimum must be set
        $this->assertArrayHasKey('curl', $config);
        $this->assertArrayHasKey(CURLOPT_SSLVERSION, $config['curl']);
        $this->assertSame(CURL_SSLVERSION_TLSv1_2, $config['curl'][CURLOPT_SSLVERSION]);
    }

    public function testLocalClientDisablesCertVerification(): void
    {
        $client = new LegitruAuthClient('test-token', 'http://localhost:8000');

        $ref = new \ReflectionClass($client);
        $prop = $ref->getProperty('client');
        $prop->setAccessible(true);
        $guzzle = $prop->getValue($client);

        $config = $guzzle->getConfig();

        // Local servers: verification disabled (no certs in dev)
        $this->assertFalse($config['verify']);

        // Local servers: no TLS version constraint (plain HTTP)
        $this->assertEmpty($config['curl']);
    }

    public function testDockerInternalDisablesCertVerification(): void
    {
        $client = new LegitruAuthClient('test-token', 'http://host.docker.internal:8000');

        $ref = new \ReflectionClass($client);
        $prop = $ref->getProperty('client');
        $prop->setAccessible(true);
        $guzzle = $prop->getValue($client);

        $config = $guzzle->getConfig();

        $this->assertFalse($config['verify']);
    }

    public function testInternalDomainEnforcesTls(): void
    {
        $client = new LegitruAuthClient('test-token', 'https://analyzer.legitrum.internal');

        $ref = new \ReflectionClass($client);
        $prop = $ref->getProperty('client');
        $prop->setAccessible(true);
        $guzzle = $prop->getValue($client);

        $config = $guzzle->getConfig();

        $this->assertTrue($config['verify']);
        $this->assertSame(CURL_SSLVERSION_TLSv1_2, $config['curl'][CURLOPT_SSLVERSION]);
    }

    public function testBearerTokenInHeaders(): void
    {
        $client = new LegitruAuthClient('my-secret-token', 'https://app.legitrum.pt');

        $ref = new \ReflectionClass($client);
        $prop = $ref->getProperty('client');
        $prop->setAccessible(true);
        $guzzle = $prop->getValue($client);

        $headers = $guzzle->getConfig('headers');

        $this->assertSame('Bearer my-secret-token', $headers['Authorization']);
        $this->assertSame('application/json', $headers['Accept']);
    }

    public function testTimeoutIsSet(): void
    {
        $client = new LegitruAuthClient('test-token', 'https://app.legitrum.pt');

        $ref = new \ReflectionClass($client);
        $prop = $ref->getProperty('client');
        $prop->setAccessible(true);
        $guzzle = $prop->getValue($client);

        $this->assertSame(30, $guzzle->getConfig('timeout'));
    }
}
