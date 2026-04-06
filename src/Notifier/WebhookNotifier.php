<?php

namespace Legitrum\Analyzer\Notifier;

use GuzzleHttp\Client;
use GuzzleHttp\Exception\GuzzleException;
use Legitrum\Analyzer\Auth\LegitruAuthClient;
use Legitrum\Analyzer\Logging\Logger;

class WebhookNotifier
{
    private Logger $logger;

    private LegitruAuthClient $authClient;

    public function __construct(Logger $logger, LegitruAuthClient $authClient)
    {
        $this->logger = $logger;
        $this->authClient = $authClient;
    }

    public function send(string $webhookUrl, array $report): void
    {
        if (! $this->validateUrl($webhookUrl)) {
            return;
        }

        $client = new Client([
            'timeout' => 10,
            'headers' => [
                'Content-Type' => 'application/json',
                'User-Agent' => 'Legitrum-Analyzer/1.0',
            ],
        ]);

        try {
            $client->post($webhookUrl, [
                'json' => $report,
            ]);

            $this->logger->info('Webhook notification sent', [
                'event' => 'webhook_sent',
                'url' => $this->sanitizeUrl($webhookUrl),
            ]);
        } catch (GuzzleException $e) {
            $this->logger->warn('Webhook notification failed', [
                'event' => 'webhook_failed',
                'url' => $this->sanitizeUrl($webhookUrl),
                'error' => $e->getMessage(),
            ]);
        }
    }

    private function validateUrl(string $url): bool
    {
        $parsed = parse_url($url);
        if (! $parsed || ! isset($parsed['scheme']) || ! isset($parsed['host'])) {
            $this->logger->warn('Webhook URL is invalid — skipping notification', [
                'event' => 'webhook_url_invalid',
            ]);

            return false;
        }

        if (! in_array($parsed['scheme'], ['http', 'https'], true)) {
            $this->logger->warn('Webhook URL has invalid scheme — skipping notification', [
                'event' => 'webhook_url_invalid_scheme',
                'scheme' => $parsed['scheme'],
            ]);

            return false;
        }

        if (! $this->authClient->isAllowedServer($url)) {
            $this->logger->warn('Webhook URL not in allowlist — skipping notification (SSRF prevention)', [
                'event' => 'webhook_url_not_allowed',
                'host' => $parsed['host'],
            ]);

            return false;
        }

        return true;
    }

    private function sanitizeUrl(string $url): string
    {
        $parsed = parse_url($url);
        $host = $parsed['host'] ?? 'unknown';
        $path = $parsed['path'] ?? '/';

        return "{$parsed['scheme']}://{$host}{$path}";
    }
}
