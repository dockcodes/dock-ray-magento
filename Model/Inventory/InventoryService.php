<?php

declare(strict_types=1);

namespace DockCodes\DockRay\Model\Inventory;

use DockCodes\DockRay\Model\Config;
use DockCodes\DockRay\Model\Version;
use Magento\Framework\Lock\LockManagerInterface;
use Symfony\Component\HttpClient\HttpClient;
use Symfony\Contracts\HttpClient\HttpClientInterface;

/**
 * Opt-in software inventory for DockRay's vulnerability checks.
 *
 * Sending never happens while a page renders: Magento cron calls `tick()`
 * every fifteen minutes, and the tick sends only when
 *
 * - the interval DockRay asked for has passed (`next_report_in`, clamped to
 *   1 hour … 7 days, 12 hours by default), or
 * - the installed software changed since the last report - a deployment,
 *   `composer update`, a module switched on or off.
 *
 * A database lock keeps two cron runs (or a cron run and the "Send now"
 * button) from sending at the same time.
 */
class InventoryService
{
    public const SEVERITIES = ['critical', 'high', 'medium', 'low', 'unknown'];

    private const LOCK = 'dockray_inventory';

    private const DEFAULT_INTERVAL = 43200;

    private const MIN_INTERVAL = 3600;

    private const MAX_INTERVAL = 604800;

    private const MAX_ITEMS = 50;

    private const MAX_RESPONSE_BYTES = 262144;

    private ?HttpClientInterface $http = null;

    public function __construct(
        private readonly Config $config,
        private readonly Collector $collector,
        private readonly State $state,
        private readonly LockManagerInterface $lockManager,
    ) {
    }

    /** The option is on and the module has the credentials to authenticate. */
    public function isEnabled(): bool
    {
        try {
            return $this->config->inventory() && $this->config->isConfigured();
        } catch (\Throwable) {
            return false;
        }
    }

    public function lastResult(): ?array
    {
        return $this->state->lastResult();
    }

    /** The cron entry point. Cheap when nothing is due. */
    public function tick(): ?array
    {
        if (! $this->isEnabled()) {
            return null;
        }

        $last = $this->state->lastResult();
        $due = $last === null || time() >= (int) ($last['next_at'] ?? 0);

        if ($due) {
            return $this->run('schedule');
        }

        // A change is worth reporting early - except while DockRay asked us
        // to back off.
        if (($last['error'] ?? null) === 'rate_limited') {
            return null;
        }

        $payload = $this->collector->payload();

        if (($last['fingerprint'] ?? null) !== $this->collector->fingerprint($payload)) {
            return $this->run('change', $payload);
        }

        return null;
    }

    /**
     * Builds and sends one report, stores the outcome and returns it. Returns
     * null without sending when another run holds the lock or the feature is
     * off. Never throws.
     */
    public function run(string $trigger, ?array $payload = null): ?array
    {
        if (! $this->isEnabled()) {
            return null;
        }

        try {
            if (! $this->lockManager->lock(self::LOCK, 0)) {
                return null;
            }
        } catch (\Throwable) {
            return null;
        }

        try {
            $payload ??= $this->collector->payload();
            $result = $this->send($payload, $trigger);
            $result['fingerprint'] = $this->collector->fingerprint($payload);
        } catch (\Throwable) {
            error_log('DockRay could not send the software inventory.');
            $result = $this->failure('unexpected', 0, '', $trigger, self::DEFAULT_INTERVAL);
        } finally {
            try {
                $this->lockManager->unlock(self::LOCK);
            } catch (\Throwable) {
            }
        }

        $this->state->saveResult($result);

        return $result;
    }

    /**
     * The inventory endpoint for the configured server, or null when the
     * server URL is not HTTPS - the private key never travels in clear text.
     */
    public function endpoint(): ?string
    {
        $token = $this->config->token();
        $parts = parse_url($this->config->serverUrl());

        if ($token === '' || ! is_array($parts) || strtolower($parts['scheme'] ?? '') !== 'https' || empty($parts['host'])) {
            return null;
        }

        $base = 'https://'.$parts['host'].(isset($parts['port']) ? ':'.(int) $parts['port'] : '').rtrim($parts['path'] ?? '', '/');

        return $base.'/api/v1/'.rawurlencode($token).'/inventory';
    }

    /**
     * The `url` of an item, only when it is HTTPS and on the same host as the
     * configured server - anything else is shown as plain text.
     */
    public function safeItemUrl(string $url): ?string
    {
        if ($url === '') {
            return null;
        }

        $item = parse_url($url);
        $server = parse_url($this->config->serverUrl());

        if (! is_array($item) || ! is_array($server) || strtolower($item['scheme'] ?? '') !== 'https'
            || empty($item['host']) || empty($server['host'])
            || strtolower($item['host']) !== strtolower($server['host'])
            || isset($item['user']) || isset($item['pass'])) {
            return null;
        }

        return $url;
    }

    private function send(array $payload, string $trigger): array
    {
        $endpoint = $this->endpoint();
        $key = $this->config->privateKey();

        if ($endpoint === null || $key === '' || preg_match('/[\x00-\x20\x7f]/', $key) === 1) {
            return $this->failure('not_configured', 0, '', $trigger, self::DEFAULT_INTERVAL);
        }

        try {
            $response = $this->http()->request('POST', $endpoint, [
                'headers' => [
                    'Authorization' => 'Bearer '.$key,
                    'Content-Type' => 'application/json',
                    'Accept' => 'application/json',
                    'User-Agent' => 'dockray-magento/'.Version::VERSION,
                ],
                'body' => (string) json_encode($payload, JSON_UNESCAPED_SLASHES),
                'max_redirects' => 0,
                'verify_peer' => true,
                'verify_host' => true,
                'timeout' => 5,
                'max_duration' => 10,
            ]);

            $status = $response->getStatusCode();
            $content = '';

            foreach ($this->http()->stream($response) as $chunk) {
                $content .= $chunk->getContent();

                if (strlen($content) > self::MAX_RESPONSE_BYTES) {
                    $response->cancel();

                    break;
                }
            }
        } catch (\Throwable) {
            return $this->serverFailure('network', 0, $trigger);
        }

        $body = json_decode($content, true);
        $body = is_array($body) ? $body : [];
        $message = isset($body['message']) && is_scalar($body['message']) ? (string) $body['message'] : '';

        if ($status === 200 && ($body['success'] ?? false) === true) {
            return $this->success($body, count($payload['components']), $trigger);
        }

        return match (true) {
            $status === 401 => $this->failure('unauthorized', $status, $message, $trigger, self::DEFAULT_INTERVAL),
            $status === 404 => $this->failure('not_found', $status, $message, $trigger, self::DEFAULT_INTERVAL),
            $status === 422 => $this->failure('invalid', $status, $message, $trigger, self::DEFAULT_INTERVAL),
            // Back off until the next regular run.
            $status === 429 => $this->failure('rate_limited', $status, $message, $trigger, self::DEFAULT_INTERVAL),
            $status >= 500 => $this->serverFailure('server', $status, $trigger),
            default => $this->failure('unexpected', $status, $message, $trigger, self::DEFAULT_INTERVAL),
        };
    }

    private function success(array $body, int $sent, string $trigger): array
    {
        $interval = isset($body['next_report_in']) && is_numeric($body['next_report_in'])
            ? (int) $body['next_report_in']
            : self::DEFAULT_INTERVAL;
        $interval = max(self::MIN_INTERVAL, min(self::MAX_INTERVAL, $interval));

        $items = [];

        foreach (array_slice(is_array($body['items'] ?? null) ? $body['items'] : [], 0, self::MAX_ITEMS) as $item) {
            if (! is_array($item)) {
                continue;
            }

            $severity = strtolower(self::text($item['severity'] ?? '', 16));

            $items[] = [
                'type' => self::text($item['type'] ?? '', 32),
                'slug' => self::text($item['slug'] ?? '', 191),
                'version' => self::text($item['version'] ?? '', 64),
                'severity' => in_array($severity, self::SEVERITIES, true) ? $severity : 'unknown',
                'title' => self::text($item['title'] ?? '', 500),
                'fixed_in' => isset($item['fixed_in']) && is_scalar($item['fixed_in']) && $item['fixed_in'] !== '' ? self::text($item['fixed_in'], 64) : null,
                'url' => self::text($item['url'] ?? '', 2048),
            ];
        }

        $now = time();

        return [
            'at' => $now,
            'trigger' => $trigger,
            'success' => true,
            'error' => null,
            'status' => 200,
            'message' => '',
            'next_at' => $now + $interval,
            'retry_scheduled' => false,
            'report' => [
                'at' => $now,
                'components' => isset($body['components']) && is_numeric($body['components']) ? (int) $body['components'] : $sent,
                'vulnerable' => isset($body['vulnerable']) && is_numeric($body['vulnerable']) ? (int) $body['vulnerable'] : count($items),
                'unverified' => isset($body['unverified']) && is_numeric($body['unverified']) ? (int) $body['unverified'] : 0,
                'items' => $items,
            ],
        ];
    }

    /**
     * 5xx and timeouts get one retry no sooner than an hour later. When that
     * retry fails too, the next attempt waits for the regular interval.
     */
    private function serverFailure(string $error, int $status, string $trigger): array
    {
        $previous = $this->state->lastResult();
        $wasRetry = $previous !== null
            && in_array($previous['error'] ?? null, ['server', 'network'], true)
            && ! empty($previous['retry_scheduled']);

        $result = $this->failure($error, $status, '', $trigger, $wasRetry ? self::DEFAULT_INTERVAL : self::MIN_INTERVAL);
        $result['retry_scheduled'] = ! $wasRetry;

        return $result;
    }

    /**
     * A failed attempt keeps the findings of the last successful report: a
     * network hiccup must not wipe the warnings off the admin.
     */
    private function failure(string $error, int $status, string $message, string $trigger, int $retryIn): array
    {
        $now = time();
        $previous = $this->state->lastResult();

        return [
            'at' => $now,
            'trigger' => $trigger,
            'success' => false,
            'error' => $error,
            'status' => $status,
            'message' => self::text($message, 500),
            'next_at' => $now + $retryIn,
            'retry_scheduled' => false,
            'report' => is_array($previous['report'] ?? null) ? $previous['report'] : null,
        ];
    }

    /**
     * Server data is untrusted: bounded length, no control characters, and
     * escaped on output. Not strip_tags(): advisory titles carry version
     * ranges, and strip_tags() takes "<= 2.0.1" for a tag and drops the rest.
     */
    private static function text(mixed $value, int $limit): string
    {
        if (! is_scalar($value)) {
            return '';
        }

        return mb_substr(trim((string) preg_replace('/[\x00-\x1F\x7F]+/u', ' ', (string) $value)), 0, $limit);
    }

    private function http(): HttpClientInterface
    {
        return $this->http ??= HttpClient::create();
    }
}
