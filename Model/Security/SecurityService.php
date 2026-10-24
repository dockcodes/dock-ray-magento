<?php

declare(strict_types=1);

namespace DockCodes\DockRay\Model\Security;

use DockCodes\DockRay\Model\Config;
use DockCodes\DockRay\Model\Version;
use Magento\Framework\App\ProductMetadataInterface;
use Magento\Framework\Lock\LockManagerInterface;
use Symfony\Component\HttpClient\HttpClient;
use Symfony\Contracts\HttpClient\HttpClientInterface;

/**
 * Opt-in security report: integrity of the store's code and its
 * security-relevant settings, sent to `POST /api/v1/{token}/security` for
 * DockRay to compare with the baseline of earlier reports. Contract:
 * `docs/security-report.md` in DockRay.
 *
 * Sending never happens while a page renders: Magento cron calls `tick()`
 * every five minutes (in its own `dockray` group and process), and the tick
 * scans and sends only when
 *
 * - the interval DockRay asked for has passed (`next_report_in`, clamped to
 *   1 … 24 hours, 6 hours by default; an hour after a scan that stopped at
 *   its limit, so it continues from the hash cache), or
 * - the installed software changed (Composer packages, enabled modules, the
 *   release) and nothing else changed for a minute.
 *
 * A database lock keeps two runs (or a run and the "Send now" button) apart.
 * The body carries hashes, sizes, paths relative to the Magento root,
 * indicator names and booleans - no file contents, absolute paths, users or
 * configuration values. The per-file hash cache lives in
 * `var/dockray/security.php`, everything else in the `flag` table.
 */
class SecurityService
{
    public const SEVERITIES = ['critical', 'high', 'medium', 'low', 'unknown'];

    /** Scan time for cron and the console - its own process, nothing waits for it. */
    public const TIME_LIMIT = 60.0;

    /** Scan time for the admin button: an admin waits for the answer. */
    public const WEB_TIME_LIMIT = 20.0;

    /** Relative to `var/`. Starts with an exit line in case `var/` is ever served. */
    public const CACHE_FILE = 'dockray/security.php';

    private const CACHE_GUARD = "<?php exit; ?>\n";

    private const LOCK = 'dockray_security';

    private const DEFAULT_INTERVAL = 21600;

    private const MIN_INTERVAL = 3600;

    private const MAX_INTERVAL = 86400;

    /** A change is reported once nothing else changed for a minute - ten module updates, one report. */
    private const DEBOUNCE = 60;

    /** A scan that started this recently and left no result was killed; the tick waits. */
    private const ATTEMPT_GAP = 900;

    private const CONNECT_TIMEOUT = 5;

    private const TIMEOUT = 20;

    private const MAX_BODY_BYTES = 2097152;

    private const MAX_RESPONSE_BYTES = 262144;

    private const MAX_ITEMS = 50;

    /** The stored result stays well inside a `flag` row. */
    private const MAX_STORED_BYTES = 60000;

    private ?HttpClientInterface $http = null;

    public function __construct(
        private readonly Config $config,
        private readonly ReportBuilder $builder,
        private readonly State $state,
        private readonly WebPosture $webPosture,
        private readonly LockManagerInterface $lockManager,
        private readonly ProductMetadataInterface $productMetadata,
    ) {
    }

    /** The option is on and the module has the credentials to authenticate. */
    public function isEnabled(): bool
    {
        try {
            return $this->config->security() && $this->config->isConfigured();
        } catch (\Throwable) {
            return false;
        }
    }

    public function lastResult(): ?array
    {
        try {
            return $this->state->lastResult();
        } catch (\Throwable) {
            return null;
        }
    }

    /** When the SAPI-dependent posture was last measured in a web request; null when never. */
    public function webPostureMeasuredAt(): ?int
    {
        return $this->webPosture->measuredAt();
    }

    /** The cron entry point. Cheap when nothing is due. */
    public function tick(): ?array
    {
        if (! $this->isEnabled()) {
            return null;
        }

        $now = time();
        $schedule = $this->state->schedule();
        $fingerprint = $this->fingerprint();

        // A deployment starts the debounce; the report waits until it settled.
        if ($schedule['fingerprint'] !== $fingerprint) {
            $schedule['fingerprint'] = $fingerprint;
            $schedule['seen_at'] = $now;
            $this->state->saveSchedule($schedule);
        }

        if ($schedule['attempt_at'] > 0 && $now - $schedule['attempt_at'] < self::ATTEMPT_GAP) {
            return null;
        }

        $last = $this->state->lastResult();

        if ($last === null || $now >= (int) ($last['next_at'] ?? 0)) {
            return $this->run('schedule');
        }

        // A change is worth reporting early - except while DockRay asked us
        // to back off or had trouble of its own.
        if (in_array($last['error'] ?? null, ['rate_limited', 'server', 'network'], true)) {
            return null;
        }

        if (($last['fingerprint'] ?? null) !== $fingerprint && $now - $schedule['seen_at'] >= self::DEBOUNCE) {
            return $this->run('change');
        }

        return null;
    }

    /**
     * Scans, sends one report, stores the outcome and returns it. Returns
     * null without sending when another run holds the lock or the feature is
     * off. Never throws.
     */
    public function run(string $trigger, float $timeLimit = self::TIME_LIMIT): ?array
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

        $fingerprint = null;

        try {
            $fingerprint = $this->fingerprint();
            $schedule = $this->state->schedule();
            $schedule['attempt_at'] = time();
            $this->state->saveSchedule($schedule);

            $result = $this->send($trigger, $timeLimit);
        } catch (\Throwable) {
            // Not the exception text: transport messages can carry URLs.
            error_log('DockRay could not send the security report.');
            $result = $this->failure('unexpected', 0, '', $trigger);
        } finally {
            try {
                $this->lockManager->unlock(self::LOCK);
            } catch (\Throwable) {
            }
        }

        $result['fingerprint'] = $fingerprint;

        try {
            $this->state->saveResult($this->fit($result));
            $schedule = $this->state->schedule();
            $schedule['attempt_at'] = 0;
            $this->state->saveSchedule($schedule);
        } catch (\Throwable) {
            error_log('DockRay could not store the security report result.');
        }

        return $result;
    }

    /**
     * The security endpoint for the configured server, or null when the
     * server URL is not HTTPS - the private key never travels in clear text.
     */
    public function endpoint(): ?string
    {
        $token = $this->config->token();
        $parts = parse_url($this->config->serverUrl());

        if ($token === '' || ! is_array($parts) || strtolower($parts['scheme'] ?? '') !== 'https' || empty($parts['host'])
            || isset($parts['user']) || isset($parts['pass'])) {
            return null;
        }

        $base = 'https://'.$parts['host'].(isset($parts['port']) ? ':'.(int) $parts['port'] : '').rtrim($parts['path'] ?? '', '/');

        return $base.'/api/v1/'.rawurlencode($token).'/security';
    }

    /**
     * A link from DockRay's answer, only when it is HTTPS on the configured
     * server's host and port - anything else is shown as plain text.
     */
    public function safeItemUrl(?string $url): ?string
    {
        if ($url === null || $url === '' || preg_match('/[\x00-\x20\x7f]/', $url) === 1) {
            return null;
        }

        $item = parse_url($url);
        $server = parse_url($this->config->serverUrl());

        if (! is_array($item) || ! is_array($server) || strtolower($item['scheme'] ?? '') !== 'https'
            || empty($item['host']) || empty($server['host'])
            || strtolower($item['host']) !== strtolower($server['host'])
            || ($item['port'] ?? 443) !== ($server['port'] ?? 443)
            || isset($item['user']) || isset($item['pass'])) {
            return null;
        }

        return $url;
    }

    /**
     * Builds the report body from the installation and keeps the hash cache
     * for the next run.
     *
     * @return array<string, mixed>
     */
    public function payload(float $timeLimit = self::TIME_LIMIT, ?int $now = null): array
    {
        $built = $this->builder->build($this->config->rootDirectory(), [
            'platform_version' => (string) $this->productMetadata->getVersion(),
            'site_url' => $this->config->siteUrl(),
            'agent_version' => Version::VERSION,
            'release' => $this->config->configuredRelease(),
            // Measured in a web request, never here: cron and the console have
            // their own php.ini. The deploy mode is the same everywhere.
            'posture' => $this->webPosture->stored() + ['dev_mode' => $this->config->developerMode()],
        ], $this->readCache(), $now ?? time(), $timeLimit);

        $this->writeCache($built['cache']);

        return $built['payload'];
    }

    /**
     * What changes with a deployment: the installed Composer packages, the
     * enabled modules and the release.
     */
    public function fingerprint(): string
    {
        $root = $this->config->rootDirectory();
        $installed = @hash_file('sha256', $root.'/vendor/composer/installed.json');
        $modules = @hash_file('sha256', $root.'/app/etc/config.php');

        return hash('sha256', implode('|', [
            is_string($installed) ? $installed : '',
            is_string($modules) ? $modules : '',
            (string) $this->config->release(),
        ]));
    }

    protected function http(): HttpClientInterface
    {
        return $this->http ??= HttpClient::create();
    }

    private function send(string $trigger, float $timeLimit): array
    {
        $key = $this->config->privateKey();

        if ($this->config->token() === '' || $key === '' || preg_match('/[\x00-\x20\x7f]/', $key) === 1) {
            return $this->failure('not_configured', 0, '', $trigger);
        }

        $endpoint = $this->endpoint();

        if ($endpoint === null) {
            return $this->failure('not_https', 0, '', $trigger);
        }

        if (! in_array(PHP_SAPI, ['cli', 'phpdbg'], true) && function_exists('set_time_limit')) {
            // The scan plus the request must end before PHP's limit kills them half-way.
            @set_time_limit((int) ceil($timeLimit) + self::TIMEOUT + 60);
        }

        $payload = $this->payload($timeLimit);
        $scan = [
            'files' => (int) $payload['scan']['files'],
            'duration_ms' => (int) $payload['scan']['duration_ms'],
            'truncated' => (bool) $payload['scan']['truncated'],
        ];
        $body = json_encode($payload, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_INVALID_UTF8_SUBSTITUTE);

        if (! is_string($body) || strlen($body) > self::MAX_BODY_BYTES) {
            return $this->failure('too_large', 0, '', $trigger, $scan);
        }

        try {
            $response = $this->http()->request('POST', $endpoint, [
                'headers' => [
                    'Authorization' => 'Bearer '.$key,
                    'Content-Type' => 'application/json',
                    'Accept' => 'application/json',
                    'User-Agent' => 'dockray-magento/'.Version::VERSION,
                ],
                'body' => $body,
                'max_redirects' => 0,
                'verify_peer' => true,
                'verify_host' => true,
                'timeout' => self::CONNECT_TIMEOUT,
                'max_duration' => self::TIMEOUT,
            ]);

            $status = $response->getStatusCode();
            $content = '';

            foreach ($this->http()->stream($response) as $chunk) {
                $content .= $chunk->getContent();

                if (strlen($content) > self::MAX_RESPONSE_BYTES) {
                    $response->cancel();
                    $content = '';

                    break;
                }
            }
        } catch (\Throwable) {
            return $this->serverFailure('network', 0, $trigger, $scan);
        }

        $answer = json_decode($content, true);
        $answer = is_array($answer) ? $answer : [];
        $message = isset($answer['message']) && is_scalar($answer['message']) ? (string) $answer['message'] : '';

        if ($status === 200 && ($answer['success'] ?? false) === true) {
            return $this->success($answer, $trigger, $scan);
        }

        return match (true) {
            $status === 401 => $this->failure('unauthorized', $status, $message, $trigger, $scan),
            $status === 404 => $this->failure('not_found', $status, $message, $trigger, $scan),
            $status === 413 => $this->failure('too_large', $status, $message, $trigger, $scan),
            $status === 422 => $this->failure('invalid', $status, $message, $trigger, $scan),
            // Back off until the next regular run.
            $status === 429 => $this->failure('rate_limited', $status, $message, $trigger, $scan),
            $status >= 500 => $this->serverFailure('server', $status, $trigger, $scan),
            default => $this->failure('unexpected', $status, $message, $trigger, $scan),
        };
    }

    /** @param array{files: int, duration_ms: int, truncated: bool} $scan */
    private function success(array $answer, string $trigger, array $scan): array
    {
        $interval = isset($answer['next_report_in']) && is_numeric($answer['next_report_in'])
            ? (int) $answer['next_report_in']
            : self::DEFAULT_INTERVAL;
        $interval = max(self::MIN_INTERVAL, min(self::MAX_INTERVAL, $interval));
        $now = time();

        return [
            'at' => $now,
            'trigger' => $trigger,
            'success' => true,
            'error' => null,
            'status' => 200,
            'message' => '',
            'interval' => $interval,
            // A truncated scan continues from the hash cache an hour later
            // instead of waiting for the regular interval.
            'next_at' => $now + ($scan['truncated'] ? self::MIN_INTERVAL : $interval),
            'retry_scheduled' => false,
            'scan' => $scan,
            'report' => [
                'at' => $now,
                'findings' => $this->findings($answer['findings'] ?? []),
                'items' => $this->items($answer['items'] ?? []),
                'truncated' => $scan['truncated'],
            ],
        ];
    }

    /**
     * 5xx and timeouts get one retry no sooner than an hour later. When that
     * retry fails too, the next attempt waits for the regular interval.
     *
     * @param array{files: int, duration_ms: int, truncated: bool}|null $scan
     */
    private function serverFailure(string $error, int $status, string $trigger, ?array $scan): array
    {
        $previous = $this->lastResult();
        $wasRetry = $previous !== null
            && in_array($previous['error'] ?? null, ['server', 'network'], true)
            && ! empty($previous['retry_scheduled']);

        $result = $this->failure($error, $status, '', $trigger, $scan, $wasRetry ? null : self::MIN_INTERVAL);
        $result['retry_scheduled'] = ! $wasRetry;

        return $result;
    }

    /**
     * A failed attempt keeps the findings of the last successful report: a
     * network hiccup must not wipe the warnings off the admin.
     *
     * @param array{files: int, duration_ms: int, truncated: bool}|null $scan
     */
    private function failure(string $error, int $status, string $message, string $trigger, ?array $scan = null, ?int $retryIn = null): array
    {
        $now = time();
        $previous = $this->lastResult();
        $interval = isset($previous['interval']) && is_numeric($previous['interval'])
            ? max(self::MIN_INTERVAL, min(self::MAX_INTERVAL, (int) $previous['interval']))
            : self::DEFAULT_INTERVAL;

        return [
            'at' => $now,
            'trigger' => $trigger,
            'success' => false,
            'error' => $error,
            'status' => $status,
            'message' => self::text($message, 500),
            'interval' => $interval,
            'next_at' => $now + ($retryIn ?? $interval),
            'retry_scheduled' => false,
            'scan' => $scan,
            'report' => is_array($previous['report'] ?? null) ? $previous['report'] : null,
        ];
    }

    /**
     * Server data is untrusted: open-finding counts as non-negative integers.
     *
     * @return array<string, int>
     */
    private function findings(mixed $findings): array
    {
        $counts = [];

        foreach (['critical', 'high', 'medium', 'low'] as $severity) {
            $value = is_array($findings) ? ($findings[$severity] ?? 0) : 0;
            $counts[$severity] = is_numeric($value) ? max(0, (int) $value) : 0;
        }

        return $counts;
    }

    /**
     * Server data is untrusted: only the expected fields, as plain strings of
     * bounded length without control characters, links only to the DockRay
     * server. Escaped again on output.
     *
     * @return list<array{code: string|null, severity: string, subject: string, title: string, url: string|null}>
     */
    private function items(mixed $items): array
    {
        if (! is_array($items)) {
            return [];
        }

        $clean = [];

        foreach (array_slice($items, 0, self::MAX_ITEMS) as $item) {
            if (! is_array($item)) {
                continue;
            }

            $severity = strtolower(self::text($item['severity'] ?? '', 16));
            $code = self::text($item['code'] ?? '', 64);

            $clean[] = [
                'code' => preg_match('/^[a-z0-9_]+$/', $code) === 1 ? $code : null,
                'severity' => in_array($severity, self::SEVERITIES, true) ? $severity : 'unknown',
                'subject' => self::text($item['subject'] ?? '', 255),
                'title' => self::text($item['title'] ?? '', 300),
                'url' => $this->safeItemUrl(self::text($item['url'] ?? '', 500)),
            ];
        }

        return $clean;
    }

    /** Drops list items rather than lose the whole stored result to the row size. */
    private function fit(array $result): array
    {
        while (is_array($result['report']['items'] ?? null) && $result['report']['items'] !== []
            && strlen((string) json_encode($result, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_INVALID_UTF8_SUBSTITUTE)) > self::MAX_STORED_BYTES) {
            array_pop($result['report']['items']);
        }

        return $result;
    }

    private function cacheFile(): string
    {
        return $this->config->varDirectory().'/'.self::CACHE_FILE;
    }

    /** @return array<string, mixed> */
    private function readCache(): array
    {
        try {
            $file = $this->cacheFile();
        } catch (\Throwable) {
            return [];
        }

        if (! is_file($file) || is_link($file)) {
            return [];
        }

        $raw = @file_get_contents($file);

        if (! is_string($raw) || strncmp($raw, self::CACHE_GUARD, strlen(self::CACHE_GUARD)) !== 0) {
            return [];
        }

        $cache = json_decode(substr($raw, strlen(self::CACHE_GUARD)), true);

        return is_array($cache) ? $cache : [];
    }

    /**
     * Written under the lock, through a temporary file and a rename, so a
     * killed run leaves the previous cache rather than half a file. Private
     * to the owner: it lists the paths of the code.
     *
     * @param array<string, mixed> $cache
     */
    private function writeCache(array $cache): void
    {
        $file = $this->cacheFile();
        $directory = dirname($file);

        if ((! is_dir($directory) && ! @mkdir($directory, 0700, true) && ! is_dir($directory)) || is_link($directory) || is_link($file)) {
            return;
        }

        $body = json_encode($cache, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_INVALID_UTF8_SUBSTITUTE);

        if (! is_string($body)) {
            return;
        }

        $temporary = $file.'.'.bin2hex(random_bytes(4)).'.tmp';

        if (@file_put_contents($temporary, self::CACHE_GUARD.$body) === false || ! @chmod($temporary, 0600) || ! @rename($temporary, $file)) {
            @unlink($temporary);
        }
    }

    /**
     * Bounded plain text. Not strip_tags(): titles may carry "<" in version
     * ranges, and strip_tags() drops everything after it.
     */
    private static function text(mixed $value, int $limit): string
    {
        if (! is_scalar($value)) {
            return '';
        }

        return mb_substr(trim((string) preg_replace('/[\x00-\x1F\x7F]+/u', ' ', (string) $value)), 0, $limit);
    }
}
