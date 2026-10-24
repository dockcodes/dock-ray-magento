<?php

declare(strict_types=1);

namespace DockCodes\DockRay\Model\Security;

use DockCodes\DockRay\Model\Config;
use Magento\Framework\App\CacheInterface;

/**
 * `display_errors`, `exec_available` and `code_writable` depend on the PHP
 * SAPI, its php.ini and the process user. The report is built by cron in the
 * CLI, which has its own php.ini and often its own user, so the values that
 * count are measured here, in a storefront, REST or GraphQL request - the
 * context visitors get - and kept for the reports.
 *
 * Cheap on purpose, it runs on every web request while the report is on: one
 * cache read decides; at most once an hour (or after a cache flush) the
 * values are measured and written to the `flag` table, which survives
 * flushes and is what cron reads. Values older than 30 days are not reported
 * any more - DockRay then keeps its earlier verdict.
 */
class WebPosture
{
    private const CACHE_KEY = 'DOCKRAY_SECURITY_WEB_POSTURE';

    private const REFRESH = 3600;

    private const MAX_AGE = 2592000;

    public function __construct(
        private readonly Config $config,
        private readonly CacheInterface $cache,
        private readonly State $state,
    ) {
    }

    /** Called after a web request was handled. Never throws. */
    public function capture(): void
    {
        try {
            if (in_array(PHP_SAPI, ['cli', 'phpdbg'], true) || ! $this->config->security()) {
                return;
            }

            $measured = $this->cache->load(self::CACHE_KEY);

            if (is_string($measured) && $measured !== '' && time() - (int) $measured < self::REFRESH) {
                return;
            }

            $now = time();
            $this->state->saveWebPosture(ReportBuilder::runtimePosture($this->config->rootDirectory()), $now);
            $this->cache->save((string) $now, self::CACHE_KEY, [], self::REFRESH);
        } catch (\Throwable) {
            // A database or cache hiccup only means the next report leaves these keys out.
        }
    }

    /**
     * The values last measured in a web request, or nothing when none was
     * measured in the last 30 days.
     *
     * @return array<string, bool>
     */
    public function stored(): array
    {
        try {
            $stored = $this->state->webPosture();
        } catch (\Throwable) {
            return [];
        }

        if ($stored === null || time() - $stored['at'] > self::MAX_AGE) {
            return [];
        }

        return array_intersect_key($stored['values'], array_flip(ReportBuilder::RUNTIME_POSTURE));
    }

    /** When the stored values were measured, for the admin; null when never. */
    public function measuredAt(): ?int
    {
        try {
            $stored = $this->state->webPosture();
        } catch (\Throwable) {
            return null;
        }

        return $stored !== null && $stored['at'] > 0 ? $stored['at'] : null;
    }
}
