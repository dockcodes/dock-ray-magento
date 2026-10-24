<?php

declare(strict_types=1);

namespace DockCodes\DockRay\Model\Security;

use Magento\Framework\FlagManager;

/**
 * What the security report remembers between runs, in Magento's `flag`
 * table: the last result (shown in the admin), the software fingerprint
 * that starts the debounce after a deployment, and the posture measured in a
 * web request for the reports cron builds. The per-file hash cache is too
 * large for a row and lives in `var/dockray/` (see `SecurityService`).
 * Uninstalling the module removes all of it.
 */
class State
{
    public const RESULT = 'dockray_security_result';

    public const SCHEDULE = 'dockray_security_schedule';

    public const WEB_POSTURE = 'dockray_security_web_posture';

    public const FLAGS = [self::RESULT, self::SCHEDULE, self::WEB_POSTURE];

    public function __construct(private readonly FlagManager $flagManager)
    {
    }

    public function lastResult(): ?array
    {
        return $this->read(self::RESULT);
    }

    public function saveResult(array $result): void
    {
        $this->flagManager->saveFlag(self::RESULT, $result);
    }

    /**
     * The software fingerprint last seen by the cron tick and since when, and
     * when a scan last started - a scan killed half-way (memory, a deploy)
     * must not turn every tick into a new one.
     *
     * @return array{fingerprint: string|null, seen_at: int, attempt_at: int}
     */
    public function schedule(): array
    {
        $schedule = $this->read(self::SCHEDULE) ?? [];

        return [
            'fingerprint' => is_string($schedule['fingerprint'] ?? null) ? $schedule['fingerprint'] : null,
            'seen_at' => (int) ($schedule['seen_at'] ?? 0),
            'attempt_at' => (int) ($schedule['attempt_at'] ?? 0),
        ];
    }

    /** @param array{fingerprint: string|null, seen_at: int, attempt_at: int} $schedule */
    public function saveSchedule(array $schedule): void
    {
        $this->flagManager->saveFlag(self::SCHEDULE, $schedule);
    }

    /** @return array{at: int, values: array<string, bool>}|null */
    public function webPosture(): ?array
    {
        $stored = $this->read(self::WEB_POSTURE);

        if (! is_array($stored) || ! is_array($stored['values'] ?? null)) {
            return null;
        }

        $values = [];

        foreach ($stored['values'] as $key => $value) {
            if (is_string($key) && is_bool($value)) {
                $values[$key] = $value;
            }
        }

        return ['at' => (int) ($stored['at'] ?? 0), 'values' => $values];
    }

    /** @param array<string, bool> $values */
    public function saveWebPosture(array $values, int $at): void
    {
        $this->flagManager->saveFlag(self::WEB_POSTURE, ['at' => $at, 'values' => $values]);
    }

    public function clear(): void
    {
        foreach (self::FLAGS as $flag) {
            $this->flagManager->deleteFlag($flag);
        }
    }

    private function read(string $flag): ?array
    {
        $data = $this->flagManager->getFlagData($flag);

        return is_array($data) ? $data : null;
    }
}
