<?php

declare(strict_types=1);

namespace DockCodes\DockRay\Model\Inventory;

use Magento\Framework\FlagManager;

/**
 * What the module remembers between runs, in Magento's `flag` table: the
 * last report (shown in the admin) and the last test of the connection.
 * Uninstalling the module removes all of it.
 */
class State
{
    public const RESULT = 'dockray_inventory_result';

    public const LAST_TEST = 'dockray_last_test';

    public const FLAGS = [self::RESULT, self::LAST_TEST];

    public function __construct(private readonly FlagManager $flagManager)
    {
    }

    public function lastResult(): ?array
    {
        $result = $this->flagManager->getFlagData(self::RESULT);

        return is_array($result) ? $result : null;
    }

    public function saveResult(array $result): void
    {
        $this->flagManager->saveFlag(self::RESULT, $result);
    }

    /** @return array{success: bool, event_id: ?string, at: int}|null */
    public function lastTest(): ?array
    {
        $result = $this->flagManager->getFlagData(self::LAST_TEST);

        return is_array($result) ? $result : null;
    }

    public function saveTest(bool $success, ?string $eventId): void
    {
        $this->flagManager->saveFlag(self::LAST_TEST, ['success' => $success, 'event_id' => $eventId, 'at' => time()]);
    }

    public function clear(): void
    {
        foreach (self::FLAGS as $flag) {
            $this->flagManager->deleteFlag($flag);
        }
    }
}
