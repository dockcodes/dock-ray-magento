<?php

declare(strict_types=1);

namespace DockCodes\DockRay\Cron;

use DockCodes\DockRay\Model\Inventory\InventoryService;

class InventoryTick
{
    public function __construct(private readonly InventoryService $inventory)
    {
    }

    public function execute(): void
    {
        try {
            $this->inventory->tick();
        } catch (\Throwable) {
            // The service never throws; this guards the cron run regardless.
        }
    }
}
