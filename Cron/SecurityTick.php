<?php

declare(strict_types=1);

namespace DockCodes\DockRay\Cron;

use DockCodes\DockRay\Model\Security\SecurityService;

class SecurityTick
{
    public function __construct(private readonly SecurityService $security)
    {
    }

    public function execute(): void
    {
        try {
            $this->security->tick();
        } catch (\Throwable) {
            // The service never throws while sending; this guards the cron run regardless.
        }
    }
}
