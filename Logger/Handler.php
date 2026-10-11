<?php

declare(strict_types=1);

namespace DockCodes\DockRay\Logger;

use Dock\Ray\Monolog\CompatibilityProcessingHandlerTrait;
use DockCodes\DockRay\Model\Reporter;
use Monolog\Handler\AbstractProcessingHandler;

/**
 * Forwards exceptions Magento logs at error level or above.
 *
 * This is where most real failures surface: controllers, REST and GraphQL
 * resolvers, payment and shipping integrations and cron jobs catch the
 * exception, call `$logger->critical($e)` and carry on. Records without an
 * exception are skipped - a bare message has no type and no stack, and its
 * text usually embeds an order or quote id, which would split one problem
 * into thousands of entries in the panel.
 */
class Handler extends AbstractProcessingHandler
{
    use CompatibilityProcessingHandlerTrait;

    /** Monolog's ERROR level, as an int understood by Monolog 2 and 3. */
    private const ERROR = 400;

    private bool $writing = false;

    public function __construct(private readonly Reporter $reporter)
    {
        parent::__construct(self::ERROR, true);
    }

    protected function doWrite(array $record): void
    {
        $exception = $record['context']['exception'] ?? null;

        if (! $exception instanceof \Throwable || $this->writing) {
            return;
        }

        // Booting the reporter may log; that record must not come back here.
        $this->writing = true;

        try {
            $this->reporter->captureException($exception);
        } catch (\Throwable) {
        } finally {
            $this->writing = false;
        }
    }
}
