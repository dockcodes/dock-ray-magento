<?php

declare(strict_types=1);

namespace DockCodes\DockRay\Controller\Browser;

use Dock\Ray\Browser\Collector;
use DockCodes\DockRay\Model\Config;
use Magento\Framework\App\Action\HttpGetActionInterface;
use Magento\Framework\Controller\Result\Raw;
use Magento\Framework\Controller\Result\RawFactory;

/**
 * Serves the collector script that ships with the PHP SDK.
 *
 * Copying it into this module's web assets would create a second copy that
 * drifts at the first fix, so the file is read from the SDK package. The URL
 * carries the file's version, which lets browsers and CDNs keep it for a year.
 */
class Script implements HttpGetActionInterface
{
    private const MAX_BYTES = 65536;

    public function __construct(
        private readonly RawFactory $rawFactory,
        private readonly Config $config,
    ) {
    }

    public function execute(): Raw
    {
        $result = $this->rawFactory->create();
        $path = Collector::scriptPath();

        if (! $this->config->jsErrors() || ! is_file($path)) {
            return $result->setHttpResponseCode(404)
                ->setHeader('Cache-Control', 'no-store', true)
                ->setContents('');
        }

        return $result
            ->setHeader('Content-Type', 'application/javascript; charset=utf-8', true)
            ->setHeader('Cache-Control', 'public, max-age=31536000, immutable', true)
            ->setHeader('Pragma', 'cache', true)
            ->setHeader('X-Content-Type-Options', 'nosniff', true)
            ->setContents((string) file_get_contents($path, false, null, 0, self::MAX_BYTES));
    }
}
