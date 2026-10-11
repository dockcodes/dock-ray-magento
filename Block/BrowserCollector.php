<?php

declare(strict_types=1);

namespace DockCodes\DockRay\Block;

use Dock\Ray\Browser\Collector;
use DockCodes\DockRay\Model\Config;
use Magento\Framework\Serialize\Serializer\Json;
use Magento\Framework\View\Element\Template;
use Magento\Framework\View\Element\Template\Context;

/**
 * Puts the collector on storefront pages.
 *
 * The block is the same for every visitor, so it survives the full page cache
 * and Varnish: the per-visitor form key is not rendered into the page, the
 * collector reads it from the `form_key` cookie when it sends a report.
 */
class BrowserCollector extends Template
{
    public function __construct(
        Context $context,
        private readonly Config $config,
        private readonly Json $json,
        array $data = [],
    ) {
        parent::__construct($context, $data);
    }

    public function isEnabled(): bool
    {
        try {
            return $this->config->jsErrors() && $this->config->isConfigured() && is_file(Collector::scriptPath());
        } catch (\Throwable) {
            return false;
        }
    }

    public function configJson(): string
    {
        return (string) $this->json->serialize(Collector::config(
            endpoint: $this->getUrl('dockray/browser/error', ['_secure' => $this->getRequest()->isSecure()]),
            release: $this->config->release(),
            sampleRate: $this->config->jsSampleRate(),
            maxEvents: 10,
            ignore: Collector::defaultIgnoreList(),
        ));
    }

    public function scriptUrl(): string
    {
        return $this->getUrl('dockray/browser/script', [
            '_secure' => $this->getRequest()->isSecure(),
            '_query' => ['v' => Collector::scriptVersion()],
        ]);
    }
}
