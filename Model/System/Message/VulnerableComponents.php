<?php

declare(strict_types=1);

namespace DockCodes\DockRay\Model\System\Message;

use DockCodes\DockRay\Model\Inventory\InventoryService;
use Magento\Framework\AuthorizationInterface;
use Magento\Framework\Escaper;
use Magento\Framework\Notification\MessageInterface;
use Magento\Framework\UrlInterface;

/**
 * A notice at the top of the admin when the last report found vulnerable
 * components - Magento's counterpart of the warning row the WordPress plugin
 * puts under a vulnerable plugin. Its identity changes with every report,
 * so a dismissed notice comes back when something new is found.
 */
class VulnerableComponents implements MessageInterface
{
    private ?array $report = null;

    public function __construct(
        private readonly InventoryService $inventory,
        private readonly AuthorizationInterface $authorization,
        private readonly UrlInterface $urlBuilder,
        private readonly Escaper $escaper,
    ) {
    }

    public function getIdentity()
    {
        $report = $this->report();

        return 'dockray_vulnerable_'.hash('sha256', (string) json_encode([$report['at'] ?? 0, $report['vulnerable'] ?? 0]));
    }

    public function isDisplayed()
    {
        if (! $this->authorization->isAllowed('DockCodes_DockRay::overview') || ! $this->inventory->isEnabled()) {
            return false;
        }

        return (int) ($this->report()['vulnerable'] ?? 0) > 0;
    }

    public function getText()
    {
        $count = (int) ($this->report()['vulnerable'] ?? 0);
        $text = $count === 1
            ? __('DockRay found a known vulnerability in 1 installed component.')
            : __('DockRay found known vulnerabilities in %1 installed components.', $count);

        return $this->escaper->escapeHtml((string) $text)
            .' <a href="'.$this->escaper->escapeUrl($this->urlBuilder->getUrl('dockray/overview/index')).'">'
            .$this->escaper->escapeHtml((string) __('See the report'))
            .'</a>';
    }

    public function getSeverity()
    {
        return self::SEVERITY_MAJOR;
    }

    private function report(): array
    {
        if ($this->report === null) {
            $result = $this->inventory->lastResult();
            $this->report = is_array($result['report'] ?? null) ? $result['report'] : [];
        }

        return $this->report;
    }
}
