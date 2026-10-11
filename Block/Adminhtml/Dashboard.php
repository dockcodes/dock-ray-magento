<?php

declare(strict_types=1);

namespace DockCodes\DockRay\Block\Adminhtml;

use DockCodes\DockRay\Model\Config;
use DockCodes\DockRay\Model\Inventory\InventoryService;
use DockCodes\DockRay\Model\Inventory\State;
use DockCodes\DockRay\Model\Version;
use Magento\Backend\Block\Template;
use Magento\Backend\Block\Template\Context;
use Magento\Framework\Serialize\Serializer\Json;

/**
 * Everything the DockRay screens show: the overview page, the header of the
 * configuration section and the report panel the "Send now" button
 * re-renders. Read-only - it never calls DockRay while a page is shown.
 */
class Dashboard extends Template
{
    public function __construct(
        Context $context,
        private readonly Config $config,
        private readonly InventoryService $inventory,
        private readonly State $state,
        private readonly Json $json,
        array $data = [],
    ) {
        parent::__construct($context, $data);
    }

    public function isConfigured(): bool
    {
        try {
            return $this->config->isConfigured();
        } catch (\Throwable) {
            return false;
        }
    }

    public function config(): Config
    {
        return $this->config;
    }

    public function inventoryEnabled(): bool
    {
        return $this->inventory->isEnabled();
    }

    public function inventoryResult(): ?array
    {
        return $this->hasData('result') ? $this->getData('result') : $this->inventory->lastResult();
    }

    public function lastTest(): ?array
    {
        return $this->state->lastTest();
    }

    public function version(): string
    {
        return Version::VERSION;
    }

    public function logoUrl(bool $white = false): string
    {
        return $this->getViewFileUrl('DockCodes_DockRay::images/'.($white ? 'dockray-logo-white.svg' : 'dockray-logo.svg'));
    }

    public function settingsUrl(): string
    {
        return $this->getUrl('adminhtml/system_config/edit', ['section' => 'dockray']);
    }

    public function overviewUrl(): string
    {
        return $this->getUrl('dockray/overview/index');
    }

    /** The project in the DockRay panel - always the configured server. */
    public function panelUrl(): string
    {
        return $this->config->serverUrl().'/admin';
    }

    public function canTest(): bool
    {
        return $this->_authorization->isAllowed('DockCodes_DockRay::test');
    }

    public function canSendInventory(): bool
    {
        return $this->_authorization->isAllowed('DockCodes_DockRay::inventory');
    }

    public function canConfigure(): bool
    {
        return $this->_authorization->isAllowed('DockCodes_DockRay::config');
    }

    /** Configuration for the admin script, escaped by the template as a whole. */
    public function scriptConfig(): string
    {
        return (string) $this->json->serialize([
            'testUrl' => $this->getUrl('dockray/test/send'),
            'inventoryUrl' => $this->getUrl('dockray/inventory/send'),
            'formKey' => $this->getFormKey(),
            'strings' => [
                'sending' => (string) __('Sending…'),
                'sentWithId' => (string) __('Sent. Event ID: %1'),
                'failed' => (string) __('Could not send the test event. Check the token and the private key.'),
                'connected' => (string) __('Connected - verified just now'),
                'testFailed' => (string) __('Test failed just now'),
                'inventoryFailed' => (string) __('The report could not be sent.'),
            ],
        ]);
    }

    /**
     * The four things the module does, with their current state - the tiles
     * at the top of the overview.
     *
     * @return list<array{key: string, title: string, state: string, on: bool, text: string}>
     */
    public function features(): array
    {
        $configured = $this->isConfigured();
        $rate = $this->config->tracesSampleRate();
        $js = $this->config->jsErrors();

        return [
            [
                'key' => 'errors',
                'title' => (string) __('PHP errors'),
                'on' => $configured,
                'state' => (string) ($configured ? __('On') : __('Waiting for credentials')),
                'text' => (string) __('Exceptions from controllers, REST and GraphQL, cron jobs and everything Magento logs as an error.'),
            ],
            [
                'key' => 'performance',
                'title' => (string) __('Performance'),
                'on' => $configured && $rate > 0,
                'state' => (string) ($configured && $rate > 0 ? __('%1% of requests', (string) round($rate * 100, 1)) : __('Off')),
                'text' => (string) __('Response time of every route, named after the route - not after the URL.'),
            ],
            [
                'key' => 'browser',
                'title' => (string) __('JavaScript errors'),
                'on' => $configured && $js,
                'state' => (string) ($configured && $js ? __('On') : __('Off')),
                'text' => (string) __('Errors from the storefront, forwarded by the store - the key never reaches the page.'),
            ],
            [
                'key' => 'inventory',
                'title' => (string) __('Vulnerability checks'),
                'on' => $this->inventoryEnabled(),
                'state' => (string) ($this->inventoryEnabled() ? __('On') : __('Off')),
                'text' => (string) __('Magento, Composer packages and extensions checked against known vulnerabilities.'),
            ],
        ];
    }

    public function formatTimestamp(int $timestamp): string
    {
        return (string) $this->_localeDate->formatDateTime(
            (new \DateTime('@'.$timestamp))->setTimezone(new \DateTimeZone($this->_localeDate->getConfigTimezone())),
            \IntlDateFormatter::MEDIUM,
            \IntlDateFormatter::SHORT,
        );
    }

    /** "5 minutes", "2 hours", "3 days" - in the admin user's language. */
    public function timeAgo(int $timestamp): string
    {
        $seconds = max(0, time() - $timestamp);

        return (string) match (true) {
            $seconds < 90 => __('a minute'),
            $seconds < 3600 => __('%1 minutes', (int) round($seconds / 60)),
            $seconds < 5400 => __('an hour'),
            $seconds < 86400 => __('%1 hours', (int) round($seconds / 3600)),
            $seconds < 129600 => __('a day'),
            default => __('%1 days', (int) round($seconds / 86400)),
        };
    }

    public function severityLabel(string $severity): string
    {
        return (string) match ($severity) {
            'critical' => __('Critical'),
            'high' => __('High'),
            'medium' => __('Medium'),
            'low' => __('Low'),
            default => __('Unknown severity'),
        };
    }

    public function componentTypeLabel(string $type): string
    {
        return (string) match ($type) {
            'core' => __('Core'),
            'package' => __('Composer package'),
            'module' => __('Module'),
            'theme' => __('Theme'),
            default => $type,
        };
    }

    /** Human-readable reason for a failed attempt. */
    public function errorLabel(array $result): string
    {
        return (string) match ($result['error'] ?? null) {
            'not_configured' => __('Not sent: the token or the private key is missing.'),
            'unauthorized' => __('Rejected: the private key is missing or not accepted.'),
            'not_found' => __('Rejected: the project was not found or is disabled. Check the token and the private key.'),
            'invalid' => __('Rejected: the server did not accept the report.'),
            'rate_limited' => __('Too many reports: DockRay asked to wait until the next scheduled run.'),
            'server' => __('DockRay had a server problem. The report will be retried automatically.'),
            'network' => __('DockRay could not be reached. The report will be retried automatically.'),
            default => __('The report could not be sent.'),
        };
    }

    public function safeItemUrl(string $url): ?string
    {
        return $this->inventory->safeItemUrl($url);
    }

    public function isSeverity(string $severity): bool
    {
        return in_array($severity, InventoryService::SEVERITIES, true);
    }
}
