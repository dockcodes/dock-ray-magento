<?php

declare(strict_types=1);

namespace DockCodes\DockRay\Controller\Adminhtml\Security;

use DockCodes\DockRay\Block\Adminhtml\Dashboard;
use DockCodes\DockRay\Model\Security\SecurityService;
use Magento\Backend\App\Action;
use Magento\Backend\App\Action\Context;
use Magento\Framework\App\Action\HttpPostActionInterface;
use Magento\Framework\Controller\Result\Json;
use Magento\Framework\Controller\Result\JsonFactory;
use Magento\Framework\View\LayoutInterface;

/**
 * "Send now" for the security report. Sends only while the option is on and
 * saved - the button must not become a way around the opt-in - scans with a
 * shorter time limit than cron (an admin waits for it) and answers with the
 * re-rendered, server-escaped report panel.
 */
class Send extends Action implements HttpPostActionInterface
{
    public const ADMIN_RESOURCE = 'DockCodes_DockRay::security';

    public function __construct(
        Context $context,
        private readonly JsonFactory $jsonFactory,
        private readonly SecurityService $security,
        private readonly LayoutInterface $layout,
    ) {
        parent::__construct($context);
    }

    public function execute(): Json
    {
        $json = $this->jsonFactory->create();

        if (! $this->security->isEnabled()) {
            return $json->setData([
                'success' => false,
                'message' => (string) __('Turn on the security report and save the settings first.'),
            ]);
        }

        $result = $this->security->run('manual', SecurityService::WEB_TIME_LIMIT);

        if ($result === null) {
            return $json->setData([
                'success' => false,
                'message' => (string) __('A report is already being sent. Try again in a moment.'),
            ]);
        }

        /** @var Dashboard $block */
        $block = $this->layout->createBlock(Dashboard::class);
        $block->setTemplate('DockCodes_DockRay::security-report.phtml')->setData('security_result', $result);

        return $json->setData([
            'success' => (bool) $result['success'],
            'message' => (string) ($result['success'] ? __('Report sent.') : $block->errorLabel($result)),
            'html' => $block->toHtml(),
        ]);
    }
}
