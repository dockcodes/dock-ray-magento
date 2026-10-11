<?php

declare(strict_types=1);

namespace DockCodes\DockRay\Controller\Adminhtml\Test;

use DockCodes\DockRay\Model\Inventory\State;
use DockCodes\DockRay\Model\Reporter;
use Magento\Backend\App\Action;
use Magento\Backend\App\Action\Context;
use Magento\Framework\App\Action\HttpPostActionInterface;
use Magento\Framework\Controller\Result\Json;
use Magento\Framework\Controller\Result\JsonFactory;

/** "Send a test event": one exception, sent right away, answered with its id. */
class Send extends Action implements HttpPostActionInterface
{
    public const ADMIN_RESOURCE = 'DockCodes_DockRay::test';

    public function __construct(
        Context $context,
        private readonly JsonFactory $jsonFactory,
        private readonly Reporter $reporter,
        private readonly State $state,
    ) {
        parent::__construct($context);
    }

    public function execute(): Json
    {
        $result = $this->jsonFactory->create();

        if (! $this->reporter->isConfigured()) {
            $this->state->saveTest(false, null);

            return $result->setData([
                'success' => false,
                'message' => (string) __('DockRay is not configured - fill in the token and the private key first.'),
            ]);
        }

        $eventId = $this->reporter->sendTest();
        $this->state->saveTest($eventId !== null, $eventId);

        return $result->setData($eventId !== null
            ? ['success' => true, 'event_id' => $eventId]
            : ['success' => false, 'message' => (string) __('Could not send the test event. Check the token and the private key.')]);
    }
}
