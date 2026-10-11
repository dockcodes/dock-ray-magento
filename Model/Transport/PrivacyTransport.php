<?php

declare(strict_types=1);

namespace DockCodes\DockRay\Model\Transport;

use Dock\Ray\Event;
use Dock\Ray\Options;
use Dock\Ray\Response;
use Dock\Ray\ResponseStatus;
use Dock\Ray\Transport\TransportInterface;
use DockCodes\DockRay\Model\Privacy;
use GuzzleHttp\Promise\PromiseInterface;
use GuzzleHttp\Promise\RejectedPromise;

/**
 * Filters every event before it is serialised and refuses anything but HTTPS:
 * the private key travels in the Authorization header.
 */
final class PrivacyTransport implements TransportInterface
{
    public function __construct(
        private readonly TransportInterface $inner,
        private readonly Options $options,
    ) {
    }

    public function send(Event $event): PromiseInterface
    {
        try {
            $auth = $this->options->getAuthData();

            if ($auth === null || $auth->getScheme() !== 'https') {
                return new RejectedPromise(new Response(ResponseStatus::failed(), $event));
            }

            return $this->inner->send(Privacy::filter($event, $this->options->shouldSendDefaultPii()));
        } catch (\Throwable) {
            // Reporting an error must never become another error of the store.
            return new RejectedPromise(new Response(ResponseStatus::failed(), $event));
        }
    }

    public function close(?int $timeout = null): PromiseInterface
    {
        return $this->inner->close($timeout);
    }
}
