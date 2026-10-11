<?php

declare(strict_types=1);

namespace DockCodes\DockRay\Controller\Browser;

use Dock\Ray\Browser\BrowserEvent;
use DockCodes\DockRay\Model\Config;
use DockCodes\DockRay\Model\Privacy;
use DockCodes\DockRay\Model\Reporter;
use Magento\Framework\App\Action\HttpPostActionInterface;
use Magento\Framework\App\CacheInterface;
use Magento\Framework\App\CsrfAwareActionInterface;
use Magento\Framework\App\Request\Http as HttpRequest;
use Magento\Framework\App\Request\InvalidRequestException;
use Magento\Framework\App\RequestInterface;
use Magento\Framework\Controller\Result\Raw;
use Magento\Framework\Controller\Result\RawFactory;
use Magento\Framework\Data\Form\FormKey;
use Magento\Framework\HTTP\PhpEnvironment\RemoteAddress;

/**
 * Receives JavaScript errors from the storefront and forwards them with the
 * store's own key - the browser never sees it.
 *
 * Three gates, the same as in every DockRay CMS integration: the form key
 * (Magento's CSRF token, read by the collector from the `form_key` cookie, so
 * it works on fully cached pages), a 16 kB body limit and 20 reports per
 * minute per IP address. The answer is always 202, whatever happened: the
 * sender learns nothing about which gate stopped it.
 */
class Error implements HttpPostActionInterface, CsrfAwareActionInterface
{
    private const MAX_BODY_BYTES = 16384;

    private const RATE_LIMIT_PER_MINUTE = 20;

    public function __construct(
        private readonly RequestInterface $request,
        private readonly RawFactory $rawFactory,
        private readonly Config $config,
        private readonly Reporter $reporter,
        private readonly FormKey $formKey,
        private readonly CacheInterface $cache,
        private readonly RemoteAddress $remoteAddress,
    ) {
    }

    public function execute(): Raw
    {
        try {
            $this->forward();
        } catch (\Throwable) {
            // A broken report must not become a storefront error.
        }

        return $this->rawFactory->create()
            ->setHttpResponseCode(202)
            ->setHeader('Content-Type', 'application/json', true)
            ->setHeader('Cache-Control', 'no-store', true)
            ->setContents('{"success":true}');
    }

    /** The form key check below replaces Magento's: it reads a header, not a field. */
    public function createCsrfValidationException(RequestInterface $request): ?InvalidRequestException
    {
        return null;
    }

    public function validateForCsrf(RequestInterface $request): ?bool
    {
        return true;
    }

    private function forward(): void
    {
        if (! $this->config->jsErrors() || ! $this->request instanceof HttpRequest) {
            return;
        }

        $body = (string) $this->request->getContent();

        if (strlen($body) > self::MAX_BODY_BYTES || ! $this->validToken() || ! $this->withinRateLimit()) {
            return;
        }

        $payload = json_decode($body, true);

        if (! is_array($payload)) {
            return;
        }

        foreach (['url', 'referrer'] as $key) {
            if (isset($payload[$key]) && is_string($payload[$key])) {
                $payload[$key] = Privacy::cleanUrl($payload[$key]);
            }
        }

        if (isset($payload['stack']) && is_array($payload['stack'])) {
            foreach ($payload['stack'] as &$frame) {
                if (is_array($frame) && isset($frame['filename']) && is_string($frame['filename'])) {
                    $frame['filename'] = Privacy::cleanUrl($frame['filename']);
                }
            }
            unset($frame);
        }

        // The envelope is built here: the browser does not choose the release.
        $event = BrowserEvent::fromArray(
            array_diff_key($payload, ['release' => true]),
            Privacy::cleanUrl((string) $this->request->getHeader('Referer')),
            $this->config->sendDefaultPii() ? (string) $this->request->getHeader('User-Agent') : null,
        );

        if ($event !== null) {
            $this->reporter->captureBrowserEvent($event);
        }
    }

    private function validToken(): bool
    {
        $sent = (string) $this->request->getHeader('X-DockRay-Token');

        return $sent !== '' && hash_equals((string) $this->formKey->getFormKey(), $sent);
    }

    private function withinRateLimit(): bool
    {
        $key = 'dockray_js_'.hash('sha256', (string) $this->remoteAddress->getRemoteAddress());
        $count = (int) $this->cache->load($key);

        if ($count >= self::RATE_LIMIT_PER_MINUTE) {
            return false;
        }

        $this->cache->save((string) ($count + 1), $key, [], 60);

        return true;
    }
}
