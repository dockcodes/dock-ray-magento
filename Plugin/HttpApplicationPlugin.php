<?php

declare(strict_types=1);

namespace DockCodes\DockRay\Plugin;

use Dock\Ray\Framework\HttpTransaction;
use DockCodes\DockRay\Model\Privacy;
use DockCodes\DockRay\Model\Reporter;
use Magento\Framework\App\Bootstrap;
use Magento\Framework\App\Http;
use Magento\Framework\App\RequestInterface;
use Magento\Framework\App\State;

/**
 * The web application of Magento - storefront, admin, REST and GraphQL.
 *
 * - `launch()` boots the SDK as early as Magento allows and measures the
 *   request when transactions are on;
 * - `catchException()` sees every exception that reached Magento's error
 *   page, including the ones nobody logged.
 */
class HttpApplicationPlugin
{
    /** Our own endpoints: measuring them would only measure the measuring. */
    private const SKIPPED_ROUTES = ['dockray'];

    public function __construct(
        private readonly Reporter $reporter,
        private readonly RequestInterface $request,
        private readonly State $state,
    ) {
    }

    public function aroundLaunch(Http $subject, callable $proceed)
    {
        $booted = microtime(true);

        try {
            $tracing = $this->reporter->hub() !== null && $this->reporter->tracesSampleRate() > 0;
        } catch (\Throwable) {
            $tracing = false;
        }

        try {
            $response = $proceed();
        } catch (\Throwable $exception) {
            if ($tracing) {
                $this->measure($booted, 500);
            }

            throw $exception;
        }

        if ($tracing) {
            $status = method_exists($response, 'getHttpResponseCode') ? (int) $response->getHttpResponseCode() : 200;
            $this->measure($booted, $status > 0 ? $status : 200);
        }

        return $response;
    }

    public function beforeCatchException(Http $subject, Bootstrap $bootstrap, \Exception $exception): ?array
    {
        $this->reporter->captureException($exception);

        return null;
    }

    /**
     * The transaction is assembled after the request was handled: only then
     * does Magento know the route, and the name has to be the route - `GET
     * catalog_product_view`, not one entry per product URL. Its start is
     * the moment PHP received the request, so the duration is the real one.
     */
    private function measure(float $booted, int $status): void
    {
        try {
            $name = $this->transactionName();

            if ($name === null) {
                return;
            }

            $started = isset($_SERVER['REQUEST_TIME_FLOAT']) ? (float) $_SERVER['REQUEST_TIME_FLOAT'] : $booted;
            $finished = microtime(true);

            $transaction = HttpTransaction::start(
                $name,
                Privacy::cleanUrl($this->url()),
                $this->method(),
                $started,
                $this->reporter->hub(),
            );

            $transaction->child('magento.bootstrap', $started, $booted);
            $transaction->child('magento.handle', $booted, $finished);
            $transaction->finish($status, $finished);
        } catch (\Throwable) {
        }
    }

    private function transactionName(): ?string
    {
        $method = $this->method();
        $route = method_exists($this->request, 'getRouteName') ? (string) $this->request->getRouteName() : '';

        if (in_array($route, self::SKIPPED_ROUTES, true)) {
            return null;
        }

        $action = method_exists($this->request, 'getFullActionName') ? (string) $this->request->getFullActionName() : '';

        if ($action !== '' && $action !== '__' && ! str_starts_with($action, '_')) {
            return $method.' '.$action;
        }

        try {
            $area = $this->state->getAreaCode();
        } catch (\Throwable) {
            $area = '';
        }

        $path = method_exists($this->request, 'getPathInfo') ? (string) $this->request->getPathInfo() : '/';

        // A full page cache hit is answered before routing - there is no
        // action to name it after, and the URL would be one entry per page.
        if ($area === 'frontend') {
            return $method.' full_page_cache';
        }

        return $method.' '.self::pattern($path);
    }

    /**
     * `/rest/default/V1/orders/8123/comments` → `/rest/default/V1/orders/{id}/comments`.
     * A segment with a digit in it is almost always an identifier: an order
     * id, a SKU, a quote mask.
     */
    public static function pattern(string $path): string
    {
        $path = '/'.ltrim((string) parse_url($path, PHP_URL_PATH), '/');
        $segments = array_map(
            static fn (string $segment): string => preg_match('/\d/', $segment) === 1 && ! preg_match('/^V\d+$/', $segment) ? '{id}' : $segment,
            explode('/', $path),
        );

        return mb_substr(implode('/', $segments), 0, 200);
    }

    private function method(): string
    {
        $method = method_exists($this->request, 'getMethod') ? (string) $this->request->getMethod() : '';

        return $method !== '' ? strtoupper($method) : 'GET';
    }

    private function url(): string
    {
        return method_exists($this->request, 'getUriString') ? (string) $this->request->getUriString() : '';
    }
}
