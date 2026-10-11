<?php

declare(strict_types=1);

namespace DockCodes\DockRay\Model\Transport;

use Dock\Ray\Event;
use Dock\Ray\Framework\ResponseFlusher;
use Dock\Ray\Response;
use Dock\Ray\ResponseStatus;
use Dock\Ray\Transport\TransportInterface;
use GuzzleHttp\Promise\FulfilledPromise;
use GuzzleHttp\Promise\PromiseInterface;

/**
 * Queues events during the request and sends them from a shutdown handler.
 *
 * The SDK's DeferredTransport does the same, but before sending it always
 * calls ResponseFlusher::flush(), whose fallback for SAPIs that cannot close
 * the connection (Apache mod_php, the PHP built-in server) loops on
 * `ob_end_flush()` for as long as an output buffer is open - and a buffer that
 * cannot be removed never closes. The worker then spins until
 * max_execution_time, or forever without one. Here the flush runs only where
 * PHP can really hand the page over first (PHP-FPM, LiteSpeed); elsewhere the
 * events still leave after Magento has produced the whole response.
 */
final class AfterResponseTransport implements TransportInterface
{
    /** The panel counts repeats by fingerprint; a request failing in a loop needs no more. */
    private const MAX_QUEUED_EVENTS = 50;

    /** @var Event[] */
    private array $queue = [];

    private bool $registered = false;

    public function __construct(private readonly TransportInterface $transport)
    {
    }

    public function send(Event $event): PromiseInterface
    {
        if (count($this->queue) >= self::MAX_QUEUED_EVENTS) {
            return new FulfilledPromise(new Response(ResponseStatus::skipped(), $event));
        }

        $this->queue[] = $event;
        $this->register();

        return new FulfilledPromise(new Response(ResponseStatus::success(), $event));
    }

    public function close(?int $timeout = null): PromiseInterface
    {
        $this->flush();

        return $this->transport->close($timeout);
    }

    public function flush(): void
    {
        $queue = $this->queue;
        $this->queue = [];

        foreach ($queue as $event) {
            try {
                $this->transport->send($event)->wait(false);
            } catch (\Throwable) {
                // Nobody is left to tell about a failure after the response.
            }
        }
    }

    /**
     * Registered on the first event, not up front: shutdown handlers run in
     * order, and the SDK's fatal error handler registers when the client is
     * built - this one has to run after it, so a fatal error is queued in time.
     */
    private function register(): void
    {
        if ($this->registered) {
            return;
        }

        $this->registered = true;

        register_shutdown_function(function (): void {
            if (ResponseFlusher::supportsEarlyClose()) {
                ResponseFlusher::flush();
            }

            $this->flush();
        });
    }
}
