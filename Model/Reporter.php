<?php

declare(strict_types=1);

namespace DockCodes\DockRay\Model;

use Dock\Ray\ClientBuilder;
use Dock\Ray\ClientBuilderInterface;
use Dock\Ray\Event;
use Dock\Ray\EventType;
use Dock\Ray\Integration\ErrorListenerIntegration;
use Dock\Ray\RaySdk;
use Dock\Ray\State\Hub;
use Dock\Ray\State\HubInterface;
use Dock\Ray\State\Scope;
use Dock\Ray\UserDataBag;
use DockCodes\DockRay\Model\Transport\TransportFactory;
use Magento\Framework\App\ProductMetadataInterface;
use Magento\Framework\App\State;

/**
 * The SDK hub built from the store configuration - one per process.
 *
 * Nothing here may throw into Magento: monitoring that cannot start stays
 * silent, and reporting an error never becomes another error of the store.
 */
class Reporter
{
    private ?HubInterface $hub = null;

    private bool $booted = false;

    private bool $booting = false;

    /** @var \WeakMap<\Throwable, true> exceptions already reported in this process */
    private \WeakMap $reported;

    public function __construct(
        private readonly Config $config,
        private readonly UserContext $userContext,
        private readonly ProductMetadataInterface $productMetadata,
        private readonly State $state,
    ) {
        $this->reported = new \WeakMap();
    }

    public function isConfigured(): bool
    {
        try {
            return $this->config->isConfigured();
        } catch (\Throwable) {
            return false;
        }
    }

    public function hub(): ?HubInterface
    {
        if ($this->booted || $this->booting) {
            return $this->hub;
        }

        // Reading the configuration may log, and logging may come back here.
        $this->booting = true;

        try {
            if ($this->config->isConfigured()) {
                $this->hub = new Hub($this->builder()->getClient());
                RaySdk::setCurrentHub($this->hub);
                $this->configureScope($this->hub);
            }
        } catch (\Throwable $exception) {
            $this->hub = null;
            error_log('DockRay could not start: '.$exception->getMessage());
        } finally {
            $this->booting = false;
            $this->booted = true;
        }

        return $this->hub;
    }

    /**
     * Reports an exception once: Magento often logs an exception and then
     * lets it reach the application's error page, and both paths end here.
     */
    public function captureException(\Throwable $exception): void
    {
        try {
            if (isset($this->reported[$exception])) {
                return;
            }

            $hub = $this->hub();

            if ($hub === null) {
                return;
            }

            $this->reported[$exception] = true;
            $hub->captureException($exception);
        } catch (\Throwable) {
            // Silence on purpose, see the class comment.
        }
    }

    /**
     * A JavaScript error from the storefront. The SDK's request integration
     * would describe the request that carried the report - the POST to our
     * endpoint - so the page the error happened on is put back on the way out.
     */
    public function captureBrowserEvent(Event $event): void
    {
        try {
            $hub = $this->hub();

            if ($hub === null) {
                return;
            }

            $request = $event->getRequest();

            $hub->withScope(static function (Scope $scope) use ($hub, $event, $request): void {
                $scope->addEventProcessor(static function (Event $outgoing) use ($request): Event {
                    $outgoing->setRequest($request);

                    return $outgoing;
                });

                $hub->captureEvent($event);
            });
        } catch (\Throwable) {
        }
    }

    /**
     * Sends one test event and waits for DockRay's answer.
     *
     * The regular client queues events until after the response, so its event
     * id only means "queued" - a wrong key would look like a success. The test
     * uses its own client that sends right away: a rejection comes back as null.
     */
    public function sendTest(): ?string
    {
        if (! $this->isConfigured()) {
            return null;
        }

        try {
            $client = $this->builder(['send_after_response' => false, 'default_integrations' => false])->getClient();
            $eventId = $client->captureException(new \RuntimeException('Test event sent from the DockRay Magento module.'));
        } catch (\Throwable $exception) {
            error_log('DockRay test event failed: '.$exception->getMessage());

            return null;
        }

        return $eventId !== null ? (string) $eventId : null;
    }

    public function tracesSampleRate(): float
    {
        try {
            return $this->config->tracesSampleRate();
        } catch (\Throwable) {
            return 0.0;
        }
    }

    /** @param array<string, mixed> $overrides */
    private function builder(array $overrides = []): ClientBuilderInterface
    {
        $root = $this->config->rootDirectory();

        $builder = ClientBuilder::create($overrides + [
            'token' => $this->config->token(),
            'private_key' => $this->config->privateKey(),
            'url' => $this->config->serverUrl(),
            'environment' => $this->config->environment(),
            'release' => $this->config->release(),
            'traces_sample_rate' => $this->config->tracesSampleRate(),
            'send_default_pii' => $this->config->sendDefaultPii(),
            'max_request_body_size' => 'none',
            'prefixes' => [$root],
            'in_app_exclude' => [$root.'/vendor', $root.'/generated', $root.'/lib/internal', $root.'/setup'],
            'error_types' => E_ALL & ~E_DEPRECATED & ~E_USER_DEPRECATED & ~E_NOTICE & ~E_USER_NOTICE,
            // Magento turns PHP warnings into exceptions itself, and those reach
            // the application's error handler - a second listener would report
            // every warning twice, once as a warning and once as an exception.
            'integrations' => static fn (array $integrations): array => array_values(array_filter(
                $integrations,
                static fn ($integration): bool => ! $integration instanceof ErrorListenerIntegration,
            )),
        ]);

        $builder->setTransportFactory(new TransportFactory());
        $builder->setSdkIdentifier(Version::SDK_IDENTIFIER);
        $builder->setSdkVersion(Version::VERSION);

        return $builder;
    }

    private function configureScope(HubInterface $hub): void
    {
        $hub->configureScope(function (Scope $scope): void {
            $scope->setTag('magento', (string) $this->productMetadata->getVersion());
            $scope->setTag('magento.edition', (string) $this->productMetadata->getEdition());

            $scope->addEventProcessor(function (Event $event): Event {
                try {
                    $area = $this->state->getAreaCode();
                    $event->setTags(['magento.area' => (string) $area] + $event->getTags());
                } catch (\Throwable) {
                    // Area not set yet: bootstrap error or console.
                }

                if ($event->getType() !== EventType::transaction()
                    && $event->getUser() === null
                    && $this->config->sendDefaultPii()) {
                    $user = $this->userContext->resolve();

                    if ($user !== null) {
                        $event->setUser(UserDataBag::createFromArray($user));
                    }
                }

                return $event;
            });
        });
    }
}
