<?php

declare(strict_types=1);

namespace DockCodes\DockRay\Model\Transport;

use Dock\Ray\HttpClient\HttpClientFactory;
use Dock\Ray\Options;
use Dock\Ray\Serializer\PayloadSerializer;
use Dock\Ray\Transport\HttpTransport;
use Dock\Ray\Transport\NullTransport;
use Dock\Ray\Transport\TransportFactoryInterface;
use Dock\Ray\Transport\TransportInterface;
use DockCodes\DockRay\Model\Version;
use Http\Discovery\Psr17FactoryDiscovery;

/**
 * The SDK's own HTTP transport with the privacy gate in front of it. Queued
 * events (`send_after_response`) leave from a shutdown handler, after
 * PHP-FPM has handed the page to the shopper - see AfterResponseTransport
 * for why the SDK's DeferredTransport is not used.
 */
final class TransportFactory implements TransportFactoryInterface
{
    public function create(Options $options): TransportInterface
    {
        if ($options->getAuthData() === null) {
            return new NullTransport();
        }

        $streamFactory = Psr17FactoryDiscovery::findStreamFactory();

        $transport = new PrivacyTransport(new HttpTransport(
            $options,
            (new HttpClientFactory($streamFactory, null, Version::SDK_IDENTIFIER, Version::VERSION))->create($options),
            $streamFactory,
            Psr17FactoryDiscovery::findRequestFactory(),
            new PayloadSerializer(),
        ), $options);

        return $options->shouldSendAfterResponse() ? new AfterResponseTransport($transport) : $transport;
    }
}
