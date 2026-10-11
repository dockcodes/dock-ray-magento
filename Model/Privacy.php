<?php

declare(strict_types=1);

namespace DockCodes\DockRay\Model;

use Dock\Ray\Event;

/**
 * What leaves the store - applied at the transport boundary, so errors,
 * transactions and browser events all pass through the same gate.
 *
 * - addresses lose their query string: that is where session ids, coupon
 *   codes and payment callbacks carry tokens;
 * - the request keeps only its address and method - no headers, cookies or
 *   body (checkout forms carry addresses and card holder names);
 * - stack frames lose local variables;
 * - without "send user identity" the user and the user agent are dropped.
 */
final class Privacy
{
    public static function cleanUrl(string $url): string
    {
        $parts = parse_url($url);

        if (! is_array($parts)) {
            return '';
        }

        $base = isset($parts['host'])
            ? ($parts['scheme'] ?? 'https').'://'.$parts['host'].(isset($parts['port']) ? ':'.$parts['port'] : '')
            : '';

        return $base.($parts['path'] ?? '');
    }

    public static function filter(Event $event, bool $sendPii): Event
    {
        $request = array_intersect_key($event->getRequest(), ['url' => true, 'method' => true]);

        if (isset($request['url'])) {
            $request['url'] = self::cleanUrl((string) $request['url']);
        }

        $event->setRequest($request);

        $stacktraces = [$event->getStacktrace()];

        foreach ($event->getExceptions() as $exception) {
            $stacktraces[] = $exception->getStacktrace();
        }

        foreach ($stacktraces as $stacktrace) {
            foreach ($stacktrace?->getFrames() ?? [] as $frame) {
                $frame->setVars([]);
            }
        }

        if (! $sendPii) {
            $event->setUser(null);

            if (isset($event->getContexts()['browser'])) {
                $browser = $event->getContexts()['browser'];
                unset($browser['user_agent']);
                $event->setContext('browser', $browser);
            }
        }

        $trace = $event->getContexts()['trace'] ?? [];

        if (isset($trace['data']['url'])) {
            $trace['data']['url'] = self::cleanUrl((string) $trace['data']['url']);
            $event->setContext('trace', $trace);
        }

        $tags = $event->getTags();

        if (isset($tags['referrer'])) {
            $tags['referrer'] = self::cleanUrl((string) $tags['referrer']);
            $event->setTags($tags);
        }

        return $event;
    }
}
