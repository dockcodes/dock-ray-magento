<?php

/**
 * DockRay early fatal error reporter for Magento 2.
 *
 * Load it with `auto_prepend_file` (php.ini, `pub/.user.ini` or the PHP-FPM
 * pool); DockRay → Overview in the admin shows the exact line:
 *
 *     auto_prepend_file=/absolute/path/to/vendor/dockcodes/dock-ray-magento/early-fatal.php
 *
 * The module reports errors once Magento has started and built its
 * reporter. A fatal error before that - a parse error in `app/etc/env.php` or
 * in an extension, a broken generated class, memory exhausted while Magento
 * boots - never reaches it. This file catches exactly those and sends one
 * event to `POST {url}/api/v1/{token}/project`, in the format of the SDK.
 *
 * Deliberately dependency-free and PHP 7.4 compatible: it runs before
 * Composer's autoloader and Magento and must work when they are what is
 * broken. It never bootstraps Magento or opens the database.
 *
 * Credentials, the first source that has both the token and the key:
 * `RAY_TOKEN` + `RAY_PRIVATE_KEY` from the server environment, then
 * Magento's own `CONFIG__DEFAULT__DOCKRAY__CONNECTION__TOKEN` +
 * `…__PRIVATE_KEY`, then the values locked in `app/etc/env.php`
 * (`bin/magento config:set --lock-env`). A key saved in the admin is
 * encrypted in the database and cannot be used here. The address is
 * `RAY_URL`, then `dockray/url` from `app/etc/env.php`, then
 * https://dockray.io - HTTPS only, the key travels in a header.
 *
 * It stays silent when the module's client is already up with its fatal
 * error listener - that one reports the error itself - and it never throws
 * or prints anything. Everything lives inside a closure: a prepended file
 * runs in the global scope, and a stray variable here would become a global
 * of the store.
 */

if (defined('DOCKRAY_EARLY_FATAL')) {
    return;
}

define('DOCKRAY_EARLY_FATAL', '1.1.0');

(static function (): void {
    $version = DOCKRAY_EARLY_FATAL;

    // Memory for the report when the fatal error is "Allowed memory size exhausted".
    $reserved = str_repeat(' ', 65536);

    // vendor/dockcodes/dock-ray-magento or app/code/DockCodes/DockRay -> the Magento root.
    if (basename(dirname(__DIR__, 2)) === 'vendor') {
        $root = dirname(__DIR__, 3);
    } elseif (basename(dirname(__DIR__, 2)) === 'code' && basename(dirname(__DIR__, 3)) === 'app') {
        $root = dirname(__DIR__, 4);
    } else {
        $root = '';
    }

    register_shutdown_function(static function () use (&$reserved, $root, $version): void {
        $reserved = null;

        try {
            $error = error_get_last();
            $fatal = E_ERROR | E_PARSE | E_CORE_ERROR | E_COMPILE_ERROR | E_USER_ERROR | E_RECOVERABLE_ERROR;

            if (! is_array($error) || ! (((int) $error['type']) & $fatal)) {
                return;
            }

            if (stripos((string) $error['message'], 'Allowed memory size') === 0) {
                @ini_set('memory_limit', (string) (memory_get_usage(true) + 16777216));
            }

            // Registered from a shutdown function, this one runs after every other
            // shutdown function: Magento renders its error page and the module, if
            // it is up, reports first. Only then is it known whether anyone did.
            register_shutdown_function(static function () use ($error, $root, $version): void {
                set_error_handler(static function (): bool {
                    return true;
                });

                try {
                    if (defined('BP') && is_string(BP) && BP !== '') {
                        $root = rtrim(str_replace('\\', '/', BP), '/');
                    }

                    $env = static function (string $name): string {
                        $value = getenv($name);

                        if (! is_string($value) || $value === '') {
                            $value = $_SERVER[$name] ?? ($_ENV[$name] ?? '');
                        }

                        return is_string($value) ? trim($value) : '';
                    };

                    $type = (int) $error['type'];

                    // The module's client reports fatal errors through its own listeners.
                    if (class_exists('Dock\Ray\RaySdk', false)) {
                        try {
                            $hub = \Dock\Ray\RaySdk::getCurrentHub();
                            $client = $hub->getClient();
                            $listener = $type & (E_USER_ERROR | E_RECOVERABLE_ERROR)
                                ? 'Dock\Ray\Integration\ErrorListenerIntegration'
                                : 'Dock\Ray\Integration\FatalErrorListenerIntegration';

                            if ($client !== null && $client->getOptions()->getAuthData() !== null && $hub->getIntegration($listener) !== null) {
                                return;
                            }
                        } catch (\Throwable $exception) {
                            // An SDK in an unknown state is no reason to stay silent.
                        }
                    }

                    // app/etc/env.php, read only when the environment has no answer.
                    $deployment = null;
                    $deployed = static function (array $path) use (&$deployment, $root) {
                        if ($deployment === null) {
                            $deployment = [];
                            $file = $root !== '' ? $root.'/app/etc/env.php' : '';

                            if ($file !== '' && is_file($file) && (int) @filesize($file) < 1048576) {
                                try {
                                    $loaded = (static function (string $file) {
                                        return include $file;
                                    })($file);
                                    $deployment = is_array($loaded) ? $loaded : [];
                                } catch (\Throwable $exception) {
                                    $deployment = [];
                                }
                            }
                        }

                        $value = $deployment;

                        foreach ($path as $key) {
                            if (! is_array($value) || ! array_key_exists($key, $value)) {
                                return null;
                            }

                            $value = $value[$key];
                        }

                        return is_scalar($value) ? trim((string) $value) : null;
                    };

                    // One setting the way Magento resolves it: environment variable, then env.php.
                    $setting = static function (string $group, string $field) use ($env, $deployed): string {
                        $value = $env('CONFIG__DEFAULT__DOCKRAY__'.strtoupper($group).'__'.strtoupper($field));

                        return $value !== '' ? $value : (string) $deployed(['system', 'default', 'dockray', $group, $field]);
                    };

                    $token = $env('RAY_TOKEN');
                    $key = $env('RAY_PRIVATE_KEY');

                    if ($token === '' || $key === '') {
                        $token = $env('CONFIG__DEFAULT__DOCKRAY__CONNECTION__TOKEN');
                        $key = $env('CONFIG__DEFAULT__DOCKRAY__CONNECTION__PRIVATE_KEY');
                    }

                    if ($token === '' || $key === '') {
                        $token = (string) $deployed(['system', 'default', 'dockray', 'connection', 'token']);
                        $key = (string) $deployed(['system', 'default', 'dockray', 'connection', 'private_key']);
                    }

                    // An encrypted key ("0:3:…") needs Magento's crypt key and is not usable here.
                    if ($token === '' || $key === '' || preg_match('/^\d+:\d+:/', $key) || preg_match('/[\x00-\x20\x7f]/', $token.$key)) {
                        return;
                    }

                    $url = $env('RAY_URL') ?: (string) $deployed(['dockray', 'url']);
                    $url = rtrim($url ?: 'https://dockray.io', '/');
                    $parts = parse_url($url);

                    if (! is_array($parts) || ! isset($parts['host']) || strtolower($parts['scheme'] ?? '') !== 'https'
                        || isset($parts['user']) || isset($parts['pass'])) {
                        return;
                    }

                    $levels = [
                        E_ERROR => 'Error', E_PARSE => 'Parse Error', E_CORE_ERROR => 'Core Error',
                        E_COMPILE_ERROR => 'Compile Error', E_USER_ERROR => 'User Error', E_RECOVERABLE_ERROR => 'Catchable Fatal Error',
                    ];
                    $message = (string) $error['message'];
                    $relative = static function (string $file) use ($root): string {
                        $file = str_replace('\\', '/', $file);

                        return $root !== '' && strncmp($file, $root.'/', strlen($root) + 1) === 0 ? substr($file, strlen($root) + 1) : $file;
                    };
                    $frame = static function (string $file, int $line) use ($relative): array {
                        $path = $relative($file);

                        // The same split as the module's client: Magento's and Composer's code is not "in app".
                        return ['filename' => $path, 'lineno' => $line, 'in_app' => preg_match('#^(?:vendor|generated|lib/internal|setup)/#', $path) !== 1];
                    };

                    // Same type and value as the SDK's fatal error handler, so both land on one issue.
                    $exceptionType = 'Dock\Ray\Exception\FatalErrorException';
                    $value = ($levels[$type] ?? 'Error').': '.$message;
                    $frames = [];

                    if (strncmp($message, 'Uncaught ', 9) === 0
                        && preg_match('/^Uncaught ([^\s:]+)(?:: (.*?))? in (\S.*?):(\d+)(?:\R+Stack trace:\R(.*?))?(?:\R+\s*thrown)?\s*$/s', $message, $uncaught) === 1) {
                        $exceptionType = $uncaught[1];
                        $value = isset($uncaught[2]) && $uncaught[2] !== '' ? $uncaught[2] : $uncaught[1];

                        if (preg_match_all('/^#\d+ (\S.*?)\((\d+)\): /m', $uncaught[5] ?? '', $calls, PREG_SET_ORDER)) {
                            foreach (array_reverse(array_slice($calls, 0, 49)) as $call) {
                                $frames[] = $frame($call[1], (int) $call[2]);
                            }
                        }
                    }

                    $frames[] = $frame((string) $error['file'], (int) $error['line']);
                    $value = function_exists('mb_substr') ? mb_substr($value, 0, 1024) : substr($value, 0, 1024);

                    // One report per error per ten seconds: a fatal in the bootstrap hits every request.
                    $marker = rtrim(sys_get_temp_dir(), '/\\').'/dockray-early-'.substr(sha1($token.'|'.$exceptionType.'|'.$value.'|'.$error['file'].':'.$error['line']), 0, 20);
                    $last = @filemtime($marker);

                    if ($last !== false && time() - $last < 10) {
                        return;
                    }

                    @touch($marker);

                    // Like the module: the configured environment, else the Magento mode.
                    $environment = $env('RAY_ENVIRONMENT') ?: $setting('general', 'environment');

                    if ($environment === '') {
                        $mode = $env('MAGE_MODE') ?: (string) $deployed(['MAGE_MODE']);
                        $environment = $mode === 'developer' ? 'development' : 'production';
                    }

                    // Like the module: the configured release, else the deployed static content version.
                    $release = $env('RAY_RELEASE') ?: $setting('general', 'release');

                    if ($release === '' && $root !== '') {
                        $deployedVersion = @file_get_contents($root.'/pub/static/deployed_version.txt', false, null, 0, 64);
                        $deployedVersion = is_string($deployedVersion) ? trim($deployedVersion) : '';
                        $release = preg_match('/^[A-Za-z0-9._-]{1,64}$/', $deployedVersion) ? $deployedVersion : '';
                    }

                    $event = [
                        'event_id' => bin2hex(random_bytes(16)),
                        'timestamp' => microtime(true),
                        'platform' => 'php',
                        'level' => 'fatal',
                        'logger' => 'php',
                        'sdk' => ['name' => 'dockray.magento.early', 'version' => $version],
                        'environment' => $environment,
                        'contexts' => ['runtime' => ['name' => 'php', 'version' => PHP_VERSION]],
                        'exception' => ['values' => [[
                            'type' => $exceptionType,
                            'value' => $value,
                            'stacktrace' => ['frames' => $frames],
                            'mechanism' => ['type' => 'generic', 'handled' => false],
                        ]]],
                    ];

                    if ($release !== '') {
                        $event['release'] = $release;
                    }

                    if (function_exists('php_uname')) {
                        $event['contexts']['os'] = ['name' => (string) @php_uname('s'), 'version' => (string) @php_uname('r')];
                    }

                    // URL without the query string: it may carry tokens.
                    if (PHP_SAPI !== 'cli' && isset($_SERVER['REQUEST_URI'], $_SERVER['HTTP_HOST'])) {
                        $https = ! empty($_SERVER['HTTPS']) && strtolower((string) $_SERVER['HTTPS']) !== 'off';
                        $path = strtok((string) $_SERVER['REQUEST_URI'], '?');
                        $event['request'] = [
                            'url' => substr(preg_replace('/[\x00-\x1F\x7F]/', '', ($https ? 'https' : 'http').'://'.$_SERVER['HTTP_HOST'].($path === false ? '/' : $path)) ?? '', 0, 2048),
                            'method' => substr(preg_replace('/[^A-Z]/', '', strtoupper((string) ($_SERVER['REQUEST_METHOD'] ?? 'GET'))) ?? '', 0, 16),
                        ];
                    }

                    $body = json_encode($event, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_INVALID_UTF8_SUBSTITUTE);

                    if (! is_string($body)) {
                        return;
                    }

                    // The visitor already has whatever page there was; they do not wait for DockRay.
                    if (function_exists('fastcgi_finish_request')) {
                        @fastcgi_finish_request();
                    }

                    $endpoint = $url.'/api/v1/'.rawurlencode($token).'/project';
                    $headers = [
                        'Authorization: Bearer '.$key,
                        'Content-Type: application/json',
                        'Accept: application/json',
                        'User-Agent: dockray-magento-early/'.$version,
                    ];

                    if (function_exists('curl_init')) {
                        $handle = curl_init($endpoint);

                        if ($handle !== false) {
                            curl_setopt_array($handle, [
                                CURLOPT_POST => true,
                                CURLOPT_POSTFIELDS => $body,
                                CURLOPT_HTTPHEADER => $headers,
                                CURLOPT_RETURNTRANSFER => true,
                                CURLOPT_CONNECTTIMEOUT => 2,
                                CURLOPT_TIMEOUT => 3,
                                CURLOPT_NOSIGNAL => true,
                                CURLOPT_FOLLOWLOCATION => false,
                                CURLOPT_SSL_VERIFYPEER => true,
                                CURLOPT_SSL_VERIFYHOST => 2,
                                CURLOPT_PROTOCOLS => CURLPROTO_HTTPS,
                            ]);
                            curl_exec($handle);
                            // No curl_close(): a no-op since PHP 8.0 and deprecated since 8.5.
                            unset($handle);
                        }

                        return;
                    }

                    $previousTimeout = ini_get('default_socket_timeout');
                    @ini_set('default_socket_timeout', '2');
                    @file_get_contents($endpoint, false, stream_context_create([
                        'http' => [
                            'method' => 'POST',
                            'header' => implode("\r\n", $headers),
                            'content' => $body,
                            'timeout' => 3,
                            'ignore_errors' => true,
                            'follow_location' => 0,
                        ],
                        'ssl' => ['verify_peer' => true, 'verify_peer_name' => true],
                    ]));
                    @ini_set('default_socket_timeout', (string) $previousTimeout);
                } catch (\Throwable $exception) {
                    // Reporting a fatal error must not add one.
                } finally {
                    restore_error_handler();
                }
            });
        } catch (\Throwable $exception) {
            // Same: never a second error from the reporter.
        }
    });
})();
