<?php

declare(strict_types=1);

namespace DockCodes\DockRay\Model\Security;

/**
 * The body of the security report for one Magento installation, in the shape
 * of DockRay's contract (`docs/security-report.md`): group digests, sensitive
 * single files, suspicious files and posture booleans.
 *
 * Plain PHP on purpose - no Magento class is needed to read the file tree, so
 * the report is built and tested the same way everywhere. What only Magento
 * knows (its version, the store address, the deploy mode, the posture measured
 * in a web request) comes in through `$context`.
 *
 * Nothing here returns file contents or absolute paths: only hashes, sizes,
 * paths relative to the Magento root, indicator names and booleans.
 */
class ReportBuilder
{
    public const SCHEMA = 1;

    public const MAX_GROUPS = 1500;

    public const MAX_SENSITIVE_FILES = 500;

    public const MAX_SUSPICIOUS = 500;

    /**
     * Files visited per scan, all walks together. Higher than the contract's
     * suggestion of 200 000: `vendor` of a stock Magento alone holds well over
     * 100 000 files, and the upload walk has its own limit below.
     */
    public const MAX_SCAN_FILES = 600000;

    /** Names walked in the upload directories before the scan counts as truncated. */
    public const MAX_UPLOAD_ENTRIES = 300000;

    /** Posture keys that depend on the SAPI, its php.ini and the process user. */
    public const RUNTIME_POSTURE = ['code_writable', 'display_errors', 'exec_available'];

    /**
     * Sensitive single files (contract: `files`). `entry` is code that runs on
     * every request; Magento copies these out of `magento/magento2-base`, so no
     * package digest covers the copies that actually run.
     */
    public const SENSITIVE_FILES = [
        'index.php' => 'entry',
        'pub/index.php' => 'entry',
        'pub/get.php' => 'entry',
        'pub/static.php' => 'entry',
        'pub/cron.php' => 'entry',
        'pub/health_check.php' => 'entry',
        'app/bootstrap.php' => 'entry',
        'app/autoload.php' => 'entry',
        'app/functions.php' => 'entry',
        'app/etc/NonComposerComponentRegistration.php' => 'entry',
        'bin/magento' => 'entry',
        'app/etc/env.php' => 'config',
        'app/etc/config.php' => 'config',
        '.htaccess' => 'server',
        '.user.ini' => 'server',
        'php.ini' => 'server',
        'pub/.htaccess' => 'server',
        'pub/.user.ini' => 'server',
        'pub/php.ini' => 'server',
        'pub/media/.htaccess' => 'server',
        'pub/static/.htaccess' => 'server',
    ];

    /**
     * PHP files Magento (and Adobe Commerce Cloud) ships directly in the two
     * directories a web server may serve. Anything else there is
     * `unknown_root_php`.
     */
    public const SHIPPED_ROOT_PHP = [
        '' => ['index.php', '.php-cs-fixer.dist.php', 'magento-vars.php'],
        'pub' => ['index.php', 'get.php', 'static.php', 'cron.php', 'health_check.php'],
    ];

    /** Where Magento stores uploaded files: `pub/media`, or `media` in installations served from the root. */
    public const UPLOAD_DIRECTORIES = ['pub/media', 'media'];

    /**
     * Not walked at all, relative to an upload directory: the resized product
     * images Magento regenerates (`catalog:images:resize`, "Flush Catalog
     * Images Cache"). On a large catalogue that is most of `pub/media` - walking
     * it would stop every scan at its limit.
     */
    public const UPLOAD_EXCLUDE = ['catalog/product/cache/'];

    /**
     * Hidden directories Magento creates itself, relative to an upload
     * directory: thumbnails of the WYSIWYG image browser (`.thumbs`, and
     * `.thumbswysiwyg` from older releases) and media gallery renditions.
     * Not reported; the files inside are still judged.
     */
    public const UPLOAD_HIDDEN_ALLOWED = ['.thumbs', '.thumbswysiwyg', '.renditions', 'wysiwyg/.thumbs'];

    /** Magento code outside Composer's `vendor`: the copies `magento/magento2-base` puts into the root. */
    public const CORE_DIRECTORIES = ['lib', 'setup', 'pub/errors'];

    /** Debugging toolbars and error pages that print internals to visitors. */
    public const DEBUG_PACKAGES = [
        'vpietri/adm-quickdevbar',
        'msp/devtools',
        'yireo/magento2-whoops',
        'mgtcommerce/module-mgtdevelopertoolbar',
        'itsgoingd/clockwork',
    ];

    /** The same tools copied into `app/code`. */
    public const DEBUG_MODULES = ['ADM/QuickDevBar', 'MSP/DevTools', 'Yireo/Whoops', 'Mgt/DeveloperToolbar', 'Clockwork/Clockwork'];

    private const MAX_METADATA_BYTES = 16777216;

    private const SLUG_PATTERN = '/^[A-Za-z0-9._@\/+-]+$/';

    /**
     * Scans the installation and returns the report body together with the
     * cache for the next run (hashes by size/mtime/ctime, upload scan state).
     *
     * @param array{platform_version?: string|null, site_url?: string|null, agent_version?: string, release?: string|null, posture?: array<string, bool>} $context
     * @param array<string, mixed> $cache returned by the previous call
     *
     * @return array{payload: array<string, mixed>, cache: array<string, mixed>}
     */
    public function build(string $root, array $context, array $cache, int $now, float $timeLimit, int $maxFiles = self::MAX_SCAN_FILES): array
    {
        $root = rtrim(SecurityScanner::separators($root), '/');
        $started = microtime(true);
        $scanner = new SecurityScanner($root, is_array($cache['hashes'] ?? null) ? $cache['hashes'] : [], $started + max(0.0, $timeLimit), max(0, $maxFiles));
        $packages = $this->packages($root);

        $files = [];

        foreach (self::SENSITIVE_FILES as $path => $role) {
            $entry = $scanner->file($path, $role);

            if ($entry !== null) {
                $files[] = $entry;
            }
        }

        $suspicious = [];

        foreach (self::SHIPPED_ROOT_PHP as $directory => $shipped) {
            foreach ($scanner->rootPhp($directory, $shipped) as $entry) {
                $suspicious[] = $entry;
            }
        }

        // Groups before uploads: a catalogue with hundreds of thousands of
        // media files must not keep the code digests from ever completing.
        // The hash cache makes the next run fast, so uploads get their turn.
        $groups = [];

        foreach ($this->groupDefinitions($root, $context, $packages) as $definition) {
            if (strlen($definition[1]) > 191 || preg_match(self::SLUG_PATTERN, $definition[1]) !== 1) {
                continue;
            }

            if (count($groups) >= self::MAX_GROUPS) {
                $scanner->markTruncated();

                break;
            }

            $group = $scanner->group(...$definition);

            if ($group !== null) {
                $groups[] = $group;
            }
        }

        $uploadDirectories = $this->uploadDirectories($root);
        $exclude = [];
        $allowedHidden = [];

        foreach ($uploadDirectories as $directory) {
            foreach (self::UPLOAD_EXCLUDE as $prefix) {
                $exclude[] = $directory.'/'.$prefix;
            }

            foreach (self::UPLOAD_HIDDEN_ALLOWED as $hidden) {
                $allowedHidden[] = $directory.'/'.$hidden;
            }
        }

        // Re-reading unchanged uploads gets half of the time and continues
        // from a cursor; changed files are read on every run.
        $uploads = $scanner->uploads(
            $uploadDirectories,
            is_array($cache['uploads'] ?? null) ? $cache['uploads'] : [],
            $now,
            $timeLimit / 2,
            min(self::MAX_UPLOAD_ENTRIES, max(0, $maxFiles)),
            $exclude,
            $allowedHidden,
        );

        foreach ($uploads['entries'] as $entry) {
            $suspicious[] = $entry;
        }

        if (count($suspicious) > self::MAX_SUSPICIOUS) {
            $suspicious = array_slice($suspicious, 0, self::MAX_SUSPICIOUS);
            $scanner->markTruncated();
        }

        $posture = [];

        foreach (is_array($context['posture'] ?? null) ? $context['posture'] : [] as $key => $value) {
            if (is_string($key) && is_bool($value)) {
                $posture[$key] = $value;
            }
        }

        $posture['debug_tools'] = $this->debugTools($root, $packages);

        $payload = [
            'schema' => self::SCHEMA,
            'platform' => 'magento',
            'platform_version' => self::text($context['platform_version'] ?? null, 64),
            'php_version' => PHP_VERSION,
            'agent_version' => self::text($context['agent_version'] ?? null, 32),
            'scan' => [
                'files' => $scanner->files(),
                'duration_ms' => (int) round((microtime(true) - $started) * 1000),
                'truncated' => $scanner->truncated(),
            ],
            // Only groups that were hashed completely: with `scan.truncated`
            // set, DockRay leaves the missing ones untouched.
            'groups' => $groups,
            'files' => array_slice($files, 0, self::MAX_SENSITIVE_FILES),
            'suspicious' => $suspicious,
            'posture' => $posture,
        ];

        $siteUrl = self::validSiteUrl($context['site_url'] ?? null);

        if ($siteUrl !== null) {
            $payload['site_url'] = $siteUrl;
        }

        return [
            'payload' => $payload,
            'cache' => ['hashes' => $scanner->cache(), 'uploads' => $uploads['state']],
        ];
    }

    /**
     * Posture keys that depend on the SAPI, its php.ini and the process user.
     * Meaningful only when measured in a web request - the context visitors
     * get; a cron or CLI process has its own php.ini and often its own user.
     *
     * `code_writable`: whether PHP may write into Magento's code - the
     * framework in `vendor` (or `lib/internal` in a git installation) or
     * `app/code`. Left out when none of them exists.
     *
     * @return array<string, bool>
     */
    public static function runtimePosture(string $root): array
    {
        $root = rtrim(SecurityScanner::separators($root), '/');
        $posture = [];
        $writable = null;

        foreach (['vendor/magento/framework', 'lib/internal/Magento/Framework', 'app/code'] as $directory) {
            if (is_dir($root.'/'.$directory)) {
                $writable = ($writable ?? false) || is_writable($root.'/'.$directory);
            }
        }

        if ($writable !== null) {
            $posture['code_writable'] = $writable;
        }

        // Magento does not touch display_errors at runtime (app/bootstrap.php
        // leaves its ini_set commented out), so the current value is the one
        // visitors get.
        $posture['display_errors'] = in_array(strtolower(trim((string) ini_get('display_errors'))), ['1', 'on', 'yes', 'true', 'stdout', 'stderr'], true);
        $posture['exec_available'] = self::execAvailable();

        return $posture;
    }

    public static function execAvailable(): bool
    {
        $disabled = array_map('trim', explode(',', strtolower((string) ini_get('disable_functions'))));

        foreach (['exec', 'shell_exec', 'system', 'passthru', 'proc_open', 'popen'] as $function) {
            if (function_exists($function) && is_callable($function) && ! in_array($function, $disabled, true)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Core first, then local code (`app/code`, `app/design` - the part nobody
     * else watches), then Composer packages: a scan cut short by its limit
     * has hashed the most important code, and the next run gets further
     * through the hash cache.
     *
     * @param array<string, array{path: string, version: string|null}> $packages
     *
     * @return list<array{0: string, 1: string, 2: string|null, 3: list<string>, 4: string, 5: list<string>}>
     */
    private function groupDefinitions(string $root, array $context, array $packages): array
    {
        $release = self::text($context['release'] ?? null, 64);
        $definitions = [['core', 'magento', self::text($context['platform_version'] ?? null, 64), self::CORE_DIRECTORIES, '', []]];

        foreach ($this->directories($root.'/app/code') as $vendor) {
            if (preg_match('/^[A-Za-z0-9]+$/', $vendor) !== 1) {
                continue;
            }

            foreach ($this->directories($root.'/app/code/'.$vendor) as $module) {
                $path = 'app/code/'.$vendor.'/'.$module;

                if (preg_match('/^[A-Za-z0-9]+$/', $module) !== 1 || ! is_file($root.'/'.$path.'/registration.php')) {
                    continue;
                }

                $definitions[] = ['module', $vendor.'_'.$module, $this->localVersion($root.'/'.$path, true, $release), [$path], $path.'/', []];
            }
        }

        foreach (['frontend', 'adminhtml'] as $area) {
            foreach ($this->directories($root.'/app/design/'.$area) as $vendor) {
                foreach ($this->directories($root.'/app/design/'.$area.'/'.$vendor) as $theme) {
                    $path = 'app/design/'.$area.'/'.$vendor.'/'.$theme;

                    if (preg_match('/^[A-Za-z0-9._-]+$/', $vendor.$theme) !== 1
                        || (! is_file($root.'/'.$path.'/registration.php') && ! is_file($root.'/'.$path.'/theme.xml'))) {
                        continue;
                    }

                    $definitions[] = ['theme', $area.'/'.$vendor.'/'.$theme, $this->localVersion($root.'/'.$path, false, $release), [$path], $path.'/', []];
                }
            }
        }

        foreach ($packages as $name => $package) {
            $definitions[] = ['package', $name, $package['version'], [$package['path']], $package['path'].'/', []];
        }

        return $definitions;
    }

    /**
     * Code copied into `app/` has no Composer record, so its version is what
     * it declares (`composer.json`, then `setup_version` of a module). Teams
     * rarely bump that when they deploy a fix, so a release set explicitly in
     * the module settings is appended: a deployment with a new release
     * re-baselines local code, a file changed outside a deployment does not.
     * The release that falls back to `pub/static/deployed_version.txt` is not
     * used here - that file can be written by the web server.
     */
    private function localVersion(string $path, bool $module, ?string $release): ?string
    {
        $declared = null;
        $composer = $this->json($path.'/composer.json');

        if (is_string($composer['version'] ?? null)) {
            $declared = self::text($composer['version'], 64);
        }

        if ($declared === null && $module) {
            $xml = @file_get_contents($path.'/etc/module.xml', false, null, 0, 65536);

            if (is_string($xml) && preg_match('/<module\b[^>]*\bsetup_version\s*=\s*"([^"]{1,64})"/', $xml, $match) === 1) {
                $declared = self::text($match[1], 64);
            }
        }

        if ($release === null) {
            return $declared;
        }

        return self::text($declared !== null ? $declared.'+'.$release : $release, 64);
    }

    /**
     * Installed Composer packages that live in `vendor/`, by name, from
     * `vendor/composer/installed.json` (Composer 2 with `install-path`, or
     * Composer 1). Metapackages have no files and are left out; so are
     * packages installed into `app/` - those are judged as modules there.
     * `vendor/composer`, `vendor/bin` and `vendor/autoload.php` belong to no
     * package: every `composer dump-autoload` rewrites them.
     *
     * @return array<string, array{path: string, version: string|null}>
     */
    private function packages(string $root): array
    {
        $installed = $this->json($root.'/vendor/composer/installed.json');
        $list = isset($installed['packages']) && is_array($installed['packages']) ? $installed['packages'] : $installed;
        $packages = [];

        foreach ($list as $package) {
            if (! is_array($package) || ! is_string($package['name'] ?? null)) {
                continue;
            }

            $name = strtolower($package['name']);

            if (strlen($name) > 191 || preg_match('#^[a-z0-9_.-]+/[a-z0-9_.-]+$#D', $name) !== 1) {
                continue;
            }

            $path = isset($package['install-path']) && is_string($package['install-path'])
                ? self::normalize('vendor/composer/'.str_replace('\\', '/', $package['install-path']))
                : 'vendor/'.$name;

            if ($path === null || strncmp($path, 'vendor/', 7) !== 0 || strncmp($path, 'vendor/composer/', 16) === 0
                || strncmp($path, 'vendor/bin/', 11) === 0 || ! is_dir($root.'/'.$path)) {
                continue;
            }

            $packages[$name] = ['path' => $path, 'version' => self::packageVersion($package)];
        }

        ksort($packages, SORT_STRING);

        return $packages;
    }

    /**
     * The installed version; a branch (`dev-main`, `2.x-dev`) gets the commit
     * it points to, or every `composer update` of it would look like a
     * modified package.
     *
     * @param array<string, mixed> $package
     */
    private static function packageVersion(array $package): ?string
    {
        $version = self::text($package['version'] ?? null, 64);

        if ($version === null) {
            return null;
        }

        $version = (string) preg_replace('/^v(?=\d)/', '', $version);

        if (strncmp($version, 'dev-', 4) === 0 || substr($version, -4) === '-dev') {
            foreach (['source', 'dist'] as $origin) {
                $reference = $package[$origin]['reference'] ?? null;

                if (is_string($reference) && preg_match('/^[A-Za-z0-9]{7,}$/', $reference) === 1) {
                    return self::text($version.'#'.substr($reference, 0, 12), 64);
                }
            }
        }

        return $version;
    }

    /**
     * Debugging tools installed in this Magento: a toolbar or an error page
     * that prints internals to whoever triggers it.
     *
     * @param array<string, array{path: string, version: string|null}> $packages
     */
    private function debugTools(string $root, array $packages): bool
    {
        foreach (self::DEBUG_PACKAGES as $name) {
            if (isset($packages[$name])) {
                return true;
            }
        }

        foreach (self::DEBUG_MODULES as $module) {
            if (is_file($root.'/app/code/'.$module.'/registration.php')) {
                return true;
            }
        }

        return false;
    }

    /**
     * `media` is a symlink to `pub/media` on some installations; walking both
     * would list every upload twice.
     *
     * @return list<string>
     */
    private function uploadDirectories(string $root): array
    {
        $directories = [];
        $seen = [];

        foreach (self::UPLOAD_DIRECTORIES as $directory) {
            $real = is_dir($root.'/'.$directory) ? @realpath($root.'/'.$directory) : false;

            if ($real === false || isset($seen[$real])) {
                continue;
            }

            $seen[$real] = true;
            $directories[] = $directory;
        }

        return $directories;
    }

    /** @return list<string> sorted names of the subdirectories, symlinks excluded */
    private function directories(string $path): array
    {
        $names = is_dir($path) ? @scandir($path) : false;
        $directories = [];

        foreach (is_array($names) ? $names : [] as $name) {
            if ($name !== '.' && $name !== '..' && is_dir($path.'/'.$name) && ! is_link($path.'/'.$name)) {
                $directories[] = $name;
            }
        }

        return $directories;
    }

    /** `a/b/../c` → `a/c`; null when the path leaves its root. */
    private static function normalize(string $path): ?string
    {
        $parts = [];

        foreach (explode('/', $path) as $part) {
            if ($part === '' || $part === '.') {
                continue;
            }

            if ($part === '..') {
                if ($parts === []) {
                    return null;
                }

                array_pop($parts);

                continue;
            }

            $parts[] = $part;
        }

        return $parts === [] ? null : implode('/', $parts);
    }

    /** @return array<mixed> */
    private function json(string $file): array
    {
        if (! is_file($file) || ! is_readable($file) || (int) @filesize($file) > self::MAX_METADATA_BYTES) {
            return [];
        }

        $data = json_decode((string) @file_get_contents($file), true, 128);

        return is_array($data) ? $data : [];
    }

    private static function validSiteUrl(mixed $url): ?string
    {
        if (! is_string($url) || $url === '' || strlen($url) > 2048 || preg_match('/[\x00-\x20\x7f]/', $url) === 1) {
            return null;
        }

        $parts = parse_url($url);

        if (! is_array($parts) || ! isset($parts['host'], $parts['scheme'])
            || ! in_array(strtolower($parts['scheme']), ['http', 'https'], true)
            || isset($parts['user']) || isset($parts['pass'])) {
            return null;
        }

        return $url;
    }

    /** One line of plain text, at most `$max` characters, or null when empty. */
    private static function text(mixed $value, int $max): ?string
    {
        if (! is_scalar($value)) {
            return null;
        }

        $value = trim((string) preg_replace('/[\x00-\x1F\x7F]+/u', ' ', (string) $value));
        $value = function_exists('mb_substr') ? mb_substr($value, 0, $max) : substr($value, 0, $max);

        return $value === '' ? null : $value;
    }
}
