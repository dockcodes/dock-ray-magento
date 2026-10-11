<?php

declare(strict_types=1);

namespace DockCodes\DockRay\Model\Inventory;

use DockCodes\DockRay\Model\Config;
use DockCodes\DockRay\Model\Version;
use Magento\Framework\App\Config\ScopeConfigInterface;
use Magento\Framework\App\ProductMetadataInterface;
use Magento\Framework\Component\ComponentRegistrar;
use Magento\Framework\Component\ComponentRegistrarInterface;
use Magento\Framework\Module\FullModuleList;
use Magento\Framework\Module\ModuleListInterface;

/**
 * The software inventory, in exactly the shape the DockRay contract describes
 * and nothing more: no paths, no customers, no configuration values, no keys.
 *
 * - the core: `{type: core, slug: magento}` with the Magento version;
 * - every production Composer package from `vendor/composer/installed.json`,
 *   except the core's own `magento/*` (and Mage-OS `mage-os/*`) packages -
 *   they ship with the core and the core version covers them (a stock
 *   install has several hundred of them);
 * - modules in `app/code` and themes in `app/design`, which Composer does not
 *   know about. DockRay lists them, but has no advisory source for them.
 *
 * A Composer package that contains a disabled module is reported as inactive.
 */
class Collector
{
    public const SCHEMA = 1;

    public const MAX_COMPONENTS = 1000;

    public const MAX_BODY_BYTES = 512000;

    private const SLUG_PATTERN = '/^[A-Za-z0-9._@\/+\-]+$/';

    private const MAX_METADATA_BYTES = 16 * 1024 * 1024;

    public function __construct(
        private readonly Config $config,
        private readonly ProductMetadataInterface $productMetadata,
        private readonly ComponentRegistrarInterface $componentRegistrar,
        private readonly FullModuleList $fullModuleList,
        private readonly ModuleListInterface $enabledModules,
        private readonly ScopeConfigInterface $scopeConfig,
    ) {
    }

    /**
     * @return array{schema: int, platform: string, platform_version: string, php_version: string, site_url: string, agent_version: string, components: list<array>}
     */
    public function payload(): array
    {
        $version = (string) $this->productMetadata->getVersion();

        $payload = [
            'schema' => self::SCHEMA,
            'platform' => 'magento',
            'platform_version' => $version,
            'php_version' => PHP_VERSION,
            'site_url' => $this->siteUrl(),
            'agent_version' => Version::VERSION,
            'components' => $this->components($version),
        ];

        // The server refuses bodies above 512 KB. Trimming the tail beats
        // losing the whole report.
        while (count($payload['components']) > 1 && strlen((string) json_encode($payload)) > self::MAX_BODY_BYTES) {
            $payload['components'] = array_slice($payload['components'], 0, (int) floor(count($payload['components']) * 0.9));
        }

        return $payload;
    }

    /**
     * Stable fingerprint of what is installed - the cron tick compares it with
     * the last report to send early after a deployment.
     */
    public function fingerprint(array $payload): string
    {
        return hash('sha256', (string) json_encode([$payload['platform_version'], $payload['php_version'], $payload['components']]));
    }

    /** @return list<array{type: string, slug: string, name: string, version: string, active: bool, update_version: null}> */
    private function components(string $coreVersion): array
    {
        $components = [];
        $add = static function (?array $component) use (&$components): void {
            if ($component !== null && ! isset($components[$component['type'].':'.$component['slug']])) {
                $components[$component['type'].':'.$component['slug']] = $component;
            }
        };

        $add(self::component('core', 'magento', $this->coreName(), $coreVersion, true));

        $root = $this->config->rootDirectory();
        $disabledPaths = $this->disabledModulePaths();

        foreach ($this->composerPackages($root) as $name => $package) {
            $path = realpath($root.'/vendor/'.$name) ?: $root.'/vendor/'.$name;
            $active = true;

            foreach ($disabledPaths as $disabled) {
                if ($disabled === $path || str_starts_with($disabled, $path.'/')) {
                    $active = false;

                    break;
                }
            }

            $add(self::component('package', $name, $name, $package, $active));
        }

        foreach ($this->localComponents($root.'/app/code', ComponentRegistrar::MODULE) as [$slug, $version, $active]) {
            $add(self::component('module', $slug, $slug, $version, $active));
        }

        foreach ($this->localComponents($root.'/app/design', ComponentRegistrar::THEME) as [$slug, $version]) {
            $add(self::component('theme', $slug, $slug, $version, true));
        }

        $components = array_values($components);

        // The core first, then local code - the part nobody else watches.
        return array_slice($components, 0, self::MAX_COMPONENTS);
    }

    /**
     * Mage-OS reports the Magento version it is built on through getVersion()
     * - that is the number advisories are written against - and its own
     * release through getDistributionVersion(), shown in the name only.
     */
    private function coreName(): string
    {
        $metadata = $this->productMetadata;

        if (method_exists($metadata, 'getDistributionName') && method_exists($metadata, 'getDistributionVersion')
            && (string) $metadata->getDistributionName() !== '' && stripos((string) $metadata->getDistributionName(), 'magento') === false) {
            return $metadata->getDistributionName().' '.$metadata->getDistributionVersion();
        }

        return (string) $metadata->getEdition() === 'Community' ? 'Magento Open Source' : 'Adobe Commerce';
    }

    /** @return array<string, string> package name => version, production packages only */
    private function composerPackages(string $root): array
    {
        $installed = $this->json($root.'/vendor/composer/installed.json');
        $packages = $installed['packages'] ?? $installed;
        $dev = array_flip(is_array($installed['dev-package-names'] ?? null) ? $installed['dev-package-names'] : []);

        if (! is_array($packages)) {
            return [];
        }

        $result = [];

        foreach ($packages as $package) {
            $name = is_array($package) ? ($package['name'] ?? null) : null;
            $version = is_array($package) ? ($package['version'] ?? null) : null;

            if (! is_string($name) || ! is_string($version) || isset($dev[$name])
                || preg_match('#^[a-z0-9_.-]+/[a-z0-9_.-]+$#D', $name) !== 1
                || str_starts_with($name, 'magento/') || str_starts_with($name, 'mage-os/')) {
                continue;
            }

            $result[$name] = (string) preg_replace('/^v(?=\d)/', '', $version);
        }

        ksort($result);

        return $result;
    }

    /**
     * Modules and themes registered from inside `app/` - copied in by hand,
     * so Composer has no record of them.
     *
     * @return list<array{0: string, 1: string, 2: bool}>
     */
    private function localComponents(string $base, string $type): array
    {
        $base = realpath($base);

        if ($base === false) {
            return [];
        }

        $enabled = $type === ComponentRegistrar::MODULE ? array_flip($this->enabledModules->getNames()) : [];
        $result = [];

        foreach ($this->componentRegistrar->getPaths($type) as $name => $path) {
            $real = realpath($path);

            if ($real === false || ! str_starts_with($real, $base.'/')) {
                continue;
            }

            $version = $this->localVersion($real, $type === ComponentRegistrar::MODULE ? $name : null);

            if ($version === null) {
                continue;
            }

            // Modules are `Vendor_Module`, themes `frontend/Vendor/theme`.
            $result[] = [$name, $version, $type !== ComponentRegistrar::MODULE || isset($enabled[$name])];
        }

        return $result;
    }

    /** `composer.json` version first, then `setup_version` from `etc/module.xml`. */
    private function localVersion(string $path, ?string $module): ?string
    {
        $composer = $this->json($path.'/composer.json');

        if (is_string($composer['version'] ?? null) && $composer['version'] !== '') {
            return $composer['version'];
        }

        if ($module !== null) {
            $declared = $this->fullModuleList->getOne($module);
            $setup = is_array($declared) ? ($declared['setup_version'] ?? null) : null;

            if (is_string($setup) && $setup !== '') {
                return $setup;
            }
        }

        return null;
    }

    /** @return list<string> real paths of modules that are installed but disabled */
    private function disabledModulePaths(): array
    {
        $enabled = array_flip($this->enabledModules->getNames());
        $paths = [];

        foreach ($this->fullModuleList->getNames() as $name) {
            if (isset($enabled[$name])) {
                continue;
            }

            $path = $this->componentRegistrar->getPath(ComponentRegistrar::MODULE, $name);
            $real = $path !== null ? realpath($path) : false;

            if ($real !== false) {
                $paths[] = $real;
            }
        }

        return $paths;
    }

    /** The public address of the default store - it tells production from staging. */
    private function siteUrl(): string
    {
        foreach (['web/secure/base_url', 'web/unsecure/base_url'] as $path) {
            $url = trim((string) $this->scopeConfig->getValue($path));

            if ($url !== '' && ! str_contains($url, '{{')) {
                $parts = parse_url($url);

                if (is_array($parts) && isset($parts['scheme'], $parts['host'])) {
                    return $parts['scheme'].'://'.$parts['host'].(isset($parts['port']) ? ':'.$parts['port'] : '').rtrim($parts['path'] ?? '', '/');
                }
            }
        }

        return '';
    }

    /**
     * One component, or null when it would break the server's limits - such
     * a component is skipped, the rest of the report still goes out.
     */
    private static function component(string $type, string $slug, string $name, string $version, bool $active): ?array
    {
        $version = trim($version);
        // Plain text for the JSON body; not strip_tags(), which eats "<" and all after it.
        $name = trim((string) preg_replace('/[\x00-\x1F\x7F]+/u', ' ', $name));

        if ($slug === '' || strlen($slug) > 191 || preg_match(self::SLUG_PATTERN, $slug) !== 1) {
            return null;
        }

        if ($version === '' || mb_strlen($version) > 64) {
            return null;
        }

        return [
            'type' => $type,
            'slug' => $slug,
            'name' => mb_substr($name !== '' ? $name : $slug, 0, 255),
            'version' => $version,
            'active' => $active,
            'update_version' => null,
        ];
    }

    private function json(string $file): array
    {
        if (! is_file($file) || ! is_readable($file) || filesize($file) > self::MAX_METADATA_BYTES) {
            return [];
        }

        $data = json_decode((string) file_get_contents($file), true, 128);

        return is_array($data) ? $data : [];
    }
}
