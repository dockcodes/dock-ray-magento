<?php

declare(strict_types=1);

namespace DockCodes\DockRay\Model;

use Dock\Ray\AuthData;
use Magento\Framework\App\Config\ScopeConfigInterface;
use Magento\Framework\App\DeploymentConfig;
use Magento\Framework\App\Filesystem\DirectoryList;
use Magento\Framework\App\State;
use Magento\Framework\Encryption\EncryptorInterface;

/**
 * Settings of the module, always from the default scope.
 *
 * Magento already decides between the database, app/etc/env.php and
 * CONFIG__DEFAULT__* variables, and locks the admin field when the value comes
 * from a file - so this class only reads. That is the WordPress plugin's
 * "Auto" source, which here is the platform's own behaviour.
 */
class Config
{
    public const XML_TOKEN = 'dockray/connection/token';

    public const XML_PRIVATE_KEY = 'dockray/connection/private_key';

    public const XML_ENVIRONMENT = 'dockray/general/environment';

    public const XML_RELEASE = 'dockray/general/release';

    public const XML_TRACES_SAMPLE_RATE = 'dockray/general/traces_sample_rate';

    public const XML_SEND_DEFAULT_PII = 'dockray/general/send_default_pii';

    public const XML_JS_ERRORS = 'dockray/browser/enabled';

    public const XML_JS_SAMPLE_RATE = 'dockray/browser/sample_rate';

    public const XML_INVENTORY = 'dockray/inventory/enabled';

    /** Every path the module stores - uninstall removes exactly these. */
    public const PATHS = [
        self::XML_TOKEN, self::XML_PRIVATE_KEY, self::XML_ENVIRONMENT, self::XML_RELEASE,
        self::XML_TRACES_SAMPLE_RATE, self::XML_SEND_DEFAULT_PII, self::XML_JS_ERRORS,
        self::XML_JS_SAMPLE_RATE, self::XML_INVENTORY,
    ];

    private ?string $release = null;

    private bool $releaseResolved = false;

    public function __construct(
        private readonly ScopeConfigInterface $scopeConfig,
        private readonly EncryptorInterface $encryptor,
        private readonly DeploymentConfig $deploymentConfig,
        private readonly DirectoryList $directoryList,
        private readonly State $state,
    ) {
    }

    public function token(): string
    {
        return trim((string) $this->scopeConfig->getValue(self::XML_TOKEN));
    }

    /**
     * The admin screen stores the key encrypted; app/etc/env.php and
     * environment variables carry it in plain text. Both are accepted.
     */
    public function privateKey(): string
    {
        $value = trim((string) $this->scopeConfig->getValue(self::XML_PRIVATE_KEY));

        if ($value !== '' && preg_match('/^\d+:\d+:/', $value) === 1) {
            try {
                $value = trim((string) $this->encryptor->decrypt($value));
            } catch (\Throwable) {
                return '';
            }
        }

        return $value;
    }

    public function isConfigured(): bool
    {
        return $this->token() !== '' && $this->privateKey() !== '';
    }

    /**
     * Where reports go. Not a setting: the module always reports to DockRay.
     * `dockray/url` in app/etc/env.php exists for DockRay's own test
     * environments only and is deliberately left out of the admin screen -
     * whoever gets into the back office must not be able to redirect the
     * store's errors elsewhere.
     */
    public function serverUrl(): string
    {
        try {
            $url = $this->deploymentConfig->get('dockray/url');
        } catch (\Throwable) {
            $url = null;
        }

        return is_string($url) && trim($url) !== '' ? rtrim(trim($url), '/') : AuthData::DEFAULT_URL;
    }

    public function environment(): string
    {
        $value = trim((string) $this->scopeConfig->getValue(self::XML_ENVIRONMENT));

        if ($value !== '') {
            return $value;
        }

        try {
            return $this->state->getMode() === State::MODE_DEVELOPER ? 'development' : 'production';
        } catch (\Throwable) {
            return 'production';
        }
    }

    /**
     * The stored release, or the deployed static content version: Magento
     * writes a new one at every `setup:static-content:deploy`, so each
     * deployment shows up in the panel as its own release.
     */
    public function release(): ?string
    {
        $value = trim((string) $this->scopeConfig->getValue(self::XML_RELEASE));

        if ($value !== '') {
            return $value;
        }

        if (! $this->releaseResolved) {
            $this->releaseResolved = true;

            try {
                $file = $this->directoryList->getPath(DirectoryList::STATIC_VIEW).'/deployed_version.txt';
                $version = is_file($file) ? trim((string) file_get_contents($file, false, null, 0, 64)) : '';
                $this->release = preg_match('/^[A-Za-z0-9._-]{1,64}$/', $version) === 1 ? $version : null;
            } catch (\Throwable) {
                $this->release = null;
            }
        }

        return $this->release;
    }

    public function tracesSampleRate(): float
    {
        return $this->rate(self::XML_TRACES_SAMPLE_RATE, 0.0);
    }

    public function sendDefaultPii(): bool
    {
        return $this->scopeConfig->isSetFlag(self::XML_SEND_DEFAULT_PII);
    }

    public function jsErrors(): bool
    {
        return $this->scopeConfig->isSetFlag(self::XML_JS_ERRORS);
    }

    public function jsSampleRate(): float
    {
        return $this->rate(self::XML_JS_SAMPLE_RATE, 1.0);
    }

    public function inventory(): bool
    {
        return $this->scopeConfig->isSetFlag(self::XML_INVENTORY);
    }

    public function rootDirectory(): string
    {
        return rtrim($this->directoryList->getRoot(), '/\\');
    }

    private function rate(string $path, float $default): float
    {
        $value = $this->scopeConfig->getValue($path);

        if ($value === null || $value === '' || ! is_numeric($value)) {
            return $default;
        }

        return max(0.0, min(1.0, (float) $value));
    }
}
