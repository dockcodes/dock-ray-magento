# DockRay for Magento 2

Reports PHP errors, exceptions, request timings, JavaScript errors and —
optionally — vulnerable software from a Magento Open Source / Adobe Commerce
2.4.4+ or Mage-OS store to [DockRay](https://dockray.io).

## Installation

```shell
composer require dockcodes/dock-ray-magento
bin/magento module:enable DockCodes_DockRay
bin/magento setup:upgrade
# production mode:
bin/magento setup:di:compile
bin/magento setup:static-content:deploy
```

The module adds a **DockRay** item to the admin menu (Overview, Settings) and a
**Stores → Configuration → DockRay → Monitoring** section.

## Configuration

| Field | Meaning |
|---|---|
| Project token | public identifier, part of the ingest URL |
| Project private key | project secret, stored encrypted; leave the dots to keep it |
| Environment | defaults to `production`, or `development` in developer mode |
| Release | defaults to the deployed static content version (`pub/static/deployed_version.txt`) |
| Transaction sample rate | `0` disables performance tracking |
| Send user identity, IP address and user agent | off by default |
| Collect JavaScript errors | off by default, see below |
| Send software versions for vulnerability checks | off by default, see below |

Settings are global (default scope). Magento's own override mechanism replaces
the "constants" source of the WordPress plugin: a value in `app/etc/env.php`
or in an environment variable wins and shows up in the admin as a locked field.
Keep the private key out of the database:

```shell
bin/magento config:set --lock-env dockray/connection/token PROJECT_TOKEN
bin/magento config:set --lock-env dockray/connection/private_key PROJECT_PRIVATE_KEY
# or: CONFIG__DEFAULT__DOCKRAY__CONNECTION__PRIVATE_KEY=... in the PHP-FPM environment
```

A store copied to staging carries its database — and with it the credentials.
Locking a different key in staging's `env.php` keeps both environments apart.
The private key is marked sensitive, so `app:config:dump` never writes it to
`app/etc/config.php`.

The module always reports to `https://dockray.io`. `dockray/url` in
`app/etc/env.php` exists for DockRay's own test environments only.

**Send a test event** (admin, or `bin/magento dockray:test`) posts one exception
and waits for DockRay's answer, so a wrong token or key shows up straight away.

## What is reported

| Source | How |
|---|---|
| exceptions that reach Magento's error page | plugin on `Magento\Framework\App\Http::catchException()` |
| exceptions Magento logs at error level or above (`$logger->critical($e)` in controllers, REST, GraphQL, payment and shipping integrations, cron) | Monolog handler added to `Magento\Framework\Logger\Monolog` |
| fatal errors and uncaught exceptions | the SDK's default integrations |

An exception that is both logged and shown on the error page is reported once.
Log records without an exception are skipped: they have no type and no stack,
and their text usually carries an order id, which would split one problem into
thousands of entries. PHP warnings are not reported separately — Magento turns
them into exceptions itself, and those are reported.

The logger handler and the plugins get the reporter through a generated proxy,
so nothing is built until the first error arrives. Without a token and a key
the module loads and stays silent.

## When events are sent

After the response. Events are queued during the request and flushed from a
shutdown handler, once PHP-FPM has handed the page to the shopper. A slow or
unreachable DockRay costs the visitor nothing. Console commands and cron send
inline.

## Privacy

Every event passes one filter before it is serialised (`Model\Privacy`):
addresses lose their query string, the request keeps only its address and
method (no headers, cookies or body — checkout forms carry addresses), stack
frames lose local variables, and without "send user identity" the user and the
user agent are dropped. With it, the id, name and e-mail of the logged-in
customer (storefront, REST, GraphQL) or admin user are attached — resolved only
when an error is reported.

## Transactions

With a sample rate above zero, each web request (storefront, admin, REST,
GraphQL) becomes a transaction named after its route — `GET catalog_product_view`,
not one entry per product URL. REST paths without a route name keep their
shape with identifiers replaced (`/rest/default/V1/orders/{id}`), and full page
cache hits are grouped as `GET full_page_cache`. The module's own endpoints are
not measured.

## JavaScript errors

Off by default. Once enabled, the storefront loads the collector shipped with
the PHP SDK, served by the store itself (`/dockray/browser/script`). It reports
`window.onerror` and unhandled promise rejections **to the store**
(`POST /dockray/browser/error`), which forwards them with its own key — the
private key never reaches the page.

The page stays identical for every visitor, so it works with the full page
cache and Varnish: the collector reads Magento's form key from the `form_key`
cookie when it sends. The endpoint checks that key, limits the body to 16 kB
and the rate to 20 reports per minute per IP address, and always answers `202`.
After switching the option, flush the full page cache.

## Software versions for vulnerability checks

Off by default. Sends to `POST /api/v1/{token}/inventory` (contract:
`resources/extensions/INVENTORY.md` in the DockRay repository):

- the Magento version (`{type: core, slug: magento}`),
- production Composer packages from `vendor/composer/installed.json` —
  third-party extensions and libraries; Adobe's own `magento/*` packages are
  left out, because the core version covers them,
- modules in `app/code` and themes in `app/design` with their versions —
  DockRay lists them, but has no advisory source for hand-copied code,
- the PHP version and the store's base URL.

Nothing else: no paths, customers, configuration values or keys. The private
key travels only in the `Authorization` header, over HTTPS with certificate
verification, no redirects, 5 s connect and 10 s total timeout.

Magento cron runs the check every fifteen minutes and sends when the interval
asked for by DockRay has passed (12 hours by default, clamped to 1 hour … 7
days) or when the installed software changed since the last report — after a
deployment, `composer update`, a module switched on or off. A database lock
keeps two runs apart; rate limiting and server errors back off instead of
retrying in a loop.

The **DockRay → Overview** screen shows the last report with the vulnerable
components, their severity and the fixed version, and has a **Send now**
button (`bin/magento dockray:inventory:send` from a deployment script). When
the last report found something, a notice at the top of the admin links to it.

## Uninstall

`bin/magento module:uninstall DockCodes_DockRay` removes the settings and the
stored report. With `composer remove`, run `bin/magento setup:upgrade` after it.

## Requirements

Magento Open Source / Adobe Commerce 2.4.4+ or Mage-OS 1.x, PHP 8.1+,
`dockcodes/dock-ray` 1.4+ (pulled by Composer).

## License

MIT. See [LICENSE](LICENSE).
