# Changelog

## 1.0.0

- PHP errors: exceptions that reach Magento's error page and exceptions logged
  at error level or above, reported once each.
- Transactions named after the route, with configurable sample rate.
- JavaScript errors from the storefront, forwarded by the store; works with the
  full page cache.
- Opt-in software inventory for vulnerability checks, sent by Magento cron;
  overview screen with the last report and an admin notice.
- Admin overview page, configuration section with connection test,
  `dockray:test` and `dockray:inventory:send` commands.
- Translations: English, Polish, German, Spanish.
