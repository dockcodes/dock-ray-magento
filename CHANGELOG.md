# Changelog

## 1.1.0

- Opt-in security report (`dockray/security/enabled`, off by default): digests
  of the Magento core copies, `app/code` modules, `app/design` themes and every
  Composer package; hashes of entry, configuration and server files; PHP and
  disguised PHP in `pub/media`, server rules that run PHP there, hidden
  directories, unknown PHP in the web roots and backdoor indicators; posture
  (`display_errors`, `exec_available`, `code_writable` as measured on
  storefront requests, `dev_mode`, `debug_tools`). Sent by Magento cron in its
  own `dockray` group, every 6 hours by default (DockRay's `next_report_in`,
  1–24 hours) and a minute after software changes; hash cache in
  `var/dockray/`; `bin/magento dockray:security:send`; open findings and a
  "Send now" button on the overview screen.
- Early fatal error reporter: `early-fatal.php` for `auto_prepend_file`,
  dependency-free and PHP 7.4 compatible, reports fatal errors raised before
  Magento loads the module (`sdk.name` `dockray.magento.early`); status and
  setup line on the overview screen.
- Uninstall also removes the security report state and hash cache.

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
