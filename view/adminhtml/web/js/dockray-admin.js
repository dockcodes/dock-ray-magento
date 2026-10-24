/**
 * DockRay admin screens: "Send a test event" and the "Send now" buttons of
 * the vulnerability and security reports without a page reload. No
 * dependencies beyond the browser - the module must not pull in a framework
 * for three buttons.
 */
define([], function () {
    'use strict';

    function post(url, formKey) {
        var body = new URLSearchParams();
        body.append('form_key', formKey);
        body.append('isAjax', 'true');

        return window.fetch(url, {
            method: 'POST',
            credentials: 'same-origin',
            headers: {'X-Requested-With': 'XMLHttpRequest'},
            body: body
        }).then(function (response) {
            return response.json();
        });
    }

    function show(element, text, state) {
        if (!element) {
            return;
        }

        element.textContent = text;
        element.classList.remove('dockray-result--ok', 'dockray-result--error', 'dockray-result--pending');

        if (state) {
            element.classList.add('dockray-result--' + state);
        }
    }

    function setBadge(root, ok, text) {
        root.querySelectorAll('[data-dockray-test-badge]').forEach(function (badge) {
            badge.classList.remove('dockray-pill--ok', 'dockray-pill--error', 'dockray-pill--neutral');
            badge.classList.add(ok ? 'dockray-pill--ok' : 'dockray-pill--error');
            badge.lastChild.textContent = ' ' + text;
        });
    }

    /**
     * A "Send now" button of a report card: posts, shows the answer and puts
     * the server-rendered panel in place. Server-rendered and escaped there;
     * nothing from the response is interpreted here.
     */
    function wireReport(root, name, url, formKey, sending, failed) {
        var button = root.querySelector('[data-dockray-' + name + '-send]');
        var result = root.querySelector('[data-dockray-' + name + '-result]');
        var report = root.querySelector('[data-dockray-' + name + '-report]');

        if (!button || !url) {
            return;
        }

        button.addEventListener('click', function () {
            button.disabled = true;
            show(result, sending, 'pending');

            post(url, formKey).then(function (data) {
                show(result, (data && data.message) || failed, data && data.success ? 'ok' : 'error');

                if (data && typeof data.html === 'string' && report) {
                    report.innerHTML = data.html;
                }
            }).catch(function () {
                show(result, failed, 'error');
            }).finally(function () {
                button.disabled = false;
            });
        });
    }

    return function (config, root) {
        var strings = config.strings || {};
        var testButton = root.querySelector('[data-dockray-test]');
        var testResult = root.querySelector('[data-dockray-test-result]');

        if (testButton) {
            testButton.addEventListener('click', function () {
                testButton.disabled = true;
                show(testResult, strings.sending, 'pending');

                post(config.testUrl, config.formKey).then(function (data) {
                    if (data && data.success) {
                        show(testResult, strings.sentWithId.replace('%1', data.event_id), 'ok');
                        setBadge(root, true, strings.connected);
                    } else {
                        show(testResult, (data && data.message) || strings.failed, 'error');
                        setBadge(root, false, strings.testFailed);
                    }
                }).catch(function () {
                    show(testResult, strings.failed, 'error');
                    setBadge(root, false, strings.testFailed);
                }).finally(function () {
                    testButton.disabled = false;
                });
            });
        }

        wireReport(root, 'inventory', config.inventoryUrl, config.formKey, strings.sending, strings.inventoryFailed);
        wireReport(root, 'security', config.securityUrl, config.formKey, strings.securityScanning || strings.sending, strings.inventoryFailed);
    };
});
