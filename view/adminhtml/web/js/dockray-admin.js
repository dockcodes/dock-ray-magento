/**
 * DockRay admin screens: "Send a test event" and "Send now" without a page
 * reload. No dependencies beyond the browser - the module must not pull in
 * a framework for two buttons.
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

    return function (config, root) {
        var strings = config.strings || {};
        var testButton = root.querySelector('[data-dockray-test]');
        var testResult = root.querySelector('[data-dockray-test-result]');
        var inventoryButton = root.querySelector('[data-dockray-inventory-send]');
        var inventoryResult = root.querySelector('[data-dockray-inventory-result]');
        var inventoryReport = root.querySelector('[data-dockray-inventory-report]');

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

        if (inventoryButton) {
            inventoryButton.addEventListener('click', function () {
                inventoryButton.disabled = true;
                show(inventoryResult, strings.sending, 'pending');

                post(config.inventoryUrl, config.formKey).then(function (data) {
                    show(inventoryResult, (data && data.message) || strings.inventoryFailed, data && data.success ? 'ok' : 'error');

                    // Server-rendered and escaped there; nothing from the
                    // response is interpreted here.
                    if (data && typeof data.html === 'string' && inventoryReport) {
                        inventoryReport.innerHTML = data.html;
                    }
                }).catch(function () {
                    show(inventoryResult, strings.inventoryFailed, 'error');
                }).finally(function () {
                    inventoryButton.disabled = false;
                });
            });
        }
    };
});
