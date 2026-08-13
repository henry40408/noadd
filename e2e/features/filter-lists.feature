@app
Feature: Filter list management
  As a signed-in administrator
  I want to manage filter lists
  So that I can choose which community blocklists noadd uses

  # These scenarios run against the shared authenticated instance. Toggling
  # scenarios restore the original state, and the add scenario uses a unique
  # list name, so they remain self-contained.

  Background:
    Given I am signed in to the admin UI
    And I am on the "Filters" tab

  Scenario: The filter lists table shows the built-in lists
    Then I see the "Filter Lists" section
    And I see a filter list named "AdGuard DNS filter"
    And each filter list shows an enabled state and a rule count

  Scenario: Disable and re-enable a filter list
    Given the filter list "AdGuard DNS filter" is enabled
    When I disable the filter list "AdGuard DNS filter"
    Then the filter list "AdGuard DNS filter" is shown as disabled
    When I enable the filter list "AdGuard DNS filter"
    Then the filter list "AdGuard DNS filter" is shown as enabled

  Scenario: Add a custom filter list
    When I add a custom filter list named "E2E Test List" with URL "https://example.com/e2e-test-list.txt"
    Then the filter lists table shows a list named "E2E Test List"

  Scenario: A quote in a filter list name cannot inject an attribute
    # esc() used to round-trip through textContent/innerHTML, which escapes &, <
    # and > but leaves " alone. Since the name is interpolated into a
    # double-quoted data-name, a name carrying a quote closed that attribute
    # early and the remainder was parsed as further attributes — a working
    # onmouseover among them.
    When I add a filter list whose name contains a double quote
    Then no filter list row carries an inline event handler
    And the quoted filter list name is shown as text

  Scenario: Browsing the registry is a page of its own
    # It was a modal mounted on document.body, which made this the one control
    # on the page that did nothing without JavaScript. Two scenarios went with
    # it: the modal's Escape-handler teardown, which has no subject any more,
    # and the javascript:-homepage check, which moved to Rust —
    # `a_hostile_homepage_never_becomes_a_link` in tests/admin_api_test.rs. The
    # registry is fetched by the server now, so a browser-side route stub no
    # longer intercepts it, and the Rust test exercises the rendering itself.
    When I open the registry browser
    Then the registry browser is a page of its own
