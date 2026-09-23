@app
Feature: Filter list management
  As a signed-in administrator
  I want to manage filter lists
  So that I can choose which community blocklists noadd uses

  # Shared instance: toggles restore their state and the added list has a
  # unique name.

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
    # Regression: esc() once left " unescaped, so a quote in the name closed the
    # data-name attribute and the rest parsed as attributes (e.g. onmouseover).
    When I add a filter list whose name contains a double quote
    Then no filter list row carries an inline event handler
    And the quoted filter list name is shown as text

  Scenario: Browsing the registry is a page of its own
    # Not a modal, so it works without JavaScript. The javascript:-homepage check
    # is Rust (`a_hostile_homepage_never_becomes_a_link` in tests/admin_api_test.rs):
    # the registry is fetched server-side, beyond a browser route stub.
    When I open the registry browser
    Then the registry browser is a page of its own
