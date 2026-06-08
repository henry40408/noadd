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
