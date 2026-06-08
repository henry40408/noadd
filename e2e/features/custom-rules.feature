@app
Feature: Custom rules and domain test
  As a signed-in administrator
  I want to add custom allow/block rules and test domains
  So that I can control exactly which domains are blocked or allowed

  # Each scenario uses a unique domain so it does not collide with other
  # scenarios running against the shared instance. Adding a rule triggers
  # an asynchronous filter rebuild, so steps that depend on the rule taking
  # effect wait for the rebuild to settle.

  Background:
    Given I am signed in to the admin UI
    And I am on the "Filters" tab

  Scenario: Add a block rule for a domain
    When I add the custom rule "||blocked-by-test.example.com^"
    Then the custom rules list shows a "block" rule for "blocked-by-test.example.com"

  Scenario: Add an allow rule for a domain
    When I add the custom rule "@@||allowed-by-test.example.com^"
    Then the custom rules list shows an "allow" rule for "allowed-by-test.example.com"

  Scenario: Delete a custom rule
    Given I have added the custom rule "||deletable-by-test.example.com^"
    When I delete the rule for "deletable-by-test.example.com"
    Then the custom rules list no longer shows "deletable-by-test.example.com"

  Scenario: Domain test reports a blocked domain
    Given I have added the custom rule "||domaintest-blocked.example.com^"
    And the filter engine has finished rebuilding
    When I run a domain test for "domaintest-blocked.example.com"
    Then the domain test reports the domain as "Blocked"
    And the domain test result mentions "domaintest-blocked.example.com"

  Scenario: Domain test reports an allowed domain
    Given I have added the custom rule "@@||domaintest-allowed.example.com^"
    And the filter engine has finished rebuilding
    When I run a domain test for "domaintest-allowed.example.com"
    Then the domain test reports the domain as "Allowed"
