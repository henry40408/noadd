@onboarding
Feature: New-install onboarding guidance
  As an administrator who has just set up noadd
  I want clear guidance on what to do next and why the screens are empty
  So that I can get noadd actually filtering my devices without guessing

  # A dedicated, initially empty instance; scenarios run one at a time in
  # file order. All but the last need an instance that has served no DNS
  # queries, and the last one sends one — so there is no going back.

  Background:
    Given the admin password has been set to "correct horse battery staple"
    And I am signed in to the admin UI

  Scenario: The dashboard guides a new user to point a device at noadd
    When I go to the "Dashboard" tab
    Then I see onboarding guidance explaining how to point a device at noadd
    And the guidance shows this server's DNS address

  Scenario: The query log explains why no queries have been recorded
    When I go to the "Query Log" tab
    Then I see onboarding guidance explaining that no DNS queries have been logged yet

  Scenario: The next-step banner is shown on a fresh install
    # Not on the dashboard, whose empty state already says the same.
    When I go to the "Settings" tab
    Then I see the next-step banner explaining how to point a device at noadd

  Scenario: Filters warns when every list is disabled
    Given I am on the "Filters" tab
    When I disable every filter list
    Then I see a warning that no filter list is enabled
    And the warning offers a way to enable a recommended list

  Scenario: The next-step banner disappears once noadd serves a real query
    # Cleared by the heartbeat's `traffic` flag; nothing polls for it.
    Given I am on the "Settings" tab
    And I see the next-step banner explaining how to point a device at noadd
    When noadd resolves a real DNS query
    Then the next-step banner is no longer shown
