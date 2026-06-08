@onboarding
Feature: New-install onboarding guidance
  As an administrator who has just set up noadd
  I want clear guidance on what to do next and why the screens are empty
  So that I can get noadd actually filtering my devices without guessing

  # These scenarios run against a dedicated noadd instance with a fresh,
  # empty database, in a single worker and in file order. They form one
  # deliberate, one-way narrative: the empty-state and banner scenarios all
  # depend on the instance having served no DNS queries yet, and the final
  # scenario sends a real query to prove the banner clears itself — so once
  # that query is served there is no going back to the pristine state.

  Background:
    Given the admin password has been set to "correct horse battery staple"
    And I am signed in to the admin UI

  Scenario: The dashboard guides a new user to point a device at noadd
    # No device is using noadd yet, so there are no statistics to chart.
    When I go to the "Dashboard" tab
    Then I see onboarding guidance explaining how to point a device at noadd
    And the guidance shows this server's DNS address

  Scenario: The query log explains why no queries have been recorded
    When I go to the "Query Log" tab
    Then I see onboarding guidance explaining that no DNS queries have been logged yet

  Scenario: The next-step banner is shown on a fresh install
    When I go to the "Dashboard" tab
    Then I see the next-step banner explaining how to point a device at noadd

  Scenario: Filters warns when every list is disabled
    # A fresh install enables one default list, so noadd blocks out of the box.
    # If the admin turns every list off, nothing is being filtered and the page
    # surfaces a warning prompting them to re-enable a list.
    Given I am on the "Filters" tab
    When I disable every filter list
    Then I see a warning that no filter list is enabled
    And the warning offers a way to enable a recommended list

  Scenario: The next-step banner disappears once noadd serves a real query
    Given I am on the "Dashboard" tab
    And I see the next-step banner explaining how to point a device at noadd
    When noadd resolves a real DNS query
    Then the next-step banner is no longer shown
