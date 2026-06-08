@auth
Feature: First-run setup and authentication
  As an administrator opening noadd for the first time
  I want to set an admin password and sign in
  So that the admin UI is protected from unauthorized access

  # These scenarios run against a dedicated noadd instance with a fresh,
  # empty database, in a single worker and in file order. They form one
  # deliberate narrative: a database can only be "set up" once, and
  # revoking sessions is destructive, so they must not share the main
  # authenticated instance used by the @app features.

  Scenario: Setup rejects a mismatched password confirmation
    Given the admin UI has never been configured
    When I open the admin UI
    Then I am shown the first-run setup screen
    When I enter "correct horse battery staple" as the new password
    And I enter "a different password" as the confirmation
    And I submit the setup form
    Then I see a setup error about the passwords not matching
    And the admin password has still not been set

  Scenario: First-run setup creates the admin password and signs in
    Given the admin UI has never been configured
    When I open the admin UI
    Then I am shown the first-run setup screen
    When I enter "correct horse battery staple" as the new password
    And I enter "correct horse battery staple" as the confirmation
    And I submit the setup form
    # Setup auto-logs-in, so a successful setup lands directly on the dashboard.
    Then I land on the dashboard

  Scenario: Sign in fails with an incorrect password
    Given the admin password has been set to "correct horse battery staple"
    When I open the admin UI
    And I sign in with the password "wrong password"
    # A rejected login re-renders the sign-in screen rather than showing an
    # inline error, so the observable outcome is simply staying signed out.
    Then I remain on the sign-in screen

  Scenario: Sign in succeeds with the correct password
    Given the admin password has been set to "correct horse battery staple"
    When I open the admin UI
    And I sign in with the password "correct horse battery staple"
    Then I land on the dashboard

  Scenario: Revoking all sessions returns to the sign-in screen
    Given I am signed in to the admin UI
    When I go to the "Settings" tab
    And I revoke all sessions
    Then I am returned to the sign-in screen
    And reloading the admin UI still shows the sign-in screen
