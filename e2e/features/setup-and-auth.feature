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

  Scenario: Setup rejects a password shorter than the minimum length
    Given the admin UI has never been configured
    When I open the admin UI
    Then I am shown the first-run setup screen
    When I enter "hunter2" as the new password
    And I enter "hunter2" as the confirmation
    And I submit the setup form
    Then I see a setup error about the password being too short
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
    And I see a welcome message confirming the setup is complete

  Scenario: Sign in fails with an incorrect password
    Given the admin password has been set to "correct horse battery staple"
    When I open the admin UI
    And I sign in with the password "wrong password"
    Then I see a sign-in error telling me the password is incorrect
    And I remain on the sign-in screen

  Scenario: Sign in succeeds with the correct password
    Given the admin password has been set to "correct horse battery staple"
    When I open the admin UI
    And I sign in with the password "correct horse battery staple"
    Then I land on the dashboard

  Scenario: The next-step banner can be dismissed and stays dismissed
    # On a fresh install the dashboard shows a banner telling the admin how to
    # point a device at noadd. This instance never serves DNS queries, so the
    # banner here can only be cleared by an explicit dismissal, and that choice
    # must survive a reload.
    Given the admin password has been set to "correct horse battery staple"
    When I open the admin UI
    And I sign in with the password "correct horse battery staple"
    Then I land on the dashboard
    And I see the next-step banner explaining how to point a device at noadd
    When I dismiss the next-step banner
    Then the next-step banner is no longer shown
    And reloading the admin UI does not show the next-step banner again

  Scenario: Revoking all sessions returns to the sign-in screen
    Given I am signed in to the admin UI
    When I go to the "Settings" tab
    And I revoke all sessions
    Then I am returned to the sign-in screen
    And reloading the admin UI still shows the sign-in screen
