@app
Feature: Dashboard and statistics
  As a signed-in administrator
  I want to see DNS query statistics
  So that I can understand what noadd is blocking and forwarding

  # These scenarios are read-only. They run against the shared, already
  # authenticated noadd instance (session restored from storageState).

  Background:
    Given I am signed in to the admin UI

  Scenario: The dashboard shows the query statistics overview
    When I go to the "Dashboard" tab
    Then I see the "Blocked Today" summary card
    And I see the "Block Rate" summary card
    And I see the "Top Queried Domains" card

  Scenario: The statistics page shows database health
    When I go to the "Statistics" tab
    Then I see the "Database Health" section
    And I see the "Database Size" metric
    And I see the "Total Logs" metric

  Scenario: Live mode can be paused and resumed on the dashboard
    Given I am on the "Dashboard" tab
    Then live updates are active
    When I toggle live mode
    Then live updates are paused
    When I toggle live mode
    Then live updates are active
