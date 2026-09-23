@app
Feature: Dashboard and statistics
  As a signed-in administrator
  I want to see DNS query statistics
  So that I can understand what noadd is blocking and forwarding

  # Read-only, against the shared instance with a pre-provisioned session.

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

  Scenario: The status bar reports the server as reachable
    # ONLINE comes from the event stream connecting, not from the markup.
    Given I am on the "Dashboard" tab
    Then the status bar reports the server is online

  Scenario: Live mode can be paused and resumed on the dashboard
    Given I am on the "Dashboard" tab
    Then live updates are active
    When I toggle live mode
    Then live updates are paused
    When I toggle live mode
    Then live updates are active

  Scenario: Stat card markers stay tinted by their value's colour
    # The ▌ marker is tinted by a :has() rule on the value's class; a rule keyed
    # on the inline style once silently reverted it to green.
    Given I am on the "Dashboard" tab
    Then every stat card marker matches its value colour
    When I go to the "Statistics" tab
    Then every stat card marker matches its value colour

  Scenario: The Throughput card shows the live rate, not the 24-hour mean
    # Throughput promises a current reading: q/s comes from queries_1m, with
    # total_today / 86400 shown only as the 24h mean.
    Given I am on the "Settings" tab
    And the summary reports 120 queries in the last minute and 86400 today
    When I go to the "Dashboard" tab
    Then the Throughput card reads "2.00" q/s
    And the Throughput card shows a 24h mean of "1.00"

  Scenario: No tab renders markup as escaped text
    # A fragment reaching html`` as a plain string instead of Markup shows up as
    # visible source (e.g. `<span class="timeago" …>`); sweep every tab for it.
    When I visit every tab
    Then no tab showed raw markup as text
