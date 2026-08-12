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

  Scenario: Stat card markers stay tinted by their value's colour
    # The ▌ before each stat label is tinted by a :has() rule that reads the
    # value's class. It once read the inline style attribute instead, so moving
    # a colour to a utility class silently reverted the marker to green with
    # nothing else changing and no test noticing.
    Given I am on the "Dashboard" tab
    Then every stat card marker matches its value colour
    When I go to the "Statistics" tab
    Then every stat card marker matches its value colour

  Scenario: The Throughput card shows the live rate, not the 24-hour mean
    # The card is labelled Throughput and flashes on change, both of which
    # promise a current reading. It derived q/s from total_today / 86400, so a
    # traffic spike could never move it, while queries_1m — fetched on every
    # summary refresh at the cost of its own DB round-trip — was discarded.
    Given I am on the "Settings" tab
    And the summary reports 120 queries in the last minute and 86400 today
    When I go to the "Dashboard" tab
    Then the Throughput card reads "2.00" q/s
    And the Throughput card shows a 24h mean of "1.00"

  Scenario: No tab renders markup as escaped text
    # A fragment that should be Markup but reaches html`` as a plain string is
    # escaped and shows up as visible source — `<span class="timeago" …>` filling
    # the Time column, say. Assertions on specific elements sail straight past
    # that, so sweep every tab for text nodes that look like tags.
    When I visit every tab
    Then no tab showed raw markup as text
