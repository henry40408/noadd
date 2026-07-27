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

  Scenario: No tab renders markup as escaped text
    # A fragment that should be Markup but reaches html`` as a plain string is
    # escaped and shows up as visible source — `<span class="timeago" …>` filling
    # the Time column, say. Assertions on specific elements sail straight past
    # that, so sweep every tab for text nodes that look like tags.
    When I visit every tab
    Then no tab showed raw markup as text

  Scenario: Leaving the dashboard before it finishes loading strands no poll timer
    # The dashboard's connectedCallback is async: it awaits server-info and a
    # first stats fetch before starting its 10s poll timer. Navigating away in
    # that window runs disconnectedCallback first — while there is still no
    # timer to stop — and the callback then resumes and starts one against a
    # page nobody will tear down again. The stranded timer keeps polling five
    # stats endpoints every 10s for the lifetime of the tab.
    Given I am on the "Settings" tab
    And I am counting dashboard poll timers
    And the server-info request is delayed
    When I go to the "Dashboard" tab
    And I go to the "Query Log" tab
    And the delayed request has arrived
    Then no dashboard poll timer is left running

  Scenario: Rebuilding the app shell leaves no stale navigation handler
    # showApp() replaces the whole app-shell, which is what happens after every
    # sign-in. Without a disconnectedCallback the outgoing shell never
    # unregisters its hashchange listener, so each rebuild strands one more —
    # each holding the whole discarded shell subtree alive through its closure.
    # Nothing breaks visibly (the stale handler just updates its own detached
    # nodes), so the leak has to be measured at the registration level.
    #
    # The rebuild goes through the same 'login-success' event the login page
    # dispatches, driving the production path without spending two more logins
    # against the 5-per-minute login rate limiter.
    Given I am on the "Dashboard" tab
    And I am counting hashchange listener registrations
    And I am recording uncaught page errors
    When the app shell is rebuilt as it is after a fresh sign-in
    And I go to the "Query Log" tab
    And I go to the "Settings" tab
    Then no hashchange listener was left behind
    And exactly one app shell is mounted
    And no uncaught page errors were recorded
