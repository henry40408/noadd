package e2e

import (
	"fmt"

	"github.com/cucumber/godog"

	"github.com/henry40408/noadd/e2e/internal/harness"
)

// markerColours checks the marker before each stat label, which a :has() rule
// on the value's class tints; one keyed on the inline style once silently
// reverted it to green.
const markerColours = `(() => {
	const root = getComputedStyle(document.documentElement);
	// Resolve a custom property to the same rgb() form getComputedStyle returns.
	const rgb = (name) => {
		const d = document.createElement('div');
		d.style.color = root.getPropertyValue(name).trim();
		document.body.appendChild(d);
		const v = getComputedStyle(d).color;
		d.remove();
		return v;
	};
	const out = [];
	for (const card of document.querySelectorAll('.stat-card')) {
		const value = card.querySelector('.stat-value');
		const label = card.querySelector('.stat-label');
		if (!value || !label) continue;
		const cl = value.classList;
		const expected = cl.contains('red') || cl.contains('text-red') ? rgb('--red')
			: cl.contains('text-orange') ? rgb('--orange')
				: rgb('--green');
		const actual = getComputedStyle(label, '::before').color;
		if (actual !== expected) {
			out.push(label.textContent.trim() + ' [' + value.className + ']: marker ' + actual + ', expected ' + expected);
		}
	}
	return out;
})()`

// leakedMarkup finds text nodes that look like tags: a fragment that reached a
// template as a plain string and was escaped into visible source.
const leakedMarkup = `(() => {
	// Only rendered text counts, so skip <script> and <style> bodies.
	const walker = document.createTreeWalker(document.body, NodeFilter.SHOW_TEXT, {
		acceptNode(node) {
			const tag = node.parentElement && node.parentElement.tagName;
			return (tag === 'SCRIPT' || tag === 'STYLE')
				? NodeFilter.FILTER_REJECT : NodeFilter.FILTER_ACCEPT;
		},
	});
	// Named tags rather than any identifier: copy legitimately contains
	// placeholders like 'Authorization: Bearer <token>'.
	const TAG = /<\/?(span|div|a|button|code|td|tr|table|tbody|thead|th|svg|path|input|label|p|br|strong|em|ul|li|select|option)\b[^<>]*>/i;
	const out = [];
	while (walker.nextNode()) {
		const text = walker.currentNode.nodeValue || '';
		if (TAG.test(text)) out.push(text.trim().slice(0, 100));
	}
	return out;
})()`

func registerDashboardSteps(sc *godog.ScenarioContext, w *world) {
	sc.Step(`^I see the `+quoted+` summary card$`, w.seeSummaryCard)
	sc.Step(`^I see the `+quoted+` card$`, w.seeCard)
	sc.Step(`^I see the `+quoted+` metric$`, func(name string) error {
		return w.browser.ExpectText("db-health-card", name)
	})
	sc.Step(`^the status bar reports the server is online$`, w.statusBarOnline)
	sc.Step(`^live updates are active$`, func() error { return w.browser.ExpectText("live-toggle", "LIVE") })
	sc.Step(`^live updates are paused$`, func() error { return w.browser.ExpectText("live-toggle", "PAUSED") })
	sc.Step(`^I toggle live mode$`, func() error { return w.browser.Click("live-toggle") })
	sc.Step(`^every stat card marker matches its value colour$`, w.markersMatch)
	sc.Step(`^I visit every tab$`, w.visitEveryTab)
	sc.Step(`^no tab showed raw markup as text$`, w.noLeakedMarkup)
	sc.Step(`^the summary reports (\d+) queries in the last minute and (\d+) today$`, w.summaryReports)
	sc.Step(`^the Throughput card reads `+quoted+` q/s$`, func(value string) error {
		return w.browser.ExpectExactText("stat-throughput-value", value+"q/s")
	})
	sc.Step(`^the Throughput card shows a 24h mean of `+quoted+`$`, func(value string) error {
		return w.browser.ExpectText("stat-throughput", "24h: "+value)
	})
}

func (w *world) seeSummaryCard(name string) error {
	ids := map[string]string{"Blocked 24h": "stat-blocked-today", "Block Rate": "stat-block-rate"}
	id, known := ids[name]
	if !known {
		return fmt.Errorf("unknown summary card: %s", name)
	}
	return w.browser.ExpectVisible(id)
}

func (w *world) seeCard(name string) error {
	if name != "Top Queried Domains" {
		return fmt.Errorf("unknown card: %s", name)
	}
	return w.browser.ExpectVisible("top-domains-card")
}

// statusBarOnline: the badge ships hidden with a placeholder, and data-state
// proves the event stream actually connected.
func (w *world) statusBarOnline() error {
	if err := w.browser.ExpectVisible("server-status"); err != nil {
		return err
	}
	if err := w.browser.ExpectText("server-status", "ONLINE"); err != nil {
		return err
	}
	online := "online"
	return w.browser.ExpectAttr(`[data-testid="server-status"]`, "data-state", &online)
}

func (w *world) markersMatch() error {
	if err := w.browser.ExpectVisible("app-shell"); err != nil {
		return err
	}
	if _, err := w.browser.CSS(".stat-card"); err != nil {
		return err
	}
	mismatches, err := harness.Eval[[]string](w.browser, markerColours)
	if err != nil {
		return err
	}
	if len(mismatches) > 0 {
		return fmt.Errorf("stat markers not matching their value colour: %q", mismatches)
	}
	return nil
}

func (w *world) visitEveryTab() error {
	var leaked []string
	for _, tab := range navTabs {
		if err := w.goToTab(tab.label); err != nil {
			return err
		}
		if err := w.browser.WaitForLoad(); err != nil {
			return err
		}
		hits, err := harness.Eval[[]string](w.browser, leakedMarkup)
		if err != nil {
			return err
		}
		for _, hit := range hits {
			leaked = append(leaked, tab.label+": "+hit)
		}
	}
	w.leakedMarkup = leaked
	return nil
}

func (w *world) noLeakedMarkup() error {
	if len(w.leakedMarkup) > 0 {
		return fmt.Errorf("markup rendered as visible text: %q", w.leakedMarkup)
	}
	return nil
}

// summaryReports rewrites queries_1m and total_today in every pushed stats
// event, rather than generating live DNS traffic and racing the logger's
// flush. It patches EventSource because the dashboard's readings arrive there.
func (w *world) summaryReports(queries1m, totalToday int) error {
	return w.browser.AddInitScript(fmt.Sprintf(`
		const __add = EventSource.prototype.addEventListener;
		EventSource.prototype.addEventListener = function (type, fn, opts) {
			if (type !== 'stats' || typeof fn !== 'function') {
				return __add.call(this, type, fn, opts);
			}
			return __add.call(this, type, function (e) {
				let data;
				try { data = JSON.parse(e.data); } catch (_) { return fn(e); }
				if (data && data.summary) {
					data.summary.queries_1m = %d;
					data.summary.total_today = %d;
				}
				fn(new MessageEvent(e.type, { data: JSON.stringify(data) }));
			}, opts);
		};
	`, queries1m, totalToday))
}
