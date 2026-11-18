package harness

import (
	"fmt"
	"strings"

	"github.com/chromedp/cdproto/emulation"
	"github.com/chromedp/cdproto/input"
	"github.com/chromedp/chromedp"
)

// RecordRequests is an init script that logs every fetch the page makes, to
// assert what was sent without a request-interception stream. The pages route
// every call through fetch, so nothing escapes it.
const RecordRequests = `
	window.__requests = [];
	const __fetch = window.fetch;
	window.fetch = function (input, init) {
		const url = typeof input === 'string' ? input : input.url;
		const method = (init && init.method) || (input && input.method) || 'GET';
		window.__requests.push({ url: String(url), method: String(method).toUpperCase() });
		return __fetch.apply(this, arguments);
	};
`

// Pixel 5 is the touch phone the chart tap specs emulate.
const (
	pixel5Width  = 393
	pixel5Height = 851
	pixel5Scale  = 2.75
)

// ShortWidth and ShortHeight are the no-JS viewport: short on purpose, so a
// fixed status bar can cover a control and the specs prove they cope.
const (
	ShortWidth  = 1024
	ShortHeight = 600
)

// ClickJS activates the element with a script click, skipping pointer
// hit-testing.
func (e *Element) ClickJS() error {
	_, err := callOn[chromedp.Void](e, "function() { this.click(); }")
	return err
}

// Blur removes the keyboard focus from the element.
func (e *Element) Blur() error {
	_, err := callOn[chromedp.Void](e, "function() { this.blur(); }")
	return err
}

// EmulatePhone makes the page a touch-enabled Pixel 5.
func (b *Browser) EmulatePhone() error {
	err := send(b, emulation.SetDeviceMetricsOverride, emulation.SetDeviceMetricsOverrideParams{
		Width: pixel5Width, Height: pixel5Height, DeviceScaleFactor: pixel5Scale, Mobile: true,
	})
	if err != nil {
		return err
	}
	return send(b, emulation.SetTouchEmulationEnabled, emulation.SetTouchEmulationEnabledParams{Enabled: true})
}

// ReduceMotion emulates prefers-reduced-motion, and keeps the colour scheme
// the browser opened with.
func (b *Browser) ReduceMotion() error {
	return send(b, emulation.SetEmulatedMedia, emulation.SetEmulatedMediaParams{
		Media: "screen",
		Features: []*emulation.MediaFeature{
			{Name: "prefers-color-scheme", Value: "light"},
			{Name: "prefers-reduced-motion", Value: "reduce"},
		},
	})
}

// Tap touches a viewport point as a finger would. Chrome turns the touch into
// pointerdown and pointerup with pointerType "touch".
func (b *Browser) Tap(x, y float64) error {
	touchID := 1.0
	point := []*input.TouchPoint{{X: x, Y: y, ID: &touchID}}
	err := send(b, input.DispatchTouchEvent, input.DispatchTouchEventParams{Type: input.DispatchTouchEventTypeTouchStart, TouchPoints: point})
	if err != nil {
		return err
	}
	return send(b, input.DispatchTouchEvent, input.DispatchTouchEventParams{Type: input.DispatchTouchEventTypeTouchEnd, TouchPoints: []*input.TouchPoint{}})
}

// RequestCount is how many recorded fetches used method against a URL
// containing path. It needs RecordRequests installed.
func (b *Browser) RequestCount(method, path string) (int, error) {
	return Eval[int](b, fmt.Sprintf(`(window.__requests || []).filter(
		(r) => r.method === %s && r.url.includes(%s)).length`, JSLiteral(method), JSLiteral(path)))
}

// ExpectRequest waits for one more method request to path than before.
func (b *Browser) ExpectRequest(method, path string, before int) error {
	return Eventually(fmt.Sprintf("a %s to %s", method, path), func() (bool, error) {
		now, err := b.RequestCount(method, path)
		return now > before, err
	})
}

// HasText reports whether any text node on the page contains needle.
func (b *Browser) HasText(needle string) (bool, error) {
	return Eval[bool](b, `(() => {
		let text = '';
		for (const el of document.body.querySelectorAll('*')) {
			if (el.tagName === 'SCRIPT' || el.tagName === 'STYLE') { continue; }
			for (const child of el.childNodes) {
				if (child.nodeType === Node.TEXT_NODE) { text += child.nodeValue + '\n'; }
			}
		}
		return text.includes(`+JSLiteral(needle)+`);
	})()`)
}

// ExpectPageText waits for some text node on the page to contain needle.
func (b *Browser) ExpectPageText(needle string) error {
	return Eventually(fmt.Sprintf("the page shows %q", needle), func() (bool, error) {
		return b.HasText(needle)
	})
}

// ExpectURLContains waits for the path and query to contain needle.
func (b *Browser) ExpectURLContains(needle string) error {
	return b.expectLocation("contains "+needle, strings.Contains, needle)
}

// ExpectURLEndsWith waits for the path and query to end with suffix.
func (b *Browser) ExpectURLEndsWith(suffix string) error {
	return b.expectLocation("ends with "+suffix, strings.HasSuffix, suffix)
}

func (b *Browser) expectLocation(what string, holds func(string, string) bool, want string) error {
	return Eventually("the URL "+what, func() (bool, error) {
		location, err := b.PathAndQuery()
		return holds(location, want), err
	})
}
