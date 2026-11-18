package harness

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/chromedp/cdproto/browser"
	"github.com/chromedp/cdproto/cdp"
	"github.com/chromedp/cdproto/emulation"
	"github.com/chromedp/cdproto/network"
	"github.com/chromedp/cdproto/page"
	"github.com/chromedp/chromedp"
)

// ScenarioTimeout bounds one scenario, so a wedged Chrome cannot hang the run.
const ScenarioTimeout = 3 * time.Minute

// DesktopWidth and DesktopHeight are the viewport a scenario starts with.
const (
	DesktopWidth  = 1280
	DesktopHeight = 720
	closeTimeout  = 10 * time.Second
)

// DialogPolicy says what the browser does with a confirm() prompt. The prompt
// blocks the click that opened it, so a step cannot answer afterwards: it
// states the answer before clicking.
type DialogPolicy int

const (
	// DismissDialogs cancels a prompt. It is the default, and the message is
	// still recorded, so a prompt nobody expected is visible to the steps.
	DismissDialogs DialogPolicy = iota
	// AcceptDialogs confirms a prompt.
	AcceptDialogs
)

// Browser is a headless Chrome of its own, scoped to one scenario.
//
// One process per scenario isolates cookies and storage.
type Browser struct {
	ctx    context.Context
	cancel context.CancelFunc

	mu      sync.Mutex
	policy  DialogPolicy
	dialogs []string
}

// Scripting says whether the page's own scripts run: the scripted path, or
// the @nojs path.
type Scripting bool

const (
	ScriptsOn  Scripting = true
	ScriptsOff Scripting = false
)

// Open starts a headless Chrome with the page's scripts on.
func Open() (*Browser, error) {
	return OpenWith(ScriptsOn)
}

// OpenWith starts a headless Chrome. Disabled scripting applies from the next
// document on, so it is set before the first navigation.
func OpenWith(scripting Scripting) (*Browser, error) {
	timeoutCtx, cancelTimeout := context.WithTimeout(context.Background(), ScenarioTimeout)
	allocCtx, cancelAlloc := chromedp.NewExecAllocator(timeoutCtx, allocatorOptions()...)
	tabCtx, cancelTab := chromedp.NewContext(allocCtx)
	opened := &Browser{
		ctx: tabCtx,
		cancel: func() {
			cancelTab()
			cancelAlloc()
			cancelTimeout()
		},
	}

	if err := opened.start(scripting); err != nil {
		opened.cancel()
		return nil, err
	}
	return opened, nil
}

// ChromeEnv names the variable that pins the browser binary.
const ChromeEnv = "E2E_CHROME"

// BrowserChoice says which browser Open will start, for the run's log.
func BrowserChoice() string {
	if path := os.Getenv(ChromeEnv); path != "" {
		return ChromeEnv + "=" + path
	}
	return "chromedp's default search (" + ChromeEnv + " is unset)"
}

func allocatorOptions() []chromedp.ExecAllocatorOption {
	options := append([]chromedp.ExecAllocatorOption{}, chromedp.DefaultExecAllocatorOptions[:]...)
	options = append(options, chromedp.WindowSize(DesktopWidth, DesktopHeight),
		// Classic Linux scrollbars take 15px off the viewport and macOS overlay
		// ones none, so width assertions would pass locally and fail on CI.
		chromedp.Flag("hide-scrollbars", true))
	// chromedp's own search prefers a chromium on PATH over google-chrome, so
	// CI pins the binary it reports.
	if path := os.Getenv(ChromeEnv); path != "" {
		options = append(options, chromedp.ExecPath(path))
	}
	return options
}

func (b *Browser) start(scripting Scripting) error {
	if err := chromedp.Do(b.ctx); err != nil {
		return fmt.Errorf("could not start a browser (%s): a local Chromium or Chrome is required "+
			"(`brew install --cask ungoogled-chromium`), or set %s to its path: %w", BrowserChoice(), ChromeEnv, err)
	}
	if err := chromedp.Listen(b.ctx, b.recordDialog); err != nil {
		return err
	}
	// --window-size sizes the window, not the viewport; without this a desktop
	// scenario could fall under a stylesheet breakpoint and silently test the
	// phone layout.
	if err := b.SetViewport(DesktopWidth, DesktopHeight); err != nil {
		return err
	}
	// Headless Chrome inherits the host's appearance; pin light. A scenario
	// that wants dark emulates it again.
	if err := b.EmulateColorScheme("light"); err != nil {
		return err
	}
	if scripting == ScriptsOff {
		return send(b, emulation.SetScriptExecutionDisabled, emulation.SetScriptExecutionDisabledParams{Value: true})
	}
	return nil
}

// Close ends the browser, and the profile directory goes with it.
func (b *Browser) Close() {
	closing, cancel := context.WithTimeout(b.ctx, closeTimeout)
	defer cancel()
	_ = chromedp.Cancel(closing)
	b.cancel()
}

// EmulateColorScheme emulates prefers-color-scheme.
func (b *Browser) EmulateColorScheme(scheme string) error {
	return send(b, emulation.SetEmulatedMedia, emulation.SetEmulatedMediaParams{
		Media:    "screen",
		Features: []*emulation.MediaFeature{{Name: "prefers-color-scheme", Value: scheme}},
	})
}

// SetViewport sizes the page in CSS pixels. It uses the device metrics
// override rather than the window, whose outer size includes browser chrome.
func (b *Browser) SetViewport(width, height int64) error {
	return send(b, emulation.SetDeviceMetricsOverride, emulation.SetDeviceMetricsOverrideParams{
		Width:             width,
		Height:            height,
		DeviceScaleFactor: 1,
	})
}

func send[P any](b *Browser, command cdp.Command[P, cdp.Empty], params P) error {
	_, err := chromedp.Call(b.ctx, command, params)
	return err
}

// SetExtraHeaders sends the headers with every request from now on.
func (b *Browser) SetExtraHeaders(headers map[string]string) error {
	if _, err := chromedp.Call(b.ctx, network.Enable, network.EnableParams{}); err != nil {
		return err
	}
	converted := network.Headers{}
	for name, value := range headers {
		converted[name] = value
	}
	_, err := chromedp.Call(b.ctx, network.SetExtraHTTPHeaders, network.SetExtraHTTPHeadersParams{Headers: converted})
	return err
}

// GrantClipboard lets the page write the clipboard; headless Chrome rejects
// clipboard.writeText without it.
func (b *Browser) GrantClipboard() error {
	for _, name := range []string{"clipboard-read", "clipboard-write"} {
		_, err := chromedp.CallBrowser(b.ctx, browser.SetPermission, browser.SetPermissionParams{
			Permission: &browser.PermissionDescriptor{Name: name},
			Setting:    browser.PermissionSettingGranted,
		})
		if err != nil {
			return err
		}
	}
	return nil
}

// SetDialogPolicy chooses how the next confirm() prompts are answered.
func (b *Browser) SetDialogPolicy(policy DialogPolicy) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.policy = policy
}

// Dialogs are the messages of the prompts shown so far, oldest first.
func (b *Browser) Dialogs() []string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return append([]string(nil), b.dialogs...)
}

func (b *Browser) recordDialog(event any) {
	opening, ok := event.(*page.EventJavascriptDialogOpening)
	if !ok {
		return
	}
	b.mu.Lock()
	b.dialogs = append(b.dialogs, opening.Message)
	accept := b.policy == AcceptDialogs
	b.mu.Unlock()
	// The listener runs on chromedp's event loop; answering inline would
	// deadlock it.
	go func() {
		_, _ = chromedp.Call(b.ctx, page.HandleJavaScriptDialog, page.HandleJavaScriptDialogParams{Accept: accept})
	}()
}

// Goto navigates to a URL and waits for the page to load.
func (b *Browser) Goto(url string) error {
	return chromedp.Do(b.ctx, chromedp.Navigate(url))
}

// Reload reloads the page and waits for it to load.
func (b *Browser) Reload() error {
	if err := chromedp.Do(b.ctx, chromedp.Reload()); err != nil {
		return err
	}
	return b.WaitForLoad()
}

// WaitForLoad waits for document.readyState to be "complete".
//
// CDP does not wait for a page load after a click, so every read or action
// that follows a navigation waits first.
func (b *Browser) WaitForLoad() error {
	return Eventually("the page to finish loading", func() (bool, error) {
		state, err := Eval[string](b, "document.readyState")
		return state == "complete", err
	})
}

// URL is the page's current URL.
func (b *Browser) URL() (*url.URL, error) {
	location, err := chromedp.Run(b.ctx, chromedp.Location())
	if err != nil {
		return nil, err
	}
	return url.Parse(location)
}

// PathAndQuery is the current URL's path and query, the shape the steps assert
// against: the port is ephemeral, so full URLs are unstable.
func (b *Browser) PathAndQuery() (string, error) {
	current, err := b.URL()
	if err != nil {
		return "", err
	}
	if current.RawQuery == "" {
		return current.Path, nil
	}
	return current.Path + "?" + current.RawQuery, nil
}

// Screenshot captures the viewport as a PNG.
func (b *Browser) Screenshot() ([]byte, error) {
	return chromedp.Run(b.ctx, chromedp.CaptureScreenshot())
}

// Eval evaluates a JavaScript expression in the page and decodes the result.
//
// Reads go through JavaScript rather than DOM-domain queries, because
// chromedp's queries wait forever by default and the suite's lookups are
// immediate.
func Eval[T any](b *Browser, expression string) (T, error) {
	return chromedp.Run(b.ctx, chromedp.Evaluate[T](expression))
}

// EvalAsync is Eval for an expression that yields a promise: it waits for the
// promise and decodes what it resolves to.
func EvalAsync[T any](b *Browser, expression string) (T, error) {
	return chromedp.Run(b.ctx, chromedp.Evaluate[T](expression, chromedp.EvalAwaitPromise))
}

// JSLiteral renders a Go value as a JavaScript literal.
func JSLiteral(value any) string {
	encoded, err := json.Marshal(value)
	if err != nil {
		// Only strings, numbers and bools are passed; this cannot happen.
		panic(fmt.Sprintf("encoding %v as a JavaScript literal: %v", value, err))
	}
	return string(encoded)
}

// CookieHeader is the browser's cookie jar as a Cookie header value, so a
// step can act as the signed-in user without the page.
func (b *Browser) CookieHeader() (string, error) {
	result, err := chromedp.Call(b.ctx, network.GetCookies, network.GetCookiesParams{})
	if err != nil {
		return "", err
	}
	pairs := make([]string, 0, len(result.Cookies))
	for _, cookie := range result.Cookies {
		pairs = append(pairs, cookie.Name+"="+cookie.Value)
	}
	return strings.Join(pairs, "; "), nil
}

// AdoptSession plants a session cookie for the instance at baseURL, so a
// scenario skips the UI sign-in. The cookie needs a document of that origin
// first.
func (b *Browser) AdoptSession(baseURL, token string) error {
	if err := b.Goto(baseURL + "/"); err != nil {
		return err
	}
	_, err := chromedp.Call(b.ctx, network.SetCookie, network.SetCookieParams{
		Name:   SessionCookie,
		Value:  token,
		URL:    baseURL,
		Path:   "/",
		Domain: "",
	})
	return err
}

// SessionToken is the value of the session cookie the browser holds.
func (b *Browser) SessionToken() (string, error) {
	result, err := chromedp.Call(b.ctx, network.GetCookies, network.GetCookiesParams{})
	if err != nil {
		return "", err
	}
	for _, cookie := range result.Cookies {
		if cookie.Name == SessionCookie {
			return cookie.Value, nil
		}
	}
	return "", fmt.Errorf("the browser holds no %q cookie", SessionCookie)
}

// AddInitScript runs source before the page's own scripts on every later
// document.
func (b *Browser) AddInitScript(source string) error {
	_, err := chromedp.Call(b.ctx, page.AddScriptToEvaluateOnNewDocument, page.AddScriptToEvaluateOnNewDocumentParams{Source: source})
	return err
}
