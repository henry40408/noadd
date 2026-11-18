package harness

import (
	"fmt"
	"strings"
)

// Locator is a lazily resolved CSS selector, optionally narrowed by text and
// index and scoped to the first match of another locator. Every expectation
// polls, so a locator names what to find and the call says what must hold.
type Locator struct {
	browser  *Browser
	css      string
	hasText  string
	index    int
	hasIndex bool
	within   *Locator
}

// Loc starts a locator over the whole page.
func (b *Browser) Loc(css string) Locator {
	return Locator{browser: b, css: css}
}

// LocTestID is Loc addressed by data-testid.
func (b *Browser) LocTestID(id string) Locator {
	return b.Loc(testIDSelector(id))
}

// HavingText narrows to the elements whose textContent contains text.
func (l Locator) HavingText(text string) Locator {
	l.hasText = text
	return l
}

// Nth narrows to the nth match, zero-based.
func (l Locator) Nth(index int) Locator {
	l.index, l.hasIndex = index, true
	return l
}

// First is Nth(0).
func (l Locator) First() Locator { return l.Nth(0) }

// Loc scopes a selector to the first match of l.
func (l Locator) Loc(css string) Locator {
	return Locator{browser: l.browser, css: css, within: &l}
}

// TestID scopes a data-testid to the first match of l.
func (l Locator) TestID(id string) Locator {
	return l.Loc(testIDSelector(id))
}

func (l Locator) String() string {
	description := l.css
	if l.within != nil {
		description += " within " + l.within.String()
	}
	if l.hasText != "" {
		description += fmt.Sprintf(" having text %q", l.hasText)
	}
	if l.hasIndex {
		description += fmt.Sprintf(" [%d]", l.index)
	}
	return description
}

// matches resolves every element the locator selects, without waiting.
func (l Locator) matches() ([]*Element, error) {
	var found []*Element
	var err error
	if l.within == nil {
		found, err = l.browser.QueryAll(l.css)
	} else {
		var scope *Element
		scope, err = l.within.get()
		if err != nil {
			return nil, nil
		}
		found, err = scope.FindAll(l.css)
	}
	if err != nil {
		return nil, err
	}
	if l.hasText != "" {
		found, err = keepContaining(found, l.hasText)
		if err != nil {
			return nil, err
		}
	}
	if !l.hasIndex {
		return found, nil
	}
	if l.index >= len(found) {
		return nil, nil
	}
	return found[l.index : l.index+1], nil
}

func keepContaining(elements []*Element, text string) ([]*Element, error) {
	var kept []*Element
	for _, element := range elements {
		content, err := element.TextContent()
		if err != nil {
			return nil, err
		}
		if strings.Contains(content, text) {
			kept = append(kept, element)
		}
	}
	return kept, nil
}

// get is the first match, or an error when there is none.
func (l Locator) get() (*Element, error) {
	found, err := l.matches()
	if err != nil {
		return nil, err
	}
	if len(found) == 0 {
		return nil, fmt.Errorf("nothing matches %s", l)
	}
	return found[0], nil
}

// Count is how many elements match now.
func (l Locator) Count() (int, error) {
	found, err := l.matches()
	return len(found), err
}

// act waits for a match, then runs action on it. A node swapped out between
// the find and the action is retried.
func (l Locator) act(what string, action func(*Element) error) error {
	return Eventually(what+" "+l.String(), func() (bool, error) {
		element, err := l.get()
		if err != nil {
			return false, err
		}
		return true, action(element)
	})
}

// read waits for a match and returns what read produces from it.
func read[T any](l Locator, read func(*Element) (T, error)) (T, error) {
	var value T
	err := Eventually("reading "+l.String(), func() (bool, error) {
		element, err := l.get()
		if err != nil {
			return false, err
		}
		value, err = read(element)
		return err == nil, err
	})
	return value, err
}

func normalise(text string) string {
	return strings.Join(strings.Fields(text), " ")
}

// Text is the first match's whitespace-normalised textContent.
func (l Locator) Text() (string, error) {
	raw, err := l.TextRaw()
	return normalise(raw), err
}

// TextRaw is the first match's textContent, untouched.
func (l Locator) TextRaw() (string, error) {
	return read(l, (*Element).TextContent)
}

// Value is the first match's value property.
func (l Locator) Value() (string, error) {
	return read(l, (*Element).Value)
}

// Attr is an attribute of the first match; nil when absent.
func (l Locator) Attr(name string) (*string, error) {
	return read(l, func(e *Element) (*string, error) {
		value, present, err := e.Attr(name)
		if err != nil || !present {
			return nil, err
		}
		return &value, nil
	})
}

// Click scrolls the first match into view and clicks it natively.
func (l Locator) Click() error { return l.act("clicking", (*Element).Click) }

// ClickJS activates the first match with a script click, skipping pointer
// hit-testing, for controls a fixed bar can cover.
func (l Locator) ClickJS() error { return l.act("script-clicking", (*Element).ClickJS) }

// Fill replaces the first match's value.
func (l Locator) Fill(value string) error {
	return l.act("filling", func(e *Element) error { return e.Fill(value) })
}

// TypeText types into the first match key by key, without clearing it.
func (l Locator) TypeText(text string) error {
	return l.act("typing into", func(e *Element) error { return e.Type(text) })
}

// PressEnter presses Enter in the first match, submitting its form as a
// keyboard user would wherever the fixed status bar has covered the button.
func (l Locator) PressEnter() error {
	return l.act("pressing Enter in", func(e *Element) error {
		if err := e.Focus(); err != nil {
			return err
		}
		return l.browser.PressFocused("Enter")
	})
}

// Blur removes focus from the first match, which commits a value on the
// settings page.
func (l Locator) Blur() error { return l.act("blurring", (*Element).Blur) }

// SelectValue picks an option by value on the first match, firing change.
func (l Locator) SelectValue(value string) error {
	return l.act("selecting in", func(e *Element) error { return selectValue(e, l.String(), value) })
}

// ViewportRect is the first match's box in viewport coordinates.
func (l Locator) ViewportRect() (Rect, error) {
	return read(l, (*Element).Box)
}

// ViewportCentre is the centre of the first match in viewport coordinates.
func (l Locator) ViewportCentre() (x, y float64, err error) {
	box, err := l.ViewportRect()
	if err != nil {
		return 0, 0, err
	}
	return box.X + box.Width/2, box.Y + box.Height/2, nil
}

// expect polls until holds reports true for the first match.
func (l Locator) expect(what string, holds func(*Element) (bool, error)) error {
	return Eventually(l.String()+" "+what, func() (bool, error) {
		element, err := l.get()
		if err != nil {
			return false, nil
		}
		return holds(element)
	})
}

// ExpectVisible waits for the first match to be displayed.
func (l Locator) ExpectVisible() error {
	return l.expect("is visible", (*Element).Displayed)
}

// ExpectHidden waits for the locator to match nothing displayed.
func (l Locator) ExpectHidden() error {
	return Eventually(l.String()+" is hidden", func() (bool, error) {
		element, err := l.get()
		if err != nil {
			return true, nil
		}
		shown, err := element.Displayed()
		return !shown, err
	})
}

// ExpectCount waits for exactly want matches.
func (l Locator) ExpectCount(want int) error {
	return EventuallyEq(l.String()+" count", want, l.Count)
}

// ExpectCountAtLeast waits for at least want matches.
func (l Locator) ExpectCountAtLeast(want int) error {
	return Eventually(fmt.Sprintf("%s matches at least %d", l, want), func() (bool, error) {
		count, err := l.Count()
		return count >= want, err
	})
}

// ExpectTextContains waits for the first match's normalised text to contain needle.
func (l Locator) ExpectTextContains(needle string) error {
	return l.expect(fmt.Sprintf("text contains %q", needle), func(e *Element) (bool, error) {
		text, err := e.NormalizedText()
		return strings.Contains(text, needle), err
	})
}

// ExpectTextExcludes fails at once when the first match's text contains needle.
func (l Locator) ExpectTextExcludes(needle string) error {
	text, err := l.Text()
	if err != nil {
		return err
	}
	if strings.Contains(text, needle) {
		return fmt.Errorf("%s should not contain %q, but reads %q", l, needle, text)
	}
	return nil
}

// ExpectTextEq waits for the first match's normalised text to equal want.
func (l Locator) ExpectTextEq(want string) error {
	return EventuallyEq(l.String()+" text", normalise(want), func() (string, error) {
		element, err := l.get()
		if err != nil {
			return "", err
		}
		return element.NormalizedText()
	})
}

// ExpectValue waits for the first match's value to equal want.
func (l Locator) ExpectValue(want string) error {
	return EventuallyEq(l.String()+" value", want, l.Value)
}

// ExpectValueStartsWith waits for the first match's value to start with prefix.
func (l Locator) ExpectValueStartsWith(prefix string) error {
	return l.expect(fmt.Sprintf("value starts with %q", prefix), func(e *Element) (bool, error) {
		value, err := e.Value()
		return strings.HasPrefix(value, prefix), err
	})
}

// ExpectValueNotEmpty waits for the first match's value to be non-empty.
func (l Locator) ExpectValueNotEmpty() error {
	return l.expect("has a value", func(e *Element) (bool, error) {
		value, err := e.Value()
		return value != "", err
	})
}

// ExpectAttr waits for an attribute to equal want.
func (l Locator) ExpectAttr(name, want string) error {
	return l.expect(fmt.Sprintf("@%s is %q", name, want), func(e *Element) (bool, error) {
		value, present, err := e.Attr(name)
		return present && value == want, err
	})
}

func (l Locator) hasClass(name string) func(*Element) (bool, error) {
	return func(e *Element) (bool, error) {
		classes, err := e.Classes()
		for _, class := range classes {
			if class == name {
				return true, err
			}
		}
		return false, err
	}
}

// ExpectClass waits for the first match to carry class name.
func (l Locator) ExpectClass(name string) error {
	return l.expect("carries class "+name, l.hasClass(name))
}

// ExpectNotClass waits for the first match to drop class name.
func (l Locator) ExpectNotClass(name string) error {
	return l.expect("drops class "+name, func(e *Element) (bool, error) {
		has, err := l.hasClass(name)(e)
		return !has, err
	})
}

// ExpectChecked waits for the first match's checked state to equal want.
func (l Locator) ExpectChecked(want bool) error {
	return l.expect(fmt.Sprintf("checked is %v", want), func(e *Element) (bool, error) {
		checked, err := callOn[bool](e, "function() { return this.checked; }")
		return checked == want, err
	})
}
