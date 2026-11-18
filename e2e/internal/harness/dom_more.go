package harness

import (
	"fmt"
	"strings"
)

// ConfirmAndSubmit clicks a control that asks confirm() first, accepts the
// prompt, and waits for the page it submits to. Without scripts there is no
// prompt; see the @nojs scenarios.
func (b *Browser) ConfirmAndSubmit(id string) error {
	b.SetDialogPolicy(AcceptDialogs)
	defer b.SetDialogPolicy(DismissDialogs)
	return b.Submit(id)
}

// ExpectExactTextSomewhere waits for some displayed, innermost element whose
// whitespace-normalised text is exactly text.
func (b *Browser) ExpectExactTextSomewhere(text string) error {
	return Eventually("the page to show exactly "+JSLiteral(text), func() (bool, error) {
		return Eval[bool](b, `(() => {
			const needle = `+JSLiteral(text)+`;
			const norm = (e) => e.textContent.replace(/\s+/g, " ").trim();
			return [...document.querySelectorAll("*")].some((e) =>
				norm(e) === needle
				&& ![...e.children].some((c) => norm(c) === needle)
				&& e.checkVisibility({ opacityProperty: true, visibilityProperty: true }));
		})()`)
	})
}

// RowTextContainingTestID is the normalised text of the table row that holds
// the element with the data-testid.
func (b *Browser) RowTextContainingTestID(id string) (string, error) {
	element, err := b.TestID(id)
	if err != nil {
		return "", err
	}
	text, err := callOn[*string](element, `function() {
		const row = this.closest('tr');
		return row && row.textContent.replace(/\s+/g, ' ').trim();
	}`)
	if err != nil {
		return "", err
	}
	if text == nil {
		return "", fmt.Errorf("`%s` is not inside a table row", id)
	}
	return *text, nil
}

// ExpectExactText waits for the element's normalised text to equal text.
func (b *Browser) ExpectExactText(id, text string) error {
	return EventuallyEq("testid `"+id+"` text", text, func() (string, error) { return b.TextOf(id) })
}

// ExpectNotExactText waits for the element to stop reading exactly text; an
// absent element counts.
func (b *Browser) ExpectNotExactText(id, text string) error {
	return Eventually("testid `"+id+"` stops reading "+JSLiteral(text), func() (bool, error) {
		current, err := b.TextOfTestID(id)
		return current == nil || *current != text, err
	})
}

// ExpectVisibleCSS waits for a displayed match of the selector.
func (b *Browser) ExpectVisibleCSS(selector string) error {
	_, err := b.CSS(selector)
	return err
}

// ExpectHiddenCSS waits for the selector to match nothing displayed.
func (b *Browser) ExpectHiddenCSS(selector string) error {
	return Eventually("`"+selector+"` is hidden", func() (bool, error) {
		element, err := b.Optional(selector)
		if err != nil || element == nil {
			return element == nil, err
		}
		shown, err := element.Displayed()
		return !shown, err
	})
}

// ExpectExactTextCSS waits for the match's normalised text to equal text.
func (b *Browser) ExpectExactTextCSS(selector, text string) error {
	return EventuallyEq("`"+selector+"` text", text, func() (string, error) {
		current, err := b.TextOfCSS(selector)
		if current == nil {
			return "", err
		}
		return *current, err
	})
}

// ExpectTextCSS waits for the match's normalised text to contain needle.
func (b *Browser) ExpectTextCSS(selector, needle string) error {
	return Eventually(fmt.Sprintf("`%s` text contains %q", selector, needle), func() (bool, error) {
		current, err := b.TextOfCSS(selector)
		return current != nil && strings.Contains(*current, needle), err
	})
}

// ExpectValue waits for a form control's value.
func (b *Browser) ExpectValue(id, value string) error {
	return EventuallyEq("testid `"+id+"` value", value, func() (string, error) { return b.ValueOf(id) })
}

// ValueOfCSS is the value of the displayed form control a selector picks out.
func (b *Browser) ValueOfCSS(selector string) (string, error) {
	element, err := b.CSS(selector)
	if err != nil {
		return "", err
	}
	return element.Value()
}

// ExpectValueCSS waits for the value of the control a selector picks out.
func (b *Browser) ExpectValueCSS(selector, value string) error {
	return EventuallyEq("`"+selector+"` value", value, func() (string, error) { return b.ValueOfCSS(selector) })
}

// CountCSS is how many elements match the selector right now.
func (b *Browser) CountCSS(selector string) (int, error) {
	return Eval[int](b, "document.querySelectorAll("+JSLiteral(selector)+").length")
}

// ExpectCount waits for exactly expected matches.
func (b *Browser) ExpectCount(selector string, expected int) error {
	return EventuallyEq("`"+selector+"` count", expected, func() (int, error) { return b.CountCSS(selector) })
}

// SelectOptionCSS chooses an option by value in the select a selector picks
// out, and fires the change event.
func (b *Browser) SelectOptionCSS(selector, value string) error {
	element, err := b.CSS(selector)
	if err != nil {
		return err
	}
	return selectValue(element, selector, value)
}

func selectValue(element *Element, what, value string) error {
	found, err := callOn[bool](element, `function(value) {
		const option = [...this.options].find((o) => o.value === value);
		if (!option) { return false; }
		this.value = value;
		this.dispatchEvent(new Event('input', { bubbles: true }));
		this.dispatchEvent(new Event('change', { bubbles: true }));
		return true;
	}`, value)
	if err != nil {
		return err
	}
	if !found {
		return fmt.Errorf("`%s` has no option with value `%s`", what, value)
	}
	return nil
}

// LinkExact is the displayed link whose normalised text is exactly name, or
// nil. Per-row lowercase links would win a case-insensitive match.
func (b *Browser) LinkExact(name string) (*Element, error) {
	object, err := objectFrom(b, nil, `function(name) {
		return [...document.querySelectorAll('a')].find(
			(a) => a.textContent.replace(/\s+/g, ' ').trim() === name) ?? null;
	}`, name)
	if err != nil {
		return nil, err
	}
	return wrap(b, object, "link "+JSLiteral(name)), nil
}

// ExpectAttrIs is ExpectAttr for a present attribute.
func (b *Browser) ExpectAttrIs(selector, attr, expected string) error {
	return b.ExpectAttr(selector, attr, &expected)
}
