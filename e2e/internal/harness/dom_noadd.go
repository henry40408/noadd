package harness

// ExpectClass waits for the first element a selector matches to carry a class.
func (b *Browser) ExpectClass(selector, class string) error {
	return Eventually("`"+selector+"` has class "+class, func() (bool, error) {
		return Eval[bool](b, "!!document.querySelector("+JSLiteral(selector)+")?.classList.contains("+JSLiteral(class)+")")
	})
}

// IsCheckedCSS reports whether the checkbox a selector picks out is ticked.
func (b *Browser) IsCheckedCSS(selector string) (bool, error) {
	element, err := b.Optional(selector)
	if err != nil {
		return false, err
	}
	if element == nil {
		return false, nil
	}
	return callOn[bool](element, "function() { return this.checked; }")
}

// ExpectCheckedCSS waits for the checkbox to be in the wanted state.
func (b *Browser) ExpectCheckedCSS(selector string, want bool) error {
	return EventuallyEq("`"+selector+"` checked", want, func() (bool, error) {
		return b.IsCheckedCSS(selector)
	})
}

// ExpectVisibleWithText waits for a displayed element matching the selector
// whose text contains text.
func (b *Browser) ExpectVisibleWithText(selector, text string) error {
	_, err := b.displayedWithText(selector, text)
	return err
}

func (b *Browser) displayedWithText(selector, text string) (*Element, error) {
	var found *Element
	err := Eventually("a displayed `"+selector+"` containing "+JSLiteral(text), func() (bool, error) {
		element, err := b.WithTextContaining(selector, text)
		if err != nil || element == nil {
			return false, err
		}
		shown, err := element.Displayed()
		found = element
		return shown, err
	})
	return found, err
}

// ClickWithinTextRow clicks the control matching inner inside the first
// element matching outer whose text contains text.
func (b *Browser) ClickWithinTextRow(outer, text, inner string) error {
	row, err := b.displayedWithText(outer, text)
	if err != nil {
		return err
	}
	control, err := row.Find(inner)
	if err != nil {
		return err
	}
	return control.Click()
}

// ExpectNoneWithText waits until no element matching the selector contains text.
func (b *Browser) ExpectNoneWithText(selector, text string) error {
	return Eventually("no `"+selector+"` contains "+JSLiteral(text), func() (bool, error) {
		element, err := b.WithTextContaining(selector, text)
		return element == nil, err
	})
}

// ExpectPathSuffix waits for the current URL's path to end with suffix.
func (b *Browser) ExpectPathSuffix(suffix string) error {
	return Eventually("the URL to end with "+suffix, func() (bool, error) {
		current, err := b.URL()
		if err != nil {
			return false, err
		}
		return len(current.Path) >= len(suffix) && current.Path[len(current.Path)-len(suffix):] == suffix, nil
	})
}
