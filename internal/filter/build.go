package filter

import (
	"context"
	"log/slog"
	"runtime/debug"
	"sync"
	"time"
)

// customListName is the synthetic list that custom block rules belong to.
const customListName = "Custom"

type parsedList struct {
	meta  ListMeta
	rules []ParsedRule
}

// Rebuild builds a new engine from every enabled list plus the custom rules
// and publishes it. On error the previous engine stays in place.
func (m *Manager) Rebuild(ctx context.Context) error {
	start := time.Now()
	slog.Info("rebuilding filter engine", "event", "filter.rebuild_started")

	payloads, err := m.loadEnabledLists(ctx)
	if err != nil {
		return err
	}
	customBlock, err := m.customRules(ctx, "block")
	if err != nil {
		return err
	}
	customAllow, err := m.customRules(ctx, "allow")
	if err != nil {
		return err
	}

	parseStart := time.Now()
	parsed := parseListsConcurrently(payloads)
	parseMs := time.Since(parseStart).Milliseconds()

	input, blockCount, allowCount := assembleInput(parsed, customBlock, customAllow)
	m.Holder.Swap(New(input))

	// Return the build's transient memory to the OS now, not at the next GC.
	debug.FreeOSMemory()

	slog.Info("filter engine rebuilt", "event", "filter.rebuild_completed",
		"block_count", blockCount, "allow_count", allowCount,
		"parse_ms", parseMs, "elapsed_ms", time.Since(start).Milliseconds())
	return nil
}

type listPayload struct {
	meta    ListMeta
	content string
}

// loadEnabledLists reads the stored body of each enabled list, in list order.
func (m *Manager) loadEnabledLists(ctx context.Context) ([]listPayload, error) {
	lists, err := m.DB.GetFilterLists(ctx)
	if err != nil {
		return nil, err
	}
	var payloads []listPayload
	for _, list := range lists {
		if !list.Enabled {
			continue
		}
		content, found, err := m.DB.GetFilterListContent(ctx, list.ID)
		if err != nil {
			return nil, err
		}
		if found {
			payloads = append(payloads, listPayload{meta: ListMeta{Name: list.Name, ID: list.ID}, content: content})
		}
	}
	return payloads, nil
}

func (m *Manager) customRules(ctx context.Context, ruleType string) ([]string, error) {
	rows, err := m.DB.GetCustomRulesByType(ctx, ruleType)
	if err != nil {
		return nil, err
	}
	rules := make([]string, len(rows))
	for i, row := range rows {
		rules[i] = row.Rule
	}
	return rules, nil
}

// parseListsConcurrently parses one list per goroutine and keeps list order.
func parseListsConcurrently(payloads []listPayload) []parsedList {
	parsed := make([]parsedList, len(payloads))
	var wg sync.WaitGroup
	for i, payload := range payloads {
		wg.Go(func() {
			parsed[i] = parsedList{meta: payload.meta, rules: ParseList(payload.content)}
		})
	}
	wg.Wait()
	return parsed
}

// assembleInput interns the lists that contribute block rules and appends the
// custom rules. Allow rules from every list are global.
func assembleInput(parsed []parsedList, customBlock, customAllow []string) (EngineInput, int, int) {
	var input EngineInput
	for _, list := range parsed {
		listIdx := uint16(len(input.Lists))
		used := false
		for _, rule := range list.rules {
			if rule.Action == ActionAllow {
				input.Allow = append(input.Allow, rule)
				continue
			}
			input.Block = append(input.Block, BlockRule{Rule: rule, ListIdx: listIdx})
			used = true
		}
		if used {
			input.Lists = append(input.Lists, list.meta)
		}
	}

	customIdx := -1
	for _, text := range customBlock {
		rule, ok := ParseLine(text)
		if !ok {
			continue
		}
		if customIdx < 0 {
			customIdx = len(input.Lists)
			input.Lists = append(input.Lists, ListMeta{Name: customListName, ID: CustomListID})
		}
		input.Block = append(input.Block, BlockRule{Rule: rule, ListIdx: uint16(customIdx)})
	}
	for _, text := range customAllow {
		if rule, ok := ParseLine(text); ok {
			input.Allow = append(input.Allow, rule)
		}
	}
	return input, len(input.Block), len(input.Allow)
}
