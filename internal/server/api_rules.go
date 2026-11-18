package server

import (
	"net/http"
	"strings"

	"github.com/henry40408/noadd/internal/filter"
)

// getRules handles GET /api/rules.
func (a *api) getRules(w http.ResponseWriter, r *http.Request, _ authedUser) {
	rules, err := a.DB.GetAllCustomRules(r.Context())
	if err != nil {
		writeStatus(w, http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, nonNil(rules))
}

type addRuleRequest struct {
	Rule *string `json:"rule"`
}

type addRuleResponse struct {
	ID int64 `json:"id"`
}

// ruleFailure is why a custom rule could not be added.
type ruleFailure int

const (
	// ruleUnparseable: the text is not a rule in any supported syntax.
	ruleUnparseable ruleFailure = iota + 1
	ruleInternal
)

// createCustomRule adds a custom rule and returns its id, or 0 when the exact
// text already exists. The parse decides allow or block and is the validation,
// shared by POST /api/rules and the pages' forms.
func (a *api) createCustomRule(r *http.Request, raw string) (id int64, failure ruleFailure) {
	rule := strings.TrimSpace(raw)
	parsed, ok := filter.ParseLine(rule)
	if !ok {
		return 0, ruleUnparseable
	}
	ruleType := "block"
	if parsed.Action == filter.ActionAllow {
		ruleType = "allow"
	}
	ctx := writeCtx(r)
	exists, err := a.DB.HasCustomRule(ctx, rule)
	if err != nil {
		return 0, ruleInternal
	}
	if exists {
		return 0, 0
	}
	id, err = a.DB.AddCustomRule(ctx, rule, ruleType)
	if err != nil {
		return 0, ruleInternal
	}
	a.triggerRebuild(r)
	return id, 0
}

// addRule handles POST /api/rules: an existing rule is a no-op 200 with id 0.
func (a *api) addRule(w http.ResponseWriter, r *http.Request, _ authedUser) {
	var body addRuleRequest
	if !decodeJSON(w, r, &body) {
		return
	}
	if body.Rule == nil {
		missingField(w, "rule")
		return
	}
	id, failure := a.createCustomRule(r, *body.Rule)
	switch {
	case failure == ruleUnparseable:
		writeStatus(w, http.StatusBadRequest)
	case failure != 0:
		writeStatus(w, http.StatusInternalServerError)
	case id == 0:
		writeJSON(w, http.StatusOK, addRuleResponse{ID: 0})
	default:
		writeJSON(w, http.StatusCreated, addRuleResponse{ID: id})
	}
}

// deleteRule handles DELETE /api/rules/{id}.
func (a *api) deleteRule(w http.ResponseWriter, r *http.Request, _ authedUser) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	if err := a.DB.DeleteCustomRule(writeCtx(r), id); err != nil {
		writeStatus(w, http.StatusInternalServerError)
		return
	}
	a.triggerRebuild(r)
	writeStatus(w, http.StatusOK)
}
