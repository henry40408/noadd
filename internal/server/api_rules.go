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

// addRule handles POST /api/rules. The parse decides allow or block and is the
// validation; an existing rule is a no-op 200 with id 0.
func (a *api) addRule(w http.ResponseWriter, r *http.Request, _ authedUser) {
	var body addRuleRequest
	if !decodeJSON(w, r, &body) {
		return
	}
	if body.Rule == nil {
		missingField(w, "rule")
		return
	}
	rule := strings.TrimSpace(*body.Rule)
	parsed, ok := filter.ParseLine(rule)
	if !ok {
		writeStatus(w, http.StatusBadRequest)
		return
	}
	ruleType := "block"
	if parsed.Action == filter.ActionAllow {
		ruleType = "allow"
	}
	ctx := writeCtx(r)
	exists, err := a.DB.HasCustomRule(ctx, rule)
	if err != nil {
		writeStatus(w, http.StatusInternalServerError)
		return
	}
	if exists {
		writeJSON(w, http.StatusOK, addRuleResponse{ID: 0})
		return
	}
	id, err := a.DB.AddCustomRule(ctx, rule, ruleType)
	if err != nil {
		writeStatus(w, http.StatusInternalServerError)
		return
	}
	a.triggerRebuild(r)
	writeJSON(w, http.StatusCreated, addRuleResponse{ID: id})
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
