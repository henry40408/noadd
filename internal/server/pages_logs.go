package server

import (
	"net/http"
	"strconv"
	"strings"

	"github.com/henry40408/noadd/internal/db"
	"github.com/henry40408/noadd/internal/stats"
	"github.com/henry40408/noadd/internal/views"
)

// logsPageSize is rows per page of the log; matches app.js's limit.
const logsPageSize int64 = 50

// logQueryTypes are the record types the log's filter offers: a fixed list,
// not the ones present in the log, so a type is never mysteriously missing.
var logQueryTypes = []string{"A", "AAAA", "CNAME", "MX", "TXT", "NS", "SOA", "PTR", "SRV", "CAA", "HTTPS"}

func optionalFilter(value string) *string {
	if value == "" {
		return nil
	}
	return &value
}

func appliedLogFilters(r *http.Request) logsFilters {
	query := r.URL.Query()
	return logsFilters{
		q:         strings.TrimSpace(query.Get("q")),
		action:    strings.TrimSpace(query.Get("action")),
		queryType: strings.TrimSpace(query.Get("type")),
		token:     strings.TrimSpace(query.Get("token")),
	}
}

// logFilterFor maps the applied filters onto the database's.
func logFilterFor(filters logsFilters) db.QueryLogFilter {
	filter := db.QueryLogFilter{
		Search:    optionalFilter(filters.q),
		Token:     optionalFilter(filters.token),
		QueryType: optionalFilter(filters.queryType),
	}
	switch filters.action {
	case "blocked":
		blocked := true
		filter.Blocked = &blocked
	case "allowed":
		blocked := false
		filter.Blocked = &blocked
	}
	return filter
}

func (a *api) logRows(entries []db.QueryLogEntry, now int64) []views.LogRow {
	rows := make([]views.LogRow, 0, len(entries))
	for _, entry := range entries {
		row := views.LogRow{
			// The column is milliseconds; timeAgo counts seconds.
			TimeText:    timeAgo(entry.Timestamp/1000, now),
			TimestampMS: entry.Timestamp,
			Blocked:     entry.Blocked,
			Domain:      entry.Domain,
			DNSSEC:      entry.AuthenticatedData,
			QueryType:   entry.QueryType,
			ClientIP:    entry.ClientIP,
			Cached:      entry.Cached,
			ResponseMS:  entry.ResponseMs,
			// The one-click action is the opposite of the verdict.
			ActionRule:  "||" + entry.Domain + "^",
			ActionLabel: "Block",
		}
		if entry.Blocked {
			row.ActionRule, row.ActionLabel = "@@||"+entry.Domain+"^", "Allow"
		}
		row.Result = deref(entry.Result)
		row.DoHToken = deref(entry.DohToken)
		row.Upstream = deref(entry.Upstream)
		rows = append(rows, row)
	}
	return rows
}

func deref(value *string) string {
	if value == nil {
		return ""
	}
	return *value
}

// logsPage handles GET /logs. A failed read renders an empty table.
func (a *api) logsPage(w http.ResponseWriter, r *http.Request, _ authedUser) {
	ctx := r.Context()
	shell := a.shell(w, r)
	filters := appliedLogFilters(r)
	page, err := strconv.ParseInt(r.URL.Query().Get("page"), 10, 64)
	if err != nil {
		page = 1
	}
	page = max(page, 1)
	now := a.Now().Unix()

	filter := logFilterFor(filters)
	entries, _ := a.DB.QueryLogs(ctx, filter, logsPageSize, (page-1)*logsPageSize)
	total, _ := a.DB.CountLogs(ctx, filter)

	var tokens []views.LogOption
	tokenRows, _ := a.DB.GetDohTokens(ctx)
	for _, token := range tokenRows {
		tokens = append(tokens, views.LogOption{Value: token.Token, Selected: token.Token == filters.token})
	}
	var queryTypes []views.LogOption
	for _, queryType := range logQueryTypes {
		queryTypes = append(queryTypes, views.LogOption{Value: queryType, Selected: filters.queryType == queryType})
	}

	totalPages := max((total+logsPageSize-1)/logsPageSize, 1)
	hrefFor := func(page int64) string { return logsHref(logsQueryString(filters, page)) }

	writeHTML(w, http.StatusOK, views.Logs(views.LogsPage{
		Shell:             shell,
		Rows:              a.logRows(entries, now),
		Tokens:            tokens,
		QueryTypes:        queryTypes,
		DomainSuggestions: stats.DomainSuggestions(ctx, a.DB, now),
		Q:                 filters.q,
		Action:            filters.action,
		QueryType:         filters.queryType,
		Token:             filters.token,
		Page:              page,
		TotalPages:        totalPages,
		Total:             thousands(total),
		HasPrev:           page > 1,
		HasNext:           page < totalPages,
		PrevHref:          hrefFor(page - 1),
		NextHref:          hrefFor(page + 1),
		CurrentHref:       hrefFor(page),
		Filtered:          filters != logsFilters{},
	}))
}

// logsRuleSubmit handles POST /logs/rules: the one-click Allow/Block on a row,
// through the same createCustomRule as POST /api/rules and the filters page.
func (a *api) logsRuleSubmit(w http.ResponseWriter, r *http.Request, _ authedUser) {
	form, ok := parseForm(w, r)
	if !ok || !requireFields(w, form, "rule") {
		return
	}
	_, _ = a.createCustomRule(r, form.Get("rule"))
	setFlash(w, flashFiltersSaved)
	redirectSeeOther(w, r, nextOr(form.Get("next"), "/logs"))
}

// logsClearSubmit handles POST /logs/clear. It always answers on the
// unfiltered first page: a filtered view would read "No logs found", as if the
// filter broke.
func (a *api) logsClearSubmit(w http.ResponseWriter, r *http.Request, _ authedUser) {
	_ = a.DB.DeleteAllLogs(writeCtx(r))
	setFlash(w, flashLogsCleared)
	redirectSeeOther(w, r, "/logs")
}
