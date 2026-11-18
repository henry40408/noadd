package server

import (
	"errors"
	"net/http"
	"net/url"
	"strconv"

	"github.com/henry40408/noadd/internal/db"
)

// queryParams reads a query string the way axum's Query extractor does: one
// 400 with the first bad field named. Unknown keys are ignored here; the
// stats/v2 routes use rejectUnknownParams.
type queryParams struct {
	values url.Values
	err    error
}

func newQueryParams(r *http.Request) *queryParams {
	return &queryParams{values: r.URL.Query()}
}

func (q *queryParams) fail(name, reason string) {
	if q.err == nil {
		q.err = errors.New("Failed to deserialize query string: " + name + ": " + reason)
	}
}

// optionalInt returns nil when the key is absent.
func (q *queryParams) optionalInt(name string) *int64 {
	raw, present := q.values[name]
	if !present {
		return nil
	}
	value, err := strconv.ParseInt(raw[0], 10, 64)
	if err != nil {
		q.fail(name, intErrorReason(raw[0], err))
		return nil
	}
	return &value
}

func intErrorReason(raw string, err error) string {
	switch {
	case raw == "":
		return "cannot parse integer from empty string"
	case errors.Is(err, strconv.ErrRange) && raw[0] == '-':
		return "number too small to fit in target type"
	case errors.Is(err, strconv.ErrRange):
		return "number too large to fit in target type"
	}
	return "invalid digit found in string"
}

func (q *queryParams) optionalBool(name string) *bool {
	raw, present := q.values[name]
	if !present {
		return nil
	}
	switch raw[0] {
	case "true":
		value := true
		return &value
	case "false":
		value := false
		return &value
	}
	q.fail(name, "provided string was not `true` or `false`")
	return nil
}

func (q *queryParams) optionalString(name string) *string {
	raw, present := q.values[name]
	if !present {
		return nil
	}
	return &raw[0]
}

// reject answers 400 with the first error and reports whether there was one.
func (q *queryParams) reject(w http.ResponseWriter) bool {
	if q.err == nil {
		return false
	}
	writeText(w, http.StatusBadRequest, q.err.Error())
	return true
}

type logsResponse struct {
	Logs  any   `json:"logs"`
	Total int64 `json:"total"`
}

// getLogs handles GET /api/logs.
func (a *api) getLogs(w http.ResponseWriter, r *http.Request, _ authedUser) {
	params := newQueryParams(r)
	limit, offset := params.optionalInt("limit"), params.optionalInt("offset")
	filter := db.QueryLogFilter{
		Search:    params.optionalString("search"),
		Blocked:   params.optionalBool("blocked"),
		Token:     params.optionalString("token"),
		QueryType: params.optionalString("query_type"),
	}
	if params.reject(w) {
		return
	}
	logs, err := a.DB.QueryLogs(r.Context(), filter, valueOr(limit, 100), valueOr(offset, 0))
	if err != nil {
		writeStatus(w, http.StatusInternalServerError)
		return
	}
	total, err := a.DB.CountLogs(r.Context(), filter)
	if err != nil {
		writeStatus(w, http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, logsResponse{Logs: nonNil(logs), Total: total})
}

func valueOr(value *int64, fallback int64) int64 {
	if value == nil {
		return fallback
	}
	return *value
}

// deleteLogs handles DELETE /api/logs.
func (a *api) deleteLogs(w http.ResponseWriter, r *http.Request, _ authedUser) {
	if err := a.DB.DeleteAllLogs(writeCtx(r)); err != nil {
		writeStatus(w, http.StatusInternalServerError)
		return
	}
	writeStatus(w, http.StatusOK)
}
