package server

import (
	_ "embed"
	"net/http"
)

// openAPIJSON and docsHTML are the Rust build's output, byte for byte: the
// OpenAPI document and the Scalar page that embeds it.
//
//go:embed openapi.json
var openAPIJSON []byte

//go:embed docs.html
var docsHTML []byte

// getOpenAPI handles GET /api/openapi.json. It needs an operator: the document
// holds no data, but pre-auth recon of the API surface is still denied.
func (a *api) getOpenAPI(w http.ResponseWriter, _ *http.Request, _ authedUser) {
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(openAPIJSON)
}

// getDocs handles GET /api/docs, the Scalar API reference.
func (a *api) getDocs(w http.ResponseWriter, _ *http.Request, _ authedUser) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write(docsHTML)
}
