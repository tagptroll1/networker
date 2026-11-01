//go:build headless

// Package frontend without the dashboard, for builds that skip the Node toolchain.
package frontend

import "net/http"

const Available = false

func Handler() http.Handler { return http.NotFoundHandler() }
