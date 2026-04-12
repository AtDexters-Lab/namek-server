package auth

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

// SetupDiscoverCORS is a narrowly-scoped CORS middleware for the /api/v1/setup/discover
// endpoint. It echoes Origin back only when it matches the operator-configured allowlist
// and short-circuits preflight OPTIONS with 204 BEFORE the downstream rate limiter runs,
// so preflight does not consume rate-limit budget.
//
// This is hand-rolled rather than pulling gin-contrib/cors because discover is currently
// the only cross-origin endpoint in the service — one use does not justify a new dep.
func SetupDiscoverCORS(allowed []string) gin.HandlerFunc {
	set := make(map[string]struct{}, len(allowed))
	for _, o := range allowed {
		set[o] = struct{}{}
	}
	return func(c *gin.Context) {
		// Vary: Origin is emitted unconditionally so any future shared cache correctly
		// varies responses by origin, even for requests whose Origin is not in the allowlist.
		c.Header("Vary", "Origin")
		origin := c.GetHeader("Origin")
		if _, ok := set[origin]; ok {
			c.Header("Access-Control-Allow-Origin", origin)
			c.Header("Access-Control-Allow-Methods", "GET, OPTIONS")
			c.Header("Access-Control-Allow-Headers", "Content-Type")
			c.Header("Access-Control-Max-Age", "3600")
		}
		if c.Request.Method == http.MethodOptions {
			c.AbortWithStatus(http.StatusNoContent)
			return
		}
		c.Next()
	}
}
