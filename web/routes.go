// This file is part of the happyDeliver (R) project.
// Copyright (c) 2025 happyDomain
// Authors: Pierre-Olivier Mercier, et al.
//
// This program is offered under a commercial and under the AGPL license.
// For commercial licensing, contact us at <contact@happydomain.org>.
//
// For AGPL licensing:
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.

package web

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"log"
	"net/http"
	"net/url"
	"os"
	"path"
	"strings"
	"text/template"

	"github.com/gin-gonic/gin"

	"git.happydns.org/happyDeliver/internal/config"
)

var (
	indexTpl       *template.Template
	CustomBodyHTML = ""
	CustomHeadHTML = ""
)

// staleReloadJS is served (with a 200) in place of a 404 when a client requests
// a content-hashed bundle under /_app/immutable/ that no longer exists. The
// usual cause is a browser running a *stale, cached* index.html after a deploy:
// the old bundle hashes are gone, so the SPA's bootstrapping import() would
// normally 404 and the app would never mount (visible but frozen).
//
// Because the browser evaluates this as the very module it was trying to import,
// returning a tiny self-healing script here lets already-stuck clients recover on
// their own: it forces a cache-busting reload so the browser fetches the current
// index.html (which points at bundles that actually exist). bootCleanupScript
// then strips the cache-buster from the address bar once a page loads.
//
// Retries are bounded, which matters for two failure modes the naive "reload
// until it works" version handled badly:
//   - A staggered multi-replica deploy can serve a fresh index.html from one
//     replica and 404 the bundle from an old one; a single reload then freezes.
//     Allowing a few attempts lets the replicas converge.
//   - A genuinely missing bundle (a broken/partial deploy, NOT a stale client)
//     would otherwise reload forever. Capping the attempts makes it give up and
//     fail loud instead. The server also logs each self-heal it serves, so a
//     broken deploy stays visible in monitoring despite the 200.
//
// The counter is keyed on the first attempt of an episode and expires after
// WINDOW, so a later manual reload starts a fresh budget.
//
// Two things make this robust against "kit.start is not a function":
//  1. The reload is issued SYNCHRONOUSLY during evaluation, so navigation is
//     committed before SvelteKit's bootstrap `.then(([kit]) => kit.start(...))`
//     microtask can run against this (non-)module.
//  2. We THROW at the end of evaluation, so the failing `import()` rejects
//     instead of resolving to this module. Promise.all rejects, the bootstrap
//     `.then` is skipped, and kit.start is never reached. When no reload is
//     issued (budget spent, or storage unavailable and no URL support) this
//     surfaces as a clean import rejection rather than a confusing TypeError.
//
// The fallback path never does an unguarded, non-cache-busting reload: a unique
// `_fresh` query defeats an intermediary cache that ignores no-cache and is
// self-limiting even when the attempt counter cannot be persisted (e.g. storage
// blocked), so it cannot spin into an unbounded loop.
//
// Note: there is no service worker, so the Cache Storage API is never populated;
// we deliberately do not touch `caches` (doing so only pushed the reload into an
// async microtask chain that lost the race against kit.start).
const staleReloadJS = `(function () {
  var KEY = '__hd_stale_reload__';
  var MAX = 3;
  var WINDOW = 30000;
  var now = Date.now();

  var attempts = 0, since = now, persisted = false;
  try {
    var st = JSON.parse(sessionStorage.getItem(KEY) || 'null');
    if (st && typeof st.n === 'number' && typeof st.t === 'number' && now - st.t <= WINDOW) {
      attempts = st.n;
      since = st.t;
    }
  } catch (e) {}

  if (attempts < MAX) {
    try {
      sessionStorage.setItem(KEY, JSON.stringify({ n: attempts + 1, t: since }));
      persisted = true;
    } catch (e) {}

    var target = null;
    try {
      var u = new URL(window.location.href);
      u.searchParams.set('_fresh', String(now));
      target = u.toString();
    } catch (e) {}

    if (target) {
      window.location.replace(target);
    } else if (persisted) {
      window.location.reload();
    }
    // Neither a cache-buster nor a persisted guard: do nothing and let the
    // import() reject below rather than risk an unbounded reload loop.
  }
})();
throw new Error('happyDeliver: stale bundle, reloading');
`

// staleReloadJSBytes is the precomputed response body for the stale-bundle path.
var staleReloadJSBytes = []byte(staleReloadJS)

// bootCleanupScript is injected into the served index.html. When a stale client
// self-heals it reloads with a `_fresh` cache-buster in the URL (see
// staleReloadJS); this strips that param from the address bar as the page loads,
// before SvelteKit reads the URL for routing, so it is not left behind after a
// successful recovery (nor carried into a shared or bookmarked link).
const bootCleanupScript = `<script>
(function () {
  try {
    var u = new URL(window.location.href);
    if (u.searchParams.has('_fresh')) {
      u.searchParams.delete('_fresh');
      window.history.replaceState(window.history.state, '', u.pathname + u.search + u.hash);
    }
  } catch (e) {}
})();
</script>`

// buildIndexTemplate turns the raw index.html into the served template: it
// injects the boot cleanup script and the og:url meta right before </head> and
// the custom Body right before </body>. Both the embedded and dev-proxy paths
// build the template through here so the injection stays identical.
func buildIndexTemplate(raw []byte) *template.Template {
	v := strings.Replace(
		strings.Replace(string(raw),
			"</head>", bootCleanupScript+`{{ .Head }}<meta property="og:url" content="{{ .RootURL }}"></head>`, 1),
		"</body>", "{{ .Body }}</body>", 1)
	return template.Must(template.New("index.html").Parse(v))
}

func init() {
	flag.StringVar(&CustomHeadHTML, "custom-head-html", CustomHeadHTML, "Add custom HTML right before </head>")
	flag.StringVar(&CustomBodyHTML, "custom-body-html", CustomBodyHTML, "Add custom HTML right before </body>")
}

// immutableAssetPrefix is the URL prefix under which SvelteKit emits its
// content-hashed bundles. Both the cache policy (these may be cached hard) and
// the stale-bundle self-heal (a 404 here means a stale cached client) key off
// it, so they share this constant to stay in sync.
const immutableAssetPrefix = "/_app/immutable/"

// Cache-Control policies for the responses this server returns. There are three
// distinct classes of asset:
const (
	// cacheImmutable applies to content-hashed bundles under
	// immutableAssetPrefix: their URL changes whenever their content does, so a
	// given URL never changes and may be cached forever.
	cacheImmutable = "public, max-age=604800, immutable"
	// cacheStatic applies to embedded assets that are NOT content-hashed
	// (e.g. /img/*, /favicon.png). Their URL is stable across deploys, so they
	// are cacheable, but only briefly so an in-place change propagates within
	// the hour. They cannot be served no-cache cheaply: embed.FS files carry a
	// zero modtime, so http.ServeContent emits no Last-Modified and can never
	// answer a conditional request with 304: no-cache would force a full
	// re-download of every such asset on every page load.
	cacheStatic = "public, max-age=3600"
	// cacheNone applies to page HTML and to misses. The HTML references
	// content-hashed bundles whose hashes change on every deploy; a browser
	// reusing a *cached* page would then request hashes that 404, render but
	// never mount the SPA (visible but frozen). Revalidating guarantees clients
	// always load a page pointing at bundles that actually exist.
	cacheNone = "no-cache"
)

// setCacheControl sets the response cache policy for a served asset.
func setCacheControl(c *gin.Context, policy string) {
	c.Writer.Header().Set("Cache-Control", policy)
}

// isScriptAsset reports whether path is a JavaScript module SvelteKit's
// bootstrap loads via import(). Only such requests benefit from the stale-bundle
// self-heal: the reload module is evaluated as the failing import, so it must be
// JS. Both .js and .mjs are recognised so the self-heal survives a change in the
// bundler's module extension.
func isScriptAsset(path string) bool {
	return strings.HasSuffix(path, ".js") || strings.HasSuffix(path, ".mjs")
}

// applyAssetCacheControl sets the cache policy for a successfully served asset
// from its request path: content-hashed bundles are cached hard, while every
// other embedded static asset gets a short cacheable TTL. This keeps the cache
// decision in one place rather than split between route registration and the
// file handler.
func applyAssetCacheControl(c *gin.Context) {
	if strings.HasPrefix(c.Request.URL.Path, immutableAssetPrefix) {
		setCacheControl(c, cacheImmutable)
	} else {
		setCacheControl(c, cacheStatic)
	}
}

func DeclareRoutes(cfg *config.Config, router *gin.Engine) {
	appConfig := map[string]interface{}{}

	if cfg.ReportRetention > 0 {
		appConfig["report_retention"] = cfg.ReportRetention
	}

	if cfg.SurveyURL.Host != "" {
		appConfig["survey_url"] = cfg.SurveyURL.String()
	}

	if len(cfg.Analysis.RBLs) > 0 {
		appConfig["rbls"] = cfg.Analysis.RBLs
	}

	if cfg.CustomLogoURL != "" {
		appConfig["custom_logo_url"] = cfg.CustomLogoURL
	}

	if !cfg.DisableTestList {
		appConfig["test_list_enabled"] = true
	}

	if appcfg, err := json.MarshalIndent(appConfig, "", "  "); err != nil {
		log.Println("Unable to generate JSON config to inject in web application")
	} else {
		CustomHeadHTML += `<script id="app-config" type="application/json">` + string(appcfg) + `</script>`
	}

	if cfg.DevProxy != "" {
		router.GET("/.svelte-kit/*_", serveOrReverse("", cfg))
		router.GET("/node_modules/*_", serveOrReverse("", cfg))
		router.GET("/@vite/*_", serveOrReverse("", cfg))
		router.GET("/@id/*_", serveOrReverse("", cfg))
		router.GET("/@fs/*_", serveOrReverse("", cfg))
		router.GET("/src/*_", serveOrReverse("", cfg))
		router.GET("/home/*_", serveOrReverse("", cfg))
	}
	router.GET("/_app/", serveOrReverse("", cfg))
	router.GET(immutableAssetPrefix+"*_", serveOrReverse("", cfg))

	router.GET("/", serveOrReverse("/", cfg))
	router.GET("/blacklist/", serveOrReverse("/", cfg))
	router.GET("/blacklist/:ip", serveOrReverse("/", cfg))
	router.GET("/domain/", serveOrReverse("/", cfg))
	router.GET("/domain/:domain", serveOrReverse("/", cfg))
	router.GET("/test/", serveOrReverse("/", cfg))
	router.GET("/test/:testid", serveOrReverse("/", cfg))
	router.GET("/history/", serveOrReverse("/", cfg))
	router.GET("/favicon.png", serveOrReverse("", cfg))
	router.GET("/img/*path", serveOrReverse("", cfg))

	router.NoRoute(func(c *gin.Context) {
		if strings.HasPrefix(c.Request.URL.Path, "/api") || strings.Contains(c.Request.Header.Get("Accept"), "application/json") {
			c.JSON(404, gin.H{"code": "PAGE_NOT_FOUND", "errmsg": "Page not found"})
		} else {
			serveOrReverse("/", cfg)(c)
		}
	})
}

func serveOrReverse(forced_url string, cfg *config.Config) gin.HandlerFunc {
	if cfg.DevProxy != "" {
		// Forward to the Svelte dev proxy
		return func(c *gin.Context) {
			if u, err := url.Parse(cfg.DevProxy); err != nil {
				http.Error(c.Writer, err.Error(), http.StatusInternalServerError)
			} else {
				if forced_url != "" && forced_url != "/" {
					u.Path = path.Join(u.Path, forced_url)
				} else {
					u.Path = path.Join(u.Path, c.Request.URL.Path)
				}

				u.RawQuery = c.Request.URL.RawQuery

				if r, err := http.NewRequest(c.Request.Method, u.String(), c.Request.Body); err != nil {
					http.Error(c.Writer, err.Error(), http.StatusInternalServerError)
				} else if resp, err := http.DefaultClient.Do(r); err != nil {
					http.Error(c.Writer, err.Error(), http.StatusBadGateway)
				} else {
					defer resp.Body.Close()

					if u.Path != "/" || resp.StatusCode != 200 {
						for key := range resp.Header {
							c.Writer.Header().Add(key, resp.Header.Get(key))
						}
						c.Writer.WriteHeader(resp.StatusCode)

						io.Copy(c.Writer, resp.Body)
					} else {
						for key := range resp.Header {
							if strings.ToLower(key) != "content-length" {
								c.Writer.Header().Add(key, resp.Header.Get(key))
							}
						}

						v, _ := io.ReadAll(resp.Body)

						indexTpl = buildIndexTemplate(v)

						setCacheControl(c, cacheNone)

						if err := indexTpl.ExecuteTemplate(c.Writer, "index.html", map[string]string{
							"Body":    CustomBodyHTML,
							"Head":    CustomHeadHTML,
							"RootURL": fmt.Sprintf("https://%s/", c.Request.Host),
						}); err != nil {
							log.Println("Unable to return index.html:", err.Error())
						}
					}
				}
			}
		}
	} else if Assets == nil {
		return func(c *gin.Context) {
			c.String(http.StatusNotFound, "404 Page not found - interface not embedded in binary, please compile with -tags web")
		}
	} else if forced_url == "/" {
		// Serve altered index.html
		return func(c *gin.Context) {
			if indexTpl == nil {
				// Create template from file
				f, _ := Assets.Open("index.html")
				v, _ := io.ReadAll(f)

				indexTpl = buildIndexTemplate(v)
			}

			setCacheControl(c, cacheNone)

			// Serve template
			if err := indexTpl.ExecuteTemplate(c.Writer, "index.html", map[string]string{
				"Body":    CustomBodyHTML,
				"Head":    CustomHeadHTML,
				"RootURL": fmt.Sprintf("https://%s/", c.Request.Host),
			}); err != nil {
				log.Println("Unable to return index.html:", err.Error())
			}
		}
	} else if forced_url != "" {
		// Serve forced_url
		return func(c *gin.Context) {
			c.FileFromFS(forced_url, Assets)
		}
	} else {
		// Serve requested file
		return func(c *gin.Context) {
			if _, err := fs.Stat(_assets, path.Join("build", c.Request.URL.Path)); os.IsNotExist(err) {
				// A miss is never cacheable: a 404, or, for a missing
				// content-hashed bundle, a self-healing reload module handed to
				// the stale cached client instead of a dead 404 so already-stuck
				// clients recover on their own.
				setCacheControl(c, cacheNone)
				if strings.HasPrefix(c.Request.URL.Path, immutableAssetPrefix) && isScriptAsset(c.Request.URL.Path) {
					// Logged (despite the 200) so a persistent miss — a broken or
					// partial deploy rather than a stale cached client — stays
					// visible in monitoring instead of hiding behind the self-heal.
					log.Printf("serving self-heal reload for missing bundle %q", c.Request.URL.Path)
					c.Data(http.StatusOK, "text/javascript; charset=utf-8", staleReloadJSBytes)
					return
				}
				c.FileFromFS("/404.html", Assets)
			} else {
				applyAssetCacheControl(c)
				c.FileFromFS(c.Request.URL.Path, Assets)
			}
		}
	}
}
