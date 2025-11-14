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
	"io/ioutil"
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

func init() {
	flag.StringVar(&CustomHeadHTML, "custom-head-html", CustomHeadHTML, "Add custom HTML right before </head>")
	flag.StringVar(&CustomBodyHTML, "custom-body-html", CustomBodyHTML, "Add custom HTML right before </body>")
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
	router.GET("/_app/immutable/*_", func(c *gin.Context) { c.Writer.Header().Set("Cache-Control", "public, max-age=604800, immutable") }, serveOrReverse("", cfg))

	router.GET("/", serveOrReverse("/", cfg))
	router.GET("/blacklist/", serveOrReverse("/", cfg))
	router.GET("/blacklist/:ip", serveOrReverse("/", cfg))
	router.GET("/domain/", serveOrReverse("/", cfg))
	router.GET("/domain/:domain", serveOrReverse("/", cfg))
	router.GET("/test/", serveOrReverse("/", cfg))
	router.GET("/test/:testid", serveOrReverse("/", cfg))
	router.GET("/favicon.png", func(c *gin.Context) { c.Writer.Header().Set("Cache-Control", "public, max-age=604800, immutable") }, serveOrReverse("", cfg))
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

						v, _ := ioutil.ReadAll(resp.Body)

						v2 := strings.Replace(strings.Replace(string(v), "</head>", `{{ .Head }}<meta property="og:url" content="{{ .RootURL }}"></head>`, 1), "</body>", "{{ .Body }}</body>", 1)

						indexTpl = template.Must(template.New("index.html").Parse(v2))

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
				v, _ := ioutil.ReadAll(f)

				v2 := strings.Replace(strings.Replace(string(v), "</head>", `{{ .Head }}<meta property="og:url" content="{{ .RootURL }}"></head>`, 1), "</body>", "{{ .Body }}</body>", 1)

				indexTpl = template.Must(template.New("index.html").Parse(v2))
			}

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
				c.FileFromFS("/404.html", Assets)
			} else {
				c.FileFromFS(c.Request.URL.Path, Assets)
			}
		}
	}
}
