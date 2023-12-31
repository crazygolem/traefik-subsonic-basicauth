package traefik_subsonic_basicauth

import (
	"bufio"
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
)

var DEBUG = log.New(io.Discard, "DEBUG [subsonic-basicauth]: ", 0)

type Config struct {
	// # Authentication mode
	//
	//   * "backend": The subsonic backend is performing the BasicAuth
	//     authentication.
	//
	//     In this mode, the SubsonicAuth parameters are removed, and the
	//     response is not rewritten: as the backend is a subsonic server, it is
	//     expected to sent proper subsonic responses in all situations.
	//
	//   * "proxy": The proxy is handling the authentication, e.g. using
	//     ForwardAuth.
	//
	//     In this mode, the SubsonicAuth parameters are removed, and the
	//     response is rewritten in case of authentication error: the proxy and
	//     the authentication service are not expected to know how to properly
	//     answer with a subsonic error, so the plugin has to intervene.
	//
	//     SECURITY NOTE: If used with a ForwardAuth middleware, make sure to
	//     remove the BasicAuth header after the authentication and before
	//     forwarding the request to the backend. Traefik's architecture makes
	//     it impossible to handle this directly in this plugin.
	Auth string `json:"auth"`

	// Enable debug logs. Does not contain sensitive data related to the
	// subsonic authentication.
	Debug bool `json:"debug"`

	// Name of the header used to propagate the BasicAuth token.
	//
	// The default value is "Authorization", but "Proxy-Authorization" is a
	// common alternative.
	//
	// The sanitization-only mode is enabled by setting an empty value: The
	// authentication parameters get validated and stripped from the query, but
	// without adding a BasicAuth header to the forwarded request nor rewriting
	// responses.
	Header string `json:"header"`
}

func CreateConfig() *Config {
	return &Config{
		Header: "Authorization",
		Debug:  false,
	}
}

type Middleware struct {
	config *Config
	name   string
	next   http.Handler
}

func New(ctx context.Context, next http.Handler, config *Config, name string) (http.Handler, error) {
	if config.Debug {
		DEBUG.SetFlags(log.LstdFlags)
		DEBUG.SetOutput(os.Stdout)
	}

	switch config.Auth {
	case "backend", "proxy":
	default:
		return nil, fmt.Errorf("invalid 'auth' parameter: %s", config.Auth)
	}

	DEBUG.Printf("Plugin instantiated: %s", name)
	return &Middleware{
		config: config,
		name:   name,
		next:   next,
	}, nil
}

func (middleware *Middleware) ServeHTTP(res http.ResponseWriter, req *http.Request) {
	DEBUG.Printf("Handling request: %s", req.URL.Path)
	middleware.serveHTTP(responseWriter{ResponseWriter: res, req: req}, req)
}

func (middleware *Middleware) serveHTTP(res responseWriter, req *http.Request) {
	var propagateHeader = middleware.config.Header != ""
	var interceptResponse = middleware.config.Header != "" && middleware.config.Auth == "proxy"

	// Caution: query.Get() returns the first parameter's value. We need to
	// enforce that the query contains at most one of each auth parameter that
	// we use for authentication, to avoid HTTP Parameter Pollution attacks. It
	// is not an issue if the parameters are dropped before forwarding the
	// request to the subsonic endpoint.
	var query = req.URL.Query()

	var user string
	var pass string

	if u := query["u"]; len(u) == 1 {
		user = u[0]
	} else if len(u) > 1 {
		res.sendError(0, "Invalid query")
		return
	}

	if p := query["p"]; len(p) == 1 {
		pass = p[0]
		if strings.HasPrefix(pass, "enc:") {
			var bytes, err = hex.DecodeString(strings.TrimPrefix(pass, "enc:"))
			if err != nil {
				res.sendError(40, "Wrong username or password")
				return
			}
			pass = string(bytes)
		}
	} else if len(p) > 1 {
		res.sendError(0, "Invalid query")
		return
	} else if len(query["t"]) > 0 && len(query["s"]) > 0 {
		res.sendError(41, "Token authentication not supported")
		return
	}

	// Subsonicauth parameters' validation is relaxed to not penalize clients
	// that support basicauth: those clients can either use only basicauth, in
	// which case we don't consider the subsonicauth parameters as missing, or
	// both basicauth and subsonicauth, in which case they must match.
	if u, p, ok := parseBasicAuth(req, middleware.config.Header); ok {
		DEBUG.Printf("Header already set from upstream: %s", middleware.config.Header)
		if u == "" || p == "" {
			// Even if allowed by basicauth, it is assumed that subsonicauth
			// doesn't allow empty username or password, so we shouldn't allow
			// it for the adapter either.
			res.sendError(40, "Invalid BasicAuth credentials")
			return
		} else if user == "" && pass == "" {
			// Client uses basicauth without subsonicauth
			propagateHeader = false
		} else if user == "" {
			res.sendError(40, "Required parameter is missing: u")
			return
		} else if pass == "" {
			res.sendError(40, "Required parameter is missing: p")
			return
		} else if u == user && p == pass {
			// Client uses both basicauth and subsonicauth and they match
			propagateHeader = false
		} else {
			res.sendError(0, "BasicAuth and SubsonicAuth credentials don't match")
			return
		}
	} else {
		if user == "" {
			res.sendError(40, "Required parameter is missing: u")
			return
		} else if pass == "" {
			res.sendError(40, "Required parameter is missing: p")
			return
		}
	}

	if propagateHeader {
		DEBUG.Printf("Propagating header for user: %s", user)
		var token = base64.StdEncoding.EncodeToString([]byte(user + ":" + pass))
		req.Header.Set(middleware.config.Header, "Basic "+token)
	}

	query.Del("u")
	query.Del("p")
	query.Del("t")
	query.Del("s")

	req.URL.RawQuery = query.Encode()
	req.RequestURI = req.URL.RequestURI()
	DEBUG.Printf("Subsonicauth query parameters removed: %s", req.RequestURI)

	if interceptResponse {
		middleware.next.ServeHTTP(&res, req)
	} else {
		middleware.next.ServeHTTP(res.ResponseWriter, req)
	}
}

// Adapted from net/http/request.go
func parseBasicAuth(r *http.Request, header string) (username, password string, ok bool) {
	const prefix = "Basic "
	var auth = r.Header.Get(header)

	if len(auth) < len(prefix) || !strings.EqualFold(auth[:len(prefix)], prefix) {
		return "", "", false
	}

	if bytes, err := base64.StdEncoding.DecodeString(auth[len(prefix):]); err != nil {
		return "", "", false
	} else {
		auth = string(bytes)
	}

	if username, password, ok = strings.Cut(auth, ":"); !ok {
		return "", "", false
	}

	return username, password, true
}

type responseWriter struct {
	http.ResponseWriter
	req         *http.Request
	intercepted bool
}

// Wraps the original method and intercepts authentication errors, rewriting the
// response to ensure that clients get an appropriate subsonic error instead of
// an HTTP one.
func (res *responseWriter) WriteHeader(statusCode int) {
	if statusCode == 401 || statusCode == 403 || statusCode == 407 {
		DEBUG.Printf("Rewriting authentication error response: %d", statusCode)
		res.sendError(40, "Wrong username or password")
		return
	}

	res.ResponseWriter.WriteHeader(statusCode)
}

// Wraps the original method and ensures that writes by downstream handlers are
// ignored if we already sent a subsonic response.
func (res *responseWriter) Write(data []byte) (n int, err error) {
	if res.intercepted {
		return 0, nil
	}
	return res.ResponseWriter.Write(data)
}

func (res *responseWriter) Flush() {
	if r, ok := res.ResponseWriter.(http.Flusher); ok {
		r.Flush()
	}
}

func (res *responseWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	if r, ok := res.ResponseWriter.(http.Hijacker); ok {
		return r.Hijack()
	}
	return nil, nil, fmt.Errorf("%T is not an http.Hijacker", res.ResponseWriter)
}

// Immediately respond with a subsonic error
func (res *responseWriter) sendError(code int32, message string) {
	res.intercepted = true

	var response = Subsonic{
		Version:       "1.16.1",
		Type:          "proxy-auth",
		ServerVersion: "n/a",
		OpenSubsonic:  true,
		Status:        "failed",
		Error:         &Error{Code: code, Message: message},
	}

	var mime string
	var body []byte

	switch res.req.URL.Query().Get("f") {
	case "json":
		mime = "application/json"
		body, _ = json.Marshal(&JsonWrapper{Subsonic: response})
	case "jsonp":
		mime = "application/javascript"
		body, _ = json.Marshal(&JsonWrapper{Subsonic: response})

		var callback = res.req.URL.Query().Get("callback")
		body = []byte(fmt.Sprintf("%s(%s)", callback, body))
	default:
		mime = "application/xml"
		body, _ = xml.Marshal(&response)
	}

	res.Header().Del("Content-Length")
	res.Header().Set("Content-Type", mime)
	res.ResponseWriter.WriteHeader(200)
	res.ResponseWriter.Write(body)
}

type Subsonic struct {
	XMLName       xml.Name `xml:"http://subsonic.org/restapi subsonic-response" json:"-"`
	Status        string   `xml:"status,attr"                                   json:"status"`
	Version       string   `xml:"version,attr"                                  json:"version"`
	Type          string   `xml:"type,attr"                                     json:"type"`
	ServerVersion string   `xml:"serverVersion,attr"                            json:"serverVersion"`
	OpenSubsonic  bool     `xml:"openSubsonic,attr,omitempty"                   json:"openSubsonic,omitempty"`
	Error         *Error   `xml:"error,omitempty"                               json:"error,omitempty"`
}

type Error struct {
	Code    int32  `xml:"code,attr"    json:"code"`
	Message string `xml:"message,attr" json:"message,omitempty"`
}

type JsonWrapper struct {
	Subsonic Subsonic `json:"subsonic-response"`
}
