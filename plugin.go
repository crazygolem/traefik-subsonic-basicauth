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
	"mime"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
)

var DEBUG = log.New(io.Discard, "DEBUG [subsonic-basicauth]: ", 0)

type Config struct {
	// # Authentication mode
	//
	// * "backend": The subsonic backend is performing the BasicAuth
	//   authentication.
	//
	//   In this mode, the SubsonicAuth parameters are removed, and the response
	//   is not rewritten: as the backend is a subsonic server, it is expected
	//   to sent proper subsonic responses in all situations.
	//
	// * "proxy": The proxy is handling the authentication, e.g. using
	//   ForwardAuth.
	//
	//   In this mode, the SubsonicAuth parameters are removed, and the response
	//   is rewritten in case of authentication error: the proxy and the backend
	//   authentication service are not expected to know how to properly answer
	//   with a subsonic error, so the plugin has to intervene.
	//
	//   SECURITY NOTES:
	//   - If used with a ForwardAuth middleware, make sure to remove the
	//     BasicAuth header after the authentication and before forwarding the
	//     request to the backend. Traefik's architecture makes it impossible to
	//     handle this directly in this plugin.
	//   - Make sure to check your subsonic server's documentation and disable
	//     authentication mechanisms not supported by this plugin, or prevent
	//     them from being used by clients (e.g. by stripping the corresponding
	//     credentials from requests). If not done correctly, THIS COULD LEAVE
	//     YOUR SYSTEM VULNERABLE TO HPP ATTACKS, where different credentials
	//     are retrieved in different ways by different components of your
	//     system. Credential sources not supported by this plugin could include
	//     non-standard headers (see the `ClientHeaders` option), cookies, or
	//     non-standard query parameters.
	Auth string `json:"auth"`

	// Enable debug logs. Does not contain sensitive data related to the
	// subsonic authentication.
	Debug bool `json:"debug"`

	// Name of the header used to propagate the BasicAuth token.
	//
	// The default value is "Authorization".
	//
	// The sanitization-only mode is enabled by setting an empty value: The
	// authentication parameters get validated and stripped from the query, but
	// without adding a BasicAuth header to the forwarded request nor rewriting
	// responses.
	Header string `json:"header"`

	// Name of headers that clients can use to send BasicAuth credentials.
	// Multiple headers can be specified separated by a comma.
	//
	// The default value is "Authorization".
	//
	// This list should contain at least all the headers supported by your
	// subsonic server, unless you remove them from client requests using
	// another middleware.
	ClientHeaders string `json:"client-headers"`
}

func CreateConfig() *Config {
	return &Config{
		Header:        "Authorization",
		ClientHeaders: "Authorization",
		Debug:         false,
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

	DEBUG.Printf("Plugin instantiated: %s; config: %+v", name, config)
	return &Middleware{
		config: config,
		name:   name,
		next:   next,
	}, nil
}

func (mw *Middleware) ServeHTTP(res http.ResponseWriter, req *http.Request) {
	DEBUG.Printf("Handling request: %s", req.URL.Path)

	// req.ParseForm() is called once at the beginning of the request so that
	// req.Form can be used to retrieve parameters irrespective of the request
	// method. For security-sensitive parameters, req.URL.Query() (or
	// req.URL.RawQuery) and req.PostForm must be used.
	if err := req.ParseForm(); err != nil {
		DEBUG.Printf("Error when parsing form: %s", err)
		var subres = &subsonicResponseWriter{
			ResponseWriter: res,
			format:         req.URL.Query().Get("f"),
			callback:       req.URL.Query().Get("callback"),
		}
		subres.sendError(&Error{0, "Invalid request"})
		return
	}

	var subres = subsonicResponseWriter{
		ResponseWriter: res,
		format:         req.Form.Get("f"),
		callback:       req.Form.Get("callback"),
	}
	mw.serveHTTP(subres, req)
}

func (mw *Middleware) serveHTTP(res subsonicResponseWriter, req *http.Request) {
	var propagateHeader = mw.config.Header != ""
	var interceptResponse = mw.config.Header != "" && mw.config.Auth == "proxy"

	var creds *credentials

	if c, err := extractCredentials(req, strings.Split(mw.config.ClientHeaders, ",")); err != nil {
		res.sendError(err)
		return
	} else {
		creds = c
	}

	if propagateHeader {
		DEBUG.Printf("Propagating header for user: %s", creds.user)
		req.Header.Set(mw.config.Header, creds.ToBasicAuth())
	}

	if interceptResponse {
		mw.next.ServeHTTP(&res, req)
	} else {
		mw.next.ServeHTTP(res.ResponseWriter, req)
	}
}

type credentials struct {
	user string
	pass string
}

func (c *credentials) ToBasicAuth() string {
	var token = base64.StdEncoding.EncodeToString([]byte(c.user + ":" + c.pass))
	return "Basic " + token
}

// Extracts and strips credentials from the request. If credentials are present
// in several places, ensures that they are consistent.
func extractCredentials(req *http.Request, basicAuthHeaders []string) (*credentials, *Error) {
	var credentials = make([]*credentials, 0)

	if creds, err := extractSubsonicAuthQuery(req); err != nil {
		return nil, err
	} else if creds != nil {
		DEBUG.Printf("Found credentials in query parameters")
		credentials = append(credentials, creds)
	}

	// Some subsonic clients apparently use POST with form data to transmit
	// parameters instead of, or in addition to placing them in the query.
	// Opensubsonic added official support for this as well, and even though it
	// is only optional according to the opensubsonic spec, in practice POST
	// form parameters must be validated too as it was a de facto standard with
	// legacy subsonic clients and servers, and to prevent a potential HTTP
	// Parameter Pollution vulnerability. An alternative would be to allow only
	// GET requests, but this would limit the usefulness of this plugin.
	if req.Method == "POST" {
		var ct, _, err = mime.ParseMediaType(req.Header.Get("Content-Type"))
		if err != nil || ct != "application/x-www-form-urlencoded" {
			return nil, &Error{0, "Invalid request"}
		}

		if creds, err := extractSubsonicAuthBody(req); err != nil {
			return nil, err
		} else if creds != nil {
			DEBUG.Printf("Found credentials in POST body")
			credentials = append(credentials, creds)
		}
	}

	for _, header := range basicAuthHeaders {
		if creds, err := extractBasicAuth(req, header); err != nil {
			return nil, err
		} else if creds != nil {
			DEBUG.Printf("Found BasicAuth credentials in header: %s", header)
			credentials = append(credentials, creds)
		}
	}

	if len(credentials) == 0 {
		return nil, &Error{40, "Required parameters are missing: u, p"}
	}

	var creds = credentials[0]
	for _, c := range credentials[1:] {
		if c.user != creds.user || c.pass != creds.pass {
			return nil, &Error{0, "Multiple credentials provided"}
		}
	}

	return creds, nil
}

func extractSubsonicAuthQuery(r *http.Request) (*credentials, *Error) {
	var params url.Values
	if p, err := url.ParseQuery(r.URL.RawQuery); err != nil {
		DEBUG.Printf("Error when parsing query: %s", err)
		return nil, &Error{0, "Invalid request"}
	} else {
		params = p
	}

	var creds *credentials
	if c, err := handleSubsonicAuth(params); err != nil {
		return nil, err
	} else {
		creds = c
	}

	var query = r.URL.Query()
	query.Del("u")
	query.Del("p")
	query.Del("t")
	query.Del("s")

	r.URL.RawQuery = query.Encode()
	r.RequestURI = r.URL.RequestURI()

	return creds, nil
}

// Assumes req.ParseForm() has already been called
func extractSubsonicAuthBody(req *http.Request) (*credentials, *Error) {
	var creds *credentials
	if c, err := handleSubsonicAuth(req.PostForm); err != nil {
		return nil, err
	} else {
		creds = c
	}

	var params = req.PostForm
	params.Del("u")
	params.Del("p")
	params.Del("t")
	params.Del("s")

	var body = params.Encode()
	req.Body = io.NopCloser(strings.NewReader(body))
	req.ContentLength = int64(len(body))

	return creds, nil
}

func handleSubsonicAuth(params url.Values) (*credentials, *Error) {
	// Caution: url.Values.Get() returns the first parameter's value. We need to
	// enforce that the query contains at most one of each auth parameter that
	// we use for authentication, to avoid HTTP Parameter Pollution attacks. It
	// is not as much of an issue if the parameters are dropped before
	// forwarding the request to the subsonic endpoint, but well-behaving
	// clients shouldn't do it anyway.

	if len(params["t"]) > 0 || len(params["s"]) > 0 {
		return nil, &Error{41, "Token authentication not supported"}
	}

	var user string
	if u := params["u"]; len(u) == 1 {
		user = u[0]
	} else if len(u) > 1 {
		return nil, &Error{0, "Invalid request"}
	}

	var pass string
	if p := params["p"]; len(p) == 1 {
		pass = p[0]
		if strings.HasPrefix(pass, "enc:") {
			var bytes, err = hex.DecodeString(pass[4:])
			if err != nil {
				return nil, &Error{40, "Wrong username or password"}
			}
			pass = string(bytes)
		}
	} else if len(p) > 1 {
		return nil, &Error{0, "Invalid request"}
	}

	switch {
	case user != "" && pass != "":
		return &credentials{user, pass}, nil
	case user == "" && pass == "":
		return nil, nil
	case user == "":
		return nil, &Error{40, "Required parameter is missing: u"}
	case pass == "":
		return nil, &Error{40, "Required parameter is missing: p"}
	default:
		panic("unreachable")
	}
}

func extractBasicAuth(r *http.Request, header string) (*credentials, *Error) {
	var h = r.Header[http.CanonicalHeaderKey(header)]
	switch len(h) {
	case 1:
		if u, p, ok := parseBasicAuth(h[0]); ok && u != "" && p != "" {
			r.Header.Del(header)
			return &credentials{u, p}, nil
		}

		// Even if allowed by basicauth, it is assumed that subsonicauth doesn't
		// allow empty username or password, so we shouldn't allow it for the
		// basicauth adapter either.
		return nil, &Error{40, "Invalid BasicAuth credentials"}
	case 0:
		return nil, nil
	default:
		return nil, &Error{0, "Invalid request"}
	}
}

// Adapted from net/http/request.go
func parseBasicAuth(value string) (user, pass string, ok bool) {
	const prefix = "Basic "

	if len(value) < len(prefix) || !strings.EqualFold(value[:len(prefix)], prefix) {
		return "", "", false
	}

	if bytes, err := base64.StdEncoding.DecodeString(value[len(prefix):]); err != nil {
		return "", "", false
	} else {
		value = string(bytes)
	}

	if user, pass, ok = strings.Cut(value, ":"); !ok {
		return "", "", false
	}

	return user, pass, true
}

type subsonicResponseWriter struct {
	http.ResponseWriter
	format      string
	callback    string
	intercepted bool
}

// Wraps the original method and intercepts authentication errors, rewriting the
// response to ensure that clients get an appropriate subsonic error instead of
// an HTTP one.
func (res *subsonicResponseWriter) WriteHeader(statusCode int) {
	if statusCode == 401 || statusCode == 403 || statusCode == 407 {
		DEBUG.Printf("Rewriting authentication error response: %d", statusCode)
		res.sendError(&Error{40, "Wrong username or password"})
		return
	}

	res.ResponseWriter.WriteHeader(statusCode)
}

// Wraps the original method and ensures that writes by downstream handlers are
// ignored if we already sent a subsonic response.
func (res *subsonicResponseWriter) Write(data []byte) (n int, err error) {
	if res.intercepted {
		return 0, nil
	}
	return res.ResponseWriter.Write(data)
}

func (res *subsonicResponseWriter) Flush() {
	if r, ok := res.ResponseWriter.(http.Flusher); ok {
		r.Flush()
	}
}

func (res *subsonicResponseWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	if r, ok := res.ResponseWriter.(http.Hijacker); ok {
		return r.Hijack()
	}
	return nil, nil, fmt.Errorf("%T is not an http.Hijacker", res.ResponseWriter)
}

// Immediately respond with a subsonic error
func (res *subsonicResponseWriter) sendError(err *Error) {
	res.intercepted = true

	var response = Subsonic{
		Version:       "1.16.1",
		Type:          "proxy-auth",
		ServerVersion: "n/a",
		OpenSubsonic:  true,
		Status:        "failed",
		Error:         err,
	}

	var mime string
	var body []byte

	switch res.format {
	case "json":
		mime = "application/json"
		body, _ = json.Marshal(&JsonWrapper{Subsonic: response})
	case "jsonp":
		mime = "application/javascript"
		body, _ = json.Marshal(&JsonWrapper{Subsonic: response})
		body = []byte(fmt.Sprintf("%s(%s)", res.callback, body))
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
