package traefik_subsonic_basicauth

import (
	"bufio"
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"mime"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"unicode"
)

// Writes logs for one middleware instance.
//
// Traefik has no logging API for Yaegi plugins: it captures their stdout and
// logs it at DEBUG (and stderr at ERROR), tagged with the plugin name. Debug
// logs are therefore only visible when Traefik's log level is DEBUG. Each line
// is prefixed with the middleware instance name, so that lines from different
// instances can be told apart.
type logger struct {
	name string
}

func (l logger) Debugf(format string, args ...any) {
	fmt.Printf("[%s] %s\n", l.name, fmt.Sprintf(format, args...))
}

type Config struct {
	// # Authentication mode
	//
	// * "backend": The subsonic backend is performing the BasicAuth
	//   authentication.
	//
	//   In this mode, the authentication parameters are removed, and the
	//   response is not rewritten: as the backend is a subsonic server, it is
	//   expected to sent proper subsonic responses in all situations.
	//
	// * "proxy": The proxy is handling the authentication, e.g. using
	//   ForwardAuth.
	//
	//   In this mode, the authentication parameters are removed, and the
	//   response is rewritten in case of authentication error: the proxy and
	//   the backend authentication service are not expected to know how to
	//   properly answer with a subsonic error, so the plugin has to intervene.
	//
	//   SECURITY NOTES:
	//   - If used with a ForwardAuth middleware, make sure to remove the
	//     propagated header after the ForwardAuth authentication and before
	//     forwarding the request to the backend. Traefik's architecture makes
	//     it impossible to handle this directly in this plugin.
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

	// Name of the header used to propagate the BasicAuth token, or the Bearer
	// token for API keys (see `ApiKey`).
	//
	// The default value is "Authorization".
	//
	// The sanitization-only mode is enabled by setting an empty value: The
	// authentication parameters get validated and stripped from the query, but
	// without adding a BasicAuth header to the forwarded request nor rewriting
	// responses.
	Header string `json:"header"`

	// Name of headers that clients can use to send BasicAuth credentials.
	// Multiple headers can be specified separated by commas and/or whitespace.
	//
	// The default value is "Authorization".
	//
	// This list should contain at least all the headers supported by your
	// subsonic server, unless you remove them from client requests using
	// another middleware.
	ClientHeaders string `json:"client-headers"`

	// Handling of the `apiKey` parameter of the OpenSubsonic API key extension.
	//
	// * "reject" (default): Requests with an API key are rejected.
	//
	// * "bearer": The key is propagated as a Bearer token.
	//
	// Clients are expected to look for the `apiKeyAuthentication` extension in
	// the `getOpenSubsonicExtensions` response, which the plugin doesn't
	// modify. If the backend doesn't support API keys, that response has to be
	// rewritten.
	ApiKey string `json:"apikey"`
}

func CreateConfig() *Config {
	return &Config{
		Header:        "Authorization",
		ClientHeaders: "Authorization",
		ApiKey:        "reject",
	}
}

type Middleware struct {
	config        *Config
	clientHeaders []string // Parsed from config.ClientHeaders
	name          string
	next          http.Handler
	log           logger
}

func New(ctx context.Context, next http.Handler, config *Config, name string) (http.Handler, error) {
	// Traefik logs the errors returned here and shows them in its dashboard,
	// so they are not logged by the plugin, which would duplicate them.
	// Traefik's log line names the router but not the middleware, so the
	// middleware instance name is added to the message instead.
	var configError = func(format string, args ...any) error {
		return fmt.Errorf("[%s] %s", name, fmt.Sprintf(format, args...))
	}

	switch config.Auth {
	case "backend", "proxy":
	default:
		return nil, configError("invalid 'auth' parameter: %s", config.Auth)
	}

	// An empty value enables the sanitization-only mode.
	if config.Header != "" && !HEADER_NAME.MatchString(config.Header) {
		return nil, configError("invalid 'header' parameter: invalid header name: %q", config.Header)
	}

	var clientHeaders = parseHeaderList(config.ClientHeaders)
	for _, header := range clientHeaders {
		if !HEADER_NAME.MatchString(header) {
			return nil, configError("invalid 'client-headers' parameter: invalid header name: %q", header)
		}
	}

	switch config.ApiKey {
	case "reject", "bearer":
	default:
		return nil, configError("invalid 'apikey' parameter: %s", config.ApiKey)
	}

	var mw = &Middleware{
		config:        config,
		clientHeaders: clientHeaders,
		name:          name,
		next:          next,
		log:           logger{name},
	}
	mw.log.Debugf("Plugin instantiated; config: %+v", config)
	return mw, nil
}

// Matches a header name, which must be a token as defined in RFC 9110.
var HEADER_NAME = regexp.MustCompile("^[0-9A-Za-z!#$%&'*+.^_`|~-]+$")

// Matches a Bearer token as defined in RFC 6750 (b64token).
var BEARER_TOKEN = regexp.MustCompile("^[0-9A-Za-z._~+/-]+=*$")

// Parses a list of header names separated by commas and/or whitespace. The
// names are returned in canonical form and without duplicates, so that they
// can be looked up directly in an http.Header. They are not validated, but
// canonicalization only changes the case of letters, so it doesn't affect
// their validity.
func parseHeaderList(list string) []string {
	var names = strings.FieldsFunc(
		list,
		func(r rune) bool { return r == ',' || unicode.IsSpace(r) },
	)

	var headers = make([]string, 0, len(names))
	var seen = make(map[string]bool, len(names))
	for _, name := range names {
		name = http.CanonicalHeaderKey(name)
		if !seen[name] {
			seen[name] = true
			headers = append(headers, name)
		}
	}

	return headers
}

func (mw *Middleware) ServeHTTP(res http.ResponseWriter, req *http.Request) {
	mw.log.Debugf("Handling request: %s", req.URL.Path)

	// Errors raised before the form is parsed can only use the response format
	// requested in the query.
	var sendEarlyError = func(err *Error) {
		var query = req.URL.Query()
		var subres = &subsonicResponseWriter{
			ResponseWriter: res,
			format:         query.Get("f"),
			callback:       query.Get("callback"),
			log:            mw.log,
		}
		subres.sendError(err)
	}

	// The (Open)Subsonic API only uses GET and POST. HEAD and OPTIONS are also
	// allowed for browsers and clients that use HTTP caching. Some servers
	// accept other methods, but this plugin rejects them.
	switch req.Method {
	case http.MethodGet, http.MethodPost, http.MethodHead, http.MethodOptions:
	default:
		mw.log.Debugf("Rejecting unsupported HTTP method: %s", req.Method)
		sendEarlyError(&Error{0, "HTTP method not supported"})
		return
	}

	// req.ParseForm() is called once at the beginning of the request so that
	// req.Form can be used to retrieve parameters irrespective of the request
	// method. For security-sensitive parameters, req.URL.Query() (or
	// req.URL.RawQuery) and req.PostForm must be used.
	if err := req.ParseForm(); err != nil {
		mw.log.Debugf("Error when parsing form: %s", err)
		sendEarlyError(&Error{0, "Invalid request"})
		return
	}

	var subres = subsonicResponseWriter{
		ResponseWriter: res,
		format:         req.Form.Get("f"),
		callback:       req.Form.Get("callback"),
		log:            mw.log,
	}
	mw.serveHTTP(subres, req)
}

func (mw *Middleware) serveHTTP(res subsonicResponseWriter, req *http.Request) {
	var propagateHeader = mw.config.Header != ""
	var interceptResponse = mw.config.Header != "" && mw.config.Auth == "proxy"
	var allowApiKey = mw.config.ApiKey == "bearer"

	var layers, extractErr = extractCredentials(req, mw.clientHeaders, mw.log)
	if extractErr != nil {
		res.sendError(extractErr)
		return
	}

	var creds, resolveErr = resolveCredentials(layers, allowApiKey, mw.log)
	if resolveErr != nil {
		res.sendError(resolveErr)
		return
	}

	if propagateHeader {
		if creds.apiKey != "" {
			mw.log.Debugf("Propagating header for API key")
		} else {
			mw.log.Debugf("Propagating header for user: %s", creds.user)
		}
		req.Header.Set(mw.config.Header, creds.HeaderValue())
	}

	if interceptResponse {
		res.authError = &Error{40, "Wrong username or password"}
		if creds.apiKey != "" {
			res.authError = &Error{44, "Invalid API key"}
		}
		mw.next.ServeHTTP(&res, req)
	} else {
		mw.next.ServeHTTP(res.ResponseWriter, req)
	}
}

// Either a username and password, or an API key.
type credentials struct {
	user   string
	pass   string
	apiKey string
}

func (c *credentials) HeaderValue() string {
	if c.apiKey != "" {
		return "Bearer " + c.apiKey
	}
	var token = base64.StdEncoding.EncodeToString([]byte(c.user + ":" + c.pass))
	return "Basic " + token
}

// The result of looking for one authentication mechanism in one part of the
// request.
type layer struct {
	found  bool         // Whether any of the mechanism's parameters is present
	apiKey bool         // Whether the mechanism is API key authentication
	creds  *credentials // Set if valid credentials were found
	err    *Error       // Set if invalid credentials were found
	source string       // Part of the request, for debug logs
}

// Extracts and strips credentials from every part of the request that can
// carry them, as layers to be resolved by resolveCredentials. Only returns an
// error if the request itself is invalid.
//
// The header names must be in canonical form (see parseHeaderList).
func extractCredentials(req *http.Request, basicAuthHeaders []string, log logger) ([]layer, *Error) {
	var layers = make([]layer, 0)

	var query, err = url.ParseQuery(req.URL.RawQuery)
	if err != nil {
		log.Debugf("Error when parsing query: %s", err)
		return nil, &Error{0, "Invalid request"}
	}
	layers = append(layers, extractCredentialsFromParams(query, "query parameters")...)
	req.URL.RawQuery = query.Encode()
	req.RequestURI = req.URL.RequestURI()

	// Some subsonic clients apparently use POST with form data to transmit
	// parameters instead of, or in addition to placing them in the query.
	// Opensubsonic added official support for this as well, and even though it
	// is only optional according to the opensubsonic spec, in practice POST
	// form parameters must be validated too as it was a de facto standard with
	// legacy subsonic clients and servers, and to prevent a potential HTTP
	// Parameter Pollution vulnerability. An alternative would be to allow only
	// GET requests, but this would limit the usefulness of this plugin.
	//
	// The OpenSubsonic spec is ambiguous on whether the Content-Type header is
	// required [1], and it could be interpreted as the header being optional as
	// long as the body's encoding conforms:
	//
	// > This extension requires that the server support passing
	// > API arguments via POST with the arguments respecting the
	// > application/x-www-form-urlencoded format.
	//
	// This plugin requires the header.
	//
	// As an exception, POST requests without a body are accepted whatever their
	// content type, as they cannot carry parameters (some clients could send
	// POST requests without a body, and the parameters still in the query). For
	// incoming requests, a ContentLength of 0 means that the body is known to
	// be empty, whereas a body of unknown length (e.g. chunked) has a
	// ContentLength of -1 and is still checked.
	//
	// [1]: https://opensubsonic.github.io/docs/extensions/formpost/
	if req.Method == "POST" && req.ContentLength != 0 {
		var ct, _, err = mime.ParseMediaType(req.Header.Get("Content-Type"))
		if err != nil || ct != "application/x-www-form-urlencoded" {
			return nil, &Error{0, "Invalid request"}
		}

		// req.PostForm was filled by req.ParseForm(), in ServeHTTP.
		layers = append(layers, extractCredentialsFromParams(req.PostForm, "POST body")...)
		var body = req.PostForm.Encode()
		req.Body = io.NopCloser(strings.NewReader(body))
		req.ContentLength = int64(len(body))
	}

	// req.Form is a separate map, built by req.ParseForm() from the query and
	// req.PostForm before they were stripped, so it still holds the
	// credentials. It is reset rather than stripped, so that it can't get out
	// of sync with them: the next call to req.ParseForm() (e.g. through
	// req.FormValue()) rebuilds it from the stripped query and req.PostForm.
	req.Form = nil

	for _, name := range basicAuthHeaders {
		layers = append(layers, extractCredentialsFromHeader(req.Header, name))
	}

	return layers, nil
}

// Picks the credentials to use among the layers, or the error to report.
//
// An API key must be the only credentials in the request, and the API key
// extension requires error 43 otherwise, even if the other credentials are
// invalid. This is why the errors of individual layers are only reported after
// going through all layers.
func resolveCredentials(layers []layer, allowApiKey bool, log logger) (*credentials, *Error) {
	var keyFound, otherFound bool
	var layerErr *Error
	var credentials = make([]*credentials, 0)
	for _, l := range layers {
		if l.found && l.apiKey {
			keyFound = true
		} else if l.found {
			otherFound = true
		}

		// Error messages are constant, so they don't leak credentials.
		var kind = "credentials"
		if l.apiKey {
			kind = "API key"
		}
		switch {
		case l.err != nil:
			log.Debugf("Found invalid %s in %s: %s", kind, l.source, l.err.Message)
			if layerErr == nil {
				layerErr = l.err
			}
		case l.creds != nil:
			log.Debugf("Found %s in %s", kind, l.source)
			credentials = append(credentials, l.creds)
		case l.found:
			log.Debugf("Found empty %s in %s", kind, l.source)
		}
	}

	switch {
	case keyFound && !allowApiKey:
		return nil, &Error{42, "API key authentication not supported"}
	case keyFound && otherFound:
		return nil, &Error{43, "Multiple conflicting authentication mechanisms provided"}
	case layerErr != nil:
		return nil, layerErr
	case len(credentials) == 0:
		return nil, &Error{40, "Required parameters are missing: u, p"}
	}

	// OpenSubsonic has a dedicated error code for conflicting credentials (43),
	// but it isn't part of the Subsonic spec, and the plugin usually can't tell
	// whether the client supports OpenSubsonic, so the generic error is used.
	// When an API key is involved, the client supports OpenSubsonic, so the
	// dedicated error code can be used.
	var creds = credentials[0]
	for _, c := range credentials[1:] {
		if c.user == creds.user && c.pass == creds.pass && c.apiKey == creds.apiKey {
			continue
		}
		if keyFound {
			return nil, &Error{43, "Multiple conflicting API keys provided"}
		}
		return nil, &Error{0, "Multiple conflicting credentials provided"}
	}

	return creds, nil
}

// Extracts and strips the API key, and the legacy credentials (username and
// password, or token), from the parameters, as separate layers.
func extractCredentialsFromParams(params url.Values, source string) []layer {
	var keyFound = len(params["apiKey"]) > 0
	var legacyFound = len(params["u"]) > 0 || len(params["p"]) > 0 ||
		len(params["t"]) > 0 || len(params["s"]) > 0

	var keyCreds, keyErr = parseApiKeyAuth(params)
	var legacyCreds, legacyErr = parseLegacyAuth(params)

	params.Del("apiKey")
	params.Del("u")
	params.Del("p")
	params.Del("t")
	params.Del("s")

	return []layer{
		{found: keyFound, apiKey: true, creds: keyCreds, err: keyErr, source: source},
		{found: legacyFound, creds: legacyCreds, err: legacyErr, source: source},
	}
}

// Extracts and strips the BasicAuth credentials from the header, as a layer.
//
// The header name must be in canonical form (see parseHeaderList).
func extractCredentialsFromHeader(header http.Header, name string) layer {
	var values = header[name]
	var creds, err = parseBasicAuthHeader(values)

	delete(header, name)

	return layer{found: len(values) > 0, creds: creds, err: err, source: "header " + name}
}

// Parses and validates the API key from the parameters. Returns neither
// credentials nor an error if there is none.
//
// Clients using the apiKey parameter support OpenSubsonic, so they can handle
// the OpenSubsonic error codes.
func parseApiKeyAuth(params url.Values) (*credentials, *Error) {
	var keys = params["apiKey"]
	switch {
	case len(keys) == 0:
		return nil, nil
	case len(keys) > 1:
		return nil, &Error{0, "Invalid request"}
	// Keys that aren't valid bearer tokens can't be propagated
	case !BEARER_TOKEN.MatchString(keys[0]):
		return nil, &Error{44, "Invalid API key"}
	default:
		return &credentials{apiKey: keys[0]}, nil
	}
}

// Parses and validates the username and password from the parameters, and
// rejects tokens. Returns neither credentials nor an error if there are none.
func parseLegacyAuth(params url.Values) (*credentials, *Error) {
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
		return &credentials{user: user, pass: pass}, nil
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

// Parses and validates the BasicAuth credentials from the values of a header.
// Returns neither credentials nor an error if there are none.
func parseBasicAuthHeader(values []string) (*credentials, *Error) {
	switch len(values) {
	case 1:
		// The standard library only parses BasicAuth credentials from the
		// Authorization header, so the value is put in a throwaway request.
		var r = http.Request{Header: http.Header{"Authorization": values}}
		if u, p, ok := r.BasicAuth(); ok && u != "" && p != "" {
			return &credentials{user: u, pass: p}, nil
		}

		// Even if allowed by basicauth, it is assumed that legacy authentication
		// doesn't allow empty username or password, so we shouldn't allow it for
		// the basicauth adapter either.
		return nil, &Error{40, "Invalid BasicAuth credentials"}
	case 0:
		return nil, nil
	default:
		return nil, &Error{0, "Invalid request"}
	}
}

type subsonicResponseWriter struct {
	http.ResponseWriter
	format      string
	callback    string
	authError   *Error // Sent in place of downstream authentication failures
	intercepted bool
	started     bool
	log         logger
}

// Wraps the original method and intercepts authentication errors, rewriting the
// response to ensure that clients get an appropriate subsonic error instead of
// an HTTP one.
func (res *subsonicResponseWriter) WriteHeader(statusCode int) {
	if res.intercepted {
		return
	}

	if !res.started && (statusCode == 401 || statusCode == 403 || statusCode == 407) {
		res.log.Debugf("Rewriting authentication error response: %d", statusCode)
		res.sendError(res.authError)
		return
	}

	// Informational (1xx) responses can be followed by the final one.
	if statusCode >= 200 || statusCode == http.StatusSwitchingProtocols {
		res.started = true
	}
	res.ResponseWriter.WriteHeader(statusCode)
}

// Wraps the original method and ensures that writes by downstream handlers are
// ignored if we already sent a subsonic response.
func (res *subsonicResponseWriter) Write(data []byte) (n int, err error) {
	if res.intercepted {
		// Fake success in order to adhere to the io.Writer interface
		return len(data), nil
	}
	res.started = true // Implicitly sends a 200 if WriteHeader wasn't called
	return res.ResponseWriter.Write(data)
}

// Delegates to the original writer through an http.ResponseController, which
// also finds a Flusher behind writers that only implement Unwrap.
func (res *subsonicResponseWriter) Flush() {
	var err = http.NewResponseController(res.ResponseWriter).Flush()
	if !errors.Is(err, http.ErrNotSupported) {
		res.started = true // Implicitly sends a 200 if WriteHeader wasn't called
	}
}

// Delegates to the original writer through an http.ResponseController, which
// also finds a Hijacker behind writers that only implement Unwrap, and returns
// an error matching http.ErrNotSupported if there is none. The reverse proxy
// reports that error, so it is not logged here.
func (res *subsonicResponseWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	return http.NewResponseController(res.ResponseWriter).Hijack()
}

var SAFE_JSONP_CALLBACK = regexp.MustCompile(`^[A-Za-z_$][A-Za-z0-9_$]*(?:\.[A-Za-z_$][A-Za-z0-9_$]*)*$`)

// Checks whether the callback name is safe to splice directly into a JSONP
// response body.
// Only simple, dotted JS identifiers are allowed, which is what legitimate
// subsonic clients are expected to use in practice.
// The length is also capped to guard against pathological inputs, but should
// allow realistic long-ish names.
func isSafeJsonpCallback(name string) bool {
	return name != "" && len(name) < 128 && SAFE_JSONP_CALLBACK.MatchString(name)
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

	res.Header().Del("Content-Type")
	res.Header().Del("Content-Length")
	res.Header().Set("X-Content-Type-Options", "nosniff")

	switch {
	case res.format == "json":
		mime = "application/json"
		body, _ = json.Marshal(&JsonWrapper{Subsonic: response})
	case res.format == "jsonp" && !isSafeJsonpCallback(res.callback):
		// Bypass subsonic response formatting: There is no safe way to hand the
		// response to a client that expects a jsonp payload with an unsafe
		// jsonp callback.
		res.log.Debugf("Rejecting unsafe JSONP callback")
		res.Header().Set("Content-Type", "text/plain")
		res.ResponseWriter.WriteHeader(400)
		res.ResponseWriter.Write([]byte("Invalid or unsafe JSONP callback"))
		return
	case res.format == "jsonp":
		mime = "application/javascript"
		body, _ = json.Marshal(&JsonWrapper{Subsonic: response})
		body = fmt.Appendf(nil, "%s(%s)", res.callback, body)
	default:
		mime = "application/xml"
		body, _ = xml.Marshal(&response)
	}

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
