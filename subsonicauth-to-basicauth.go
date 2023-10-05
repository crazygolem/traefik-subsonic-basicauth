package subsonicauth_to_basicauth

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"net/http"
	"strings"
)

type Config struct {
	Header       string `json:"header"`
	CleanupQuery bool   `json:"cleanupQuery"`
}

func CreateConfig() *Config {
	return &Config{
		Header:       "Authorization",
		CleanupQuery: true,
	}
}

type Middleware struct {
	config *Config
	name   string
	next   http.Handler
}

func New(ctx context.Context, next http.Handler, config *Config, name string) (http.Handler, error) {
	return &Middleware{
		config: config,
		name:   name,
		next:   next,
	}, nil
}

func (middleware *Middleware) ServeHTTP(res http.ResponseWriter, req *http.Request) {
	res = SubResponseWriter{ResponseWriter: res, req: req}

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
		res.(SubResponseWriter).sendError(&Error{
			Code:    0,
			Message: "Invalid query",
		})
		return
	} else {
		res.(SubResponseWriter).sendError(&Error{
			Code:    10,
			Message: "Required parameter is missing: u",
		})
		return
	}

	if p := query["p"]; len(p) == 1 {
		pass = p[0]
		if strings.HasPrefix(pass, "enc:") {
			var bytes, err = hex.DecodeString(strings.TrimPrefix(pass, "enc:"))
			if err != nil {
				res.(SubResponseWriter).sendError(&Error{
					Code:    40,
					Message: "Wrong username or password",
				})
				return
			}
			pass = string(bytes)
		}
	} else if len(p) > 1 {
		res.(SubResponseWriter).sendError(&Error{
			Code:    0,
			Message: "Invalid query",
		})
		return
	} else if len(query["t"]) > 0 && len(query["s"]) > 0 {
		res.(SubResponseWriter).sendError(&Error{
			Code:    41,
			Message: "Token authentication not supported",
		})
		return
	} else {
		res.(SubResponseWriter).sendError(&Error{
			Code:    40,
			Message: "Required parameter is missing: p",
		})
		return
	}

	var token = base64.StdEncoding.EncodeToString([]byte(user + ":" + pass))
	req.Header.Set(middleware.config.Header, "Basic "+token)

	// TODO: Drop u, p, t, s query parameters

	middleware.next.ServeHTTP(res, req)
}

type SubResponseWriter struct {
	http.ResponseWriter
	req *http.Request
}

// Wraps the original method and intercepts authentication errors, rewriting the
// response to ensure that clients get an appropriate subsonic error instead of
// an HTTP one.
func (res SubResponseWriter) WriteHeader(statusCode int) {
	if statusCode == 401 || statusCode == 403 || statusCode == 407 {
		res.sendError(&Error{
			Code:    40,
			Message: "Wrong username or password",
		})
		return
	}

	res.ResponseWriter.WriteHeader(statusCode)
}

// Immediately respond with a subsonic error
func (res SubResponseWriter) sendError(payload *Error) {
	var response = Subsonic{
		Version:       "1.16.1",
		Type:          "proxy-auth",
		ServerVersion: "n/a",
		OpenSubsonic:  true,
		Status:        "failed",
		Error:         payload,
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
	res.Write(body)
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
