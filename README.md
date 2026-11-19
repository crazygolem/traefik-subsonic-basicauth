# Traefik plugin to use BasicAuth with Subsonic

This Traefik plugin transforms Subsonic authentication parameters into a
BasicAuth header.

In front of a ForwardAuth service, it lets you integrate into your existing
authentication infrastructure Subsonic clients that only support the standard
Subsonic authentication scheme.

In front of a Subsonic server that supports BasicAuth or some other
authentication scheme, it lets you remove sensitive query parameters to
reduce the risk of exposing them in logs.

The plugin validates Subsonic authentication parameters for security, and
removes them before forwarding the request.

It is designed for the Subsonic API first, but tries to play nice with
OpenSubsonic: it supports several OpenSubsonic additions, either by default or
as an option.

# Security warning

This plugin requires clients to use the old subsonic authentication scheme where
the password is transmitted in clear text (`p` query parameter) and does not
support the "more secure" token scheme (`t` and `s` query parameters).

The reasons for this are
1. there is no standard way to transmit two data points in the password field of
   a BasicAuth header, and I don't want to come up with my own little scheme;
2. this requires the server to store the user's password in clear form or with
   reversible encryption (this is true for any compliant subsonic servers
   nowadays), and the goal of this plugin is to get rid of this madness.

From a security standpoint, letting clients transmit their credentials with the
old subsonic scheme is not ideal, but **if the connection is made over HTTPS**
it is similar in principle to authentication mechanisms you find on most
websites, with the following caveats:
1. **The password can end up in server logs**: Servers usually avoid logging
   the body of incoming requests, but the path and query parameters are often
   logged. This is somewhat mitigated with subsonic's token scheme where the
   user's password is not directly visible (even though it doesn't add any extra
   security from an authentication perspective).
2. **The password can be transmitted to third-parties**: For example, in order
   to support casting, the subsonic client must transmit credentials to the cast
   receiver. Since this plugin only supports the old subsonic scheme, the
   casting devices will get access to the user's password.

**Make sure you understand the implications of this and follow all privacy laws,
regulations and policies applicable to you. The contributors to this plugin
decline all responsibility and liability for your use of it.**

Note that the OpenSubsonic initiative is working on adding support for a [modern
authentication scheme][os-api-auth] to the subsonic protocol, with support from
authors of actively maintained clients and servers. You are encouraged to stop
using this plugin (and stop supporting the legacy Subsonic schemes altogether)
once a consensus has been reached and clients and servers adopt the new scheme.

## Traefik's access log

Traefik's access log records credentials sent in the query string. It logs the
request path and query as received, before any middleware runs, so this plugin
can't hide them. To keep them out of the access log, either:

* drop query parameters from the access log with
  `--accesslog.fields.queryparameters.defaultmode=drop` (Traefik v3.6.19,
  v3.7.3 and later; applies to all routers), or
* disable access logs on your Subsonic router, e.g.
  `traefik.http.routers.subsonic.observability.accesslogs: false` (Traefik v3.3
  and later).

Other proxies in front of Traefik, such as a load balancer or CDN, may log the
query string too.

# Restrictions on Subsonic credentials

Credentials are propagated in a header that can't carry every value a Subsonic
server might accept. The plugin rejects such credentials:

* **Usernames can't contain a colon (`:`).** BasicAuth separates the username
  from the password at the first colon, so the backend would see a different
  username. Requests with a colon in the `u` parameter fail with error 40.
  Passwords can contain colons.
* **API keys must be valid Bearer tokens**: letters, digits and `-._~+/`,
  optionally followed by `=` padding. Requests with any other key fail with
  error 44. This only applies with `apikey: bearer`: with `passthrough` the key
  isn't put in the header, and with `reject` every API key is rejected (see the
  `apikey` option).

The restrictions apply even when header propagation is disabled (see the
`header` option).

# OpenSubsonic's public extensions endpoint

The OpenSubsonic spec requires the extensions endpoint
(`getOpenSubsonicExtensions`) to be public, but by default this plugin requires
credentials for it, as for every other endpoint (see the `anonymous` option).

The endpoint can be used by OpenSubsonic clients to discover a server's
capabilities instead of having to probe them. Its response includes
authentication mechanisms, which in principle need to be discovered before
authenticating. A client could then offer the user only the most secure
mechanism that the server supports.

But in practice, none of the clients we know of actually *need* the extensions
endpoint to be public, and instead they let the user select the appropriate
authentication mechanism, checking server capabilities with an authenticated
request.

The requirement for it to be public was added silently in October 2024, a year
and a half after the endpoint itself, together with the API Key Authentication
extension. It is this plugin's stance that making it a public endpoint was
misguided and unnecessary, and that together with mixing in authentication and
other server capabilities it's making the life of everyone in the security
stack more difficult.

# Configuration

**`auth`**

Required, either `backend` or `proxy`.

The plugin supports two deployment scenarios:
1. Backend authentication, where the subsonic service supports BasicAuth and
   authenticates requests itself;
2. Proxy authentication, where a third-party service performs the
   authentication, e.g. using Traefik's ForwardAuth middleware.

The difference between the two modes is whether the response is intercepted and
rewritten in case of authentication error: a subsonic authentication error does
not look the same as an HTTP authentication error, and clients are expecting a
proper subsonic error when authentication fails, which cannot be expected from
a generic third-party authentication service.

> [!CAUTION]
>
> Make sure to check your subsonic server's documentation and disable
> authentication mechanisms not supported by this plugin, or prevent them from
> being used by clients (e.g. by stripping the corresponding credentials from
> requests).
>
> If not done correctly, **this could leave your system vulnerable to HPP
> attacks**, where different credentials are retrieved in different ways by
> different components of your system.
>
> Credential sources not supported by this plugin could include e.g.
> non-standard headers (see the `client-headers` option), cookies, non-standard
> query parameters or non-standard request body.

**`header`**

Optional, defaults to `Authorization`.

Specifies the header that gets propagated with the Basic credentials, or the
Bearer token (see the `apikey` option). The header name is case-insensitive,
and an invalid name makes the configuration fail to load. An empty value
disables header propagation and response rewriting. The Subsonic authentication
parameters still get validated and removed from the forwarded request, except
for API keys with `apikey: passthrough`.

If you log request headers in Traefik's access log, drop or redact this header:
Traefik reads them after the plugin has set them.

> [!CAUTION]
>
> When this plugin is used in proxy authentication mode (see the `auth` option)
> together with a third-party authentication service (e.g. using Traefik's
> ForwardAuth middleware), make sure to remove the header after the
> authentication and before forwarding the request to the backend to prevent the
> credentials from leaking to the backend.
>
> Traefik's architecture makes it impossible to handle this from this plugin so
> you have to do it yourself.

**`client-headers`**

Optional, defaults to `Authorization`.

Specifies client headers that can contain Basic credentials. You can specify
multiple headers by separating them with commas and/or whitespace. Header names
are case-insensitive, and an invalid name makes the configuration fail to load.

Credentials in these headers are validated and stripped from the request before
it gets forwarded to the Subsonic server. To avoid HPP vulnerabilities, the list
should contain at least all BasicAuth headers supported by your Subsonic server,
unless you remove them using another middleware.

**`apikey`**

Optional, one of `reject` (the default), `bearer` or `passthrough`.

Specifies how the `apiKey` parameter from the [API key extension][os-apikey] is
handled:

* `reject`: requests with an API key are rejected.
* `bearer`: the key is propagated as a Bearer token (`Authorization: Bearer
  <key>` with the default `header`). Your authentication service, or your
  Subsonic server in backend authentication mode, must accept the key as a
  Bearer token.
* `passthrough`: the key is forwarded to your Subsonic server in the `apiKey`
  parameter. Only allowed in backend authentication mode; meant for Subsonic
  servers that support the API key extension.

Clients must send the key in the `apiKey` parameter (query or POST body), as
the API key extension specifies, and without any other credentials. Bearer
tokens sent by clients in headers are not treated as API keys.

With `bearer`, the key must be a valid Bearer token (see [Restrictions on
Subsonic credentials](#restrictions-on-subsonic-credentials)). In proxy
authentication mode, authentication failures are reported to clients as an
invalid API key.

With `passthrough`, your Subsonic server gets a single copy of the key, even if
the client sent it in both the query and the POST body. The key goes:

* in the POST body if the request is a POST with the
  `application/x-www-form-urlencoded` content type, even if the body is empty or
  the client sent the key in the query.
* in the query otherwise. The request's method and content type aren't changed,
  so **the key can appear in downstream logs**.

The `passthrough` mode isn't allowed in proxy authentication mode, because the
authentication service would get no credentials in the header and is not
expected to look for the `apiKey` parameter. It could reject every request with
an API key, or worse, authenticate it through something else, such as the
session cookie of a single sign-on service (see the caution about CSRF under the
`anonymous` option).

> [!IMPORTANT]
>
> Clients are expected to use API keys only if the server lists the
> `apiKeyAuthentication` extension in its `getOpenSubsonicExtensions` response,
> which this plugin doesn't modify. If your Subsonic server doesn't support API
> keys but your authentication service does, you have to rewrite that response
> yourself to add the extension.
>
> Clients that query that endpoint before the user has logged in may need the
> `anonymous` option.

**`anonymous`**

Optional, either `reject` (the default) or `forward`.

Specifies how requests without credentials are handled:

* `reject`: requests without credentials are rejected with error 40. The
  Subsonic API has no public endpoints.
* `forward`: requests without credentials are forwarded without the header (see
  the `header` option). Your authentication service, or your Subsonic server in
  backend authentication mode, decides which endpoints are public and rejects
  requests to the others.

The `forward` mode is meant for endpoints that OpenSubsonic requires to be
public, such as the extensions endpoint (`getOpenSubsonicExtensions`), which
clients can query before the user has logged in.

> [!TIP]
>
> You should leave this option at its default, `reject`, unless one of your
> clients needs the extensions endpoint to be public. With `reject`, a client
> that queries the endpoint before logging in gets error 40, and may conclude
> that the server has no extensions or does not support OpenSubsonic.
>
> See [OpenSubsonic's public extensions
> endpoint](#opensubsonics-public-extensions-endpoint) for why this plugin
> doesn't follow the spec by default.

A request has no credentials only if none of the parameters and headers that the
plugin reads credentials from is present, even with an empty value: no `u`, `p`,
`t`, `s` or `apiKey` parameter in the query or the POST body, and none of the
headers in `client-headers`. Requests with empty, incomplete or invalid
credentials are still rejected.

In proxy authentication mode, your authentication service must:

* let requests to the public endpoints through. Traefik's BasicAuth middleware
  can't exempt paths, so it can't be used with the `forward` mode.
* answer requests to the other endpoints with status 401, 403 or 407, which the
  plugin rewrites into a Subsonic error. Many single sign-on services redirect
  requests without credentials to their login page instead, which Subsonic
  clients can't handle and this plugin can't reliably rewrite.

> [!CAUTION]
>
> With `forward`, make sure that nothing downstream authenticates a request
> without Subsonic credentials through credentials that browsers send on their
> own, such as the session cookie of a single sign-on service.
>
> Otherwise, other websites can make the browser of a logged-in user send
> Subsonic API requests as that user (CSRF). The Subsonic API changes data with
> GET requests, so following a link can be enough. With JSONP responses
> (`f=jsonp`), pages on your other subdomains, or any website if the cookie is
> `SameSite=None`, can also read the responses.
>
> In `reject` mode, every request carries the header with Subsonic credentials,
> which other websites don't know. With `forward`, when the header is missing,
> authentication services commonly fall back to the cookie.
>
> You can for example remove the `Cookie` header with a Headers middleware (an
> empty value in `customRequestHeaders` removes the header), or, in proxy
> authentication mode, list only the headers your authentication service needs
> in the ForwardAuth middleware's `authRequestHeaders` option.

## Debug logs

The plugin writes debug logs, which Traefik only shows when its log level is
set to `DEBUG` (e.g. `--log.level=DEBUG`). Each line is prefixed with the
middleware's name. Debug logs should not contain sensitive data related to
subsonic, but they do include the username.

The former `debug` option has been removed and is ignored if still present in
your configuration.

## Examples

**Backend authentication**

```yaml
# On your subsonic service
labels:
    traefik.http.routers.subsonic.rule: Host(`subsonic.example.com`) && PathPrefix(`/rest/`)
    traefik.http.routers.subsonic.middlewares: subsonicauth-sub2basic@docker

    traefik.http.middlewares.subsonicauth-sub2basic.plugin.subsonic-basicauth.auth: backend
```

**Proxy authentication**

In this scenario, the Subsonic backend still needs to know which user is making
the request. This will depend on your Subsonic server, and the integration is
not shown here.

Note that in this scenario you should avoid forwarding the BasicAuth header
as-is to the Subsonic server, as it shouldn't need to get the user's password.

```yaml
# On your authentication service
labels:
    # Your BasicAuth service, e.g. a BasicAuth or ForwardAuth middleware
    traefik.http.middlewares.authservice-basicauth.[...]

    # The subsonicauth middleware that should be mapped on your routes
    traefik.http.middlewares.authservice-subsonicauth.chain.middlewares: subsonicauth-sub2basic@docker,authservice-basicauth@docker,subsonicauth-cleanup@docker

    # Supporting middlewares
    traefik.http.middlewares.subsonicauth-sub2basic.plugin.subsonic-basicauth.auth: proxy
    traefik.http.middlewares.subsonicauth-sub2basic.plugin.subsonic-basicauth.header: Authorization
    traefik.http.middlewares.subsonicauth-cleanup.headers.customrequestheaders.Authorization: # empty removes the header
```

```yaml
# On your subsonic service
labels:
    traefik.http.routers.subsonic.rule: Host(`subsonic.example.com`) && PathPrefix(`/rest/`)
    traefik.http.routers.subsonic.middlewares: authservice-subsonicauth@docker
```


[os-api-auth]: https://github.com/opensubsonic/open-subsonic-api/discussions/25
[os-apikey]: https://opensubsonic.github.io/docs/extensions/apikeyauth/
