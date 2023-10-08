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
old subsonic scheme is not ideal, but if the connection is made over HTTPS it is
similar in principle to authentication mechanisms you find on most websites,
with the following caveats:
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

Note that the OpenSubsonic initiative is working on adding support for a modern
authentication scheme to the subsonic protocol (cf. [os-api-auth]), with support
from authors of actively maintained clients and servers. You are encouraged to
stop using this plugin (and stop supporting the legacy Subsonic schemes
altogether) once a consensus has been reached and clients and servers adopt the
new scheme.


[os-api-auth]: https://github.com/opensubsonic/open-subsonic-api/discussions/25


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

**`header`**

Optional, defaults to `Authorization`.

Specifies the header that gets propagated with the Basic credentials. An empty
value disables header propagation and response rewriting. The Subsonic
authentication parameters still get validated and removed from the forwarded
request.

**`debug`**

Optional, defaults to `false`.

Controls whether debug logs are produced. Debug logs should not contain
sensitive data related to subsonic.

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
