# Traefik plugin to use BasicAuth with Subsonic

This Traefik plugin transforms Subsonic authentication parameters into a
BasicAuth header.

In front of a ForwardAuth service, it lets you integrate into your existing
authentication infrastructure Subsonic clients that only support the standard
Subsonic authentication scheme.

In front of a Subsonic server that supports BasicAuth or some other
authentication scheme, it lets you remove sensitive query parameters to
reduce the risk of exposing them in logs.

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
