# Traefik plugin to use BasicAuth with Subsonic

This Traefik plugin transforms Subsonic authentication parameters into a
BasicAuth header.

In front of a ForwardAuth service, it lets you integrate into your existing
authentication infrastructure Subsonic clients that only support the standard
Subsonic authentication scheme.

In front of a Subsonic server that supports BasicAuth or some other
authentication scheme, it lets you remove sensitive query parameters to
reduce the risk of exposing them in logs.
