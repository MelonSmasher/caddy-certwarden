# caddy-certwarden

A [Caddy](https://caddyserver.com) TLS certificate manager that serves
certificates from [Cert Warden](https://www.certwarden.com) — **cached in memory
and refreshed in the background**, so the TLS handshake path never makes a
network call.

Module ID: `tls.get_certificate.certwarden`

## Why

Caddy's built-in `tls.get_certificate.http` manager is called by certmagic on
**every TLS handshake** and does not cache its result, so pointing it at Cert
Warden means one backend request per handshake. On a busy proxy fronting many
hosts, that doesn't scale.[^1]

[^1]: certmagic does not add a `get_certificate` manager's result to its
    certificate cache (see the lookup order in `certmagic`'s `handshake.go`), so
    every full handshake re-invokes the manager. It does coalesce *concurrent*
    lookups for the same name into one in-flight call, and TLS session
    resumption skips the callback — but distinct hosts and fresh handshakes each
    hit the backend.

`caddy-certwarden` fetches each certificate from Cert Warden **once**, keeps it
in memory, and refreshes it in the background:

- **No per-handshake I/O** — handshakes are served from an in-memory cache (a
  lock-guarded map lookup).
- **Background refresh** ahead of expiry, and on a configurable interval so
  early rotations are picked up quickly.
- **Serves through outages** — a failed refresh keeps serving the last-known
  certificate until it actually expires; an optional on-disk cache survives
  restarts even when Cert Warden is unreachable.
- **Automatic SNI matching** from each certificate's SANs (exact + single-label
  wildcard), with an optional per-certificate override.

Names it doesn't manage are passed through, so it composes with Caddy's other
certificate sources.

## Installation

### Prebuilt Docker image

```bash
docker pull ghcr.io/melonsmasher/caddy-certwarden:latest
# or
docker pull melonsmasher/caddy-certwarden:latest
```

Use it directly, or as a base for an image with your own config/plugins:

```dockerfile
FROM ghcr.io/melonsmasher/caddy-certwarden:latest
COPY Caddyfile /etc/caddy/Caddyfile
```

#### Image variants

Two variants are published for every tag below, differing only in the plugins
compiled in:

| Image | Plugins | Use when |
|-------|---------|----------|
| `caddy-certwarden` | the certwarden manager only | you just need Cert Warden certificates |
| `caddy-certwarden-cache` | certwarden **+** the [Souin](https://github.com/darkweak/souin) `cache-handler` and its storage backends (redis, badger, etcd, nuts, olric, nats, otter, simplefs) | the proxy also does HTTP response caching |

```bash
docker pull ghcr.io/melonsmasher/caddy-certwarden-cache:latest
# or
docker pull melonsmasher/caddy-certwarden-cache:latest
```

Images are published for `linux/amd64` and `linux/arm64`, and are built against
the last few Caddy release lines. Tags let you pin as loosely or tightly as you
like:

| Tag | Points at |
|-----|-----------|
| `latest` | newest plugin release on the newest supported Caddy |
| `caddy2` | newest plugin release on the newest supported Caddy 2.x |
| `caddy2.11` | newest plugin release on the latest patch of Caddy 2.11 |
| `caddy2.11.4` | newest plugin release built against Caddy 2.11.4 exactly |
| `0.1.0-caddy2.11.4` | immutable: plugin v0.1.0 built against Caddy 2.11.4 |

Pin `caddy2` to track the Caddy 2 line, `caddy2.11` for a specific minor, or a
specific `X.Y.Z-caddyA.B.C` to pin exactly; use `latest` to always track the
newest of both.

### Build with xcaddy

```bash
xcaddy build --with github.com/MelonSmasher/caddy-certwarden
```

## Quick start (Caddyfile)

Attach the manager with the `tls` directive's `get_certificate` option. This
tells Caddy to obtain the certificate from Cert Warden instead of managing it
itself.

```caddyfile
app.example.com, api.example.com {
    tls {
        get_certificate certwarden {
            base_url         {env.CW_BASE_URL}
            cache_dir        /var/lib/caddy/certwarden
            certificate      app-cert {env.CW_APP_KEY}
            certificate      api-cert {env.CW_API_KEY}
        }
    }
    reverse_proxy upstream:8080
}
```

Each `certificate` line is:

```
certificate <cert-warden-name> <api-key> [subject ...]
```

`<api-key>` is the **combined** `<cert-api-key>.<private-key-api-key>` value (see
[Getting the certificate name and API key](#getting-the-certificate-name-and-api-key)).
With no trailing subjects, the certificate is served for the DNS SANs it
contains. Add subjects to override that (for example, to serve a certificate for
a name that isn't in its SANs).

## Configuration reference

| Option | Default | Description |
|--------|---------|-------------|
| `base_url` | *(required)* | Cert Warden root URL, e.g. `https://certwarden.example.com`. |
| `certificate` / `certificates` | *(required)* | One or more certificates to serve: name, API key, optional subjects. |
| `api_path` | `/certwarden/api/v1/download/privatecertchains` | Download path; the certificate name is appended. Override only if your Cert Warden version differs (see below). |
| `refresh_interval` | `12h` | Upper bound on how often each certificate is re-fetched (it is also refreshed earlier as it approaches expiry). |
| `http_timeout` | `30s` | Per-request timeout to Cert Warden. |
| `cache_dir` | *(disabled)* | Directory for an on-disk certificate cache (`0600` files) so certificates survive restarts during a Cert Warden outage. |
| `fail_closed` | `false` | If set, startup fails when the initial fetch fails, instead of starting and retrying in the background. |
| `trusted_roots` | *(system pool)* | Additional PEM root file(s) to trust when connecting to Cert Warden. |

`base_url` and each `api_key` accept `{env.VAR}` placeholders (resolved at
provision time), so you can keep them out of the config file — use them for API
keys rather than inlining secrets.

### JSON

The manager is a `get_certificate` entry on a TLS automation policy
(`apps.tls.automation.policies[].get_certificate`), selected by `via`:

```json
{
  "apps": {
    "tls": {
      "automation": {
        "policies": [
          {
            "get_certificate": [
              {
                "via": "certwarden",
                "base_url": "{env.CW_BASE_URL}",
                "cache_dir": "/var/lib/caddy/certwarden",
                "certificates": [
                  { "name": "app-cert", "api_key": "{env.CW_APP_KEY}" },
                  { "name": "api-cert", "api_key": "{env.CW_API_KEY}", "subjects": ["legacy.example.com"] }
                ]
              }
            ]
          }
        ]
      }
    }
  }
}
```

## Getting the certificate name and API key

In Cert Warden, create a certificate (issued by any ACME account it manages —
Let's Encrypt, an internal step-ca, and so on). For each certificate you want to
serve:

- **name** — the certificate's **Name** in Cert Warden (this can differ from the
  certificate's subject/hostname; the download uses the Name).
- **api key** — because this plugin needs the **private key**, the download is
  authorized by a **combined** key: the certificate's API key and its private
  key's API key, joined by a period:

  ```
  <certificate-api-key>.<private-key-api-key>
  ```

  Both keys are shown in the Cert Warden UI — one on the certificate, one on its
  linked private key. Use the combined value as the plugin's `api_key`.

The plugin sends that combined key as the `X-API-Key` header to the
private-cert-chain download endpoint. Cert Warden handles issuance and renewal;
this plugin distributes and caches the result.

> **Note:** if your Cert Warden version serves that download at a different path
> than the default, copy the path from the download URL shown in its UI and set
> `api_path` accordingly (the certificate name is appended to it).

## How it works

1. On startup the plugin loads any on-disk cache, then fetches each configured
   certificate once. Unless `fail_closed` is set, fetch errors are logged and
   retried in the background rather than blocking startup.
2. On each handshake, the SNI is matched against an in-memory index built from
   the certificates' SANs (and any explicit subjects). Unmanaged names pass
   through to Caddy's other certificate sources.
3. A background task refreshes each certificate at two-thirds of its lifetime or
   every `refresh_interval`, whichever comes first, keeping the previous
   certificate if a refresh fails.

## Compatibility

Requires **Caddy 2.10 or newer**. Prebuilt images are published for the most
recent Caddy v2 release lines (see the tags above); building with `xcaddy` tracks
whichever Caddy v2 you build against, as long as it's ≥ 2.10.

The floor is 2.10 because Caddy 2.9 ships an older `certmagic`/`libdns` that is no
longer API-compatible with the current module graph. The minimum is declared by
the `caddyserver/caddy/v2` version in [`go.mod`](go.mod); CI reads it and builds
only Caddy lines at or above it.

## Development

```bash
go test -race ./...                                   # unit tests
xcaddy build --with github.com/MelonSmasher/caddy-certwarden=.   # build from a checkout
```

Issues and pull requests are welcome.

## License

Apache-2.0. See [LICENSE](LICENSE).
