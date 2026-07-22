// Package caddycertwarden is the module entrypoint for the Caddy certwarden
// certificate manager.
//
// The implementation lives in the ./certwarden subpackage. Importing this root
// package — which is what `xcaddy build --with github.com/MelonSmasher/caddy-certwarden`
// does — pulls in that subpackage and registers the Caddy module via its init().
package caddycertwarden

import _ "github.com/MelonSmasher/caddy-certwarden/certwarden"
