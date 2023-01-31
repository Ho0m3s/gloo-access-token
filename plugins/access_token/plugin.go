package main

import (
	impl "github.com/Ho0m3s/gloo-access-token/plugins/access_token/pkg"
	"github.com/solo-io/ext-auth-plugins/api"
)

func main() {}

// Compile-time assertion
var _ api.ExtAuthPlugin = new(impl.AccessTokenPlugin)

// This is the exported symbol that Gloo will look for.
//noinspection GoUnusedGlobalVariable
var Plugin impl.AccessTokenPlugin
