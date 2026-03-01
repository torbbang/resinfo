package main

import (
	_ "github.com/coredns/coredns/core/dnsserver"
	_ "github.com/coredns/coredns/plugin/any"
	_ "github.com/coredns/coredns/plugin/bind"
	_ "github.com/coredns/coredns/plugin/debug"
	_ "github.com/coredns/coredns/plugin/errors"
	_ "github.com/coredns/coredns/plugin/file"
	_ "github.com/coredns/coredns/plugin/forward"
	_ "github.com/coredns/coredns/plugin/health"
	_ "github.com/coredns/coredns/plugin/loadbalance"
	_ "github.com/coredns/coredns/plugin/log"
	_ "github.com/coredns/coredns/plugin/metrics"
	_ "github.com/coredns/coredns/plugin/ready"
	_ "github.com/coredns/coredns/plugin/reload"
	_ "github.com/coredns/coredns/plugin/tls"
	_ "github.com/coredns/coredns/plugin/whoami"

	// Register custom plugins here
	_ "torbbang/resinfo/plugin/lego"
	_ "torbbang/resinfo/plugin/resinfo"

	"github.com/coredns/coredns/core/dnsserver"
	"github.com/coredns/coredns/coremain"
)

func init() {
	var dnsserverDirectives = []string{
		"debug",
		"lego",
		"tls",
		"reload",
		"health",
		"errors",
		"log",
		"resinfo", // Insert our plugin here
		"file",
		"whoami",
		"bind",
		"any",
		"metrics",
		"forward",
		"ready",
		"loadbalance",
	}
	dnsserver.Directives = dnsserverDirectives
}

func main() {
	coremain.Run()
}
