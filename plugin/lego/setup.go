package lego

import (
	"github.com/coredns/caddy"
	"github.com/coredns/coredns/core/dnsserver"
	"github.com/coredns/coredns/plugin"
)

func init() {
	caddy.RegisterPlugin("lego", caddy.Plugin{
		ServerType: "dns",
		Action:     setup,
	})
}

func setup(c *caddy.Controller) error {
	l, err := legoParse(c)
	if err != nil {
		return plugin.Error("lego", err)
	}

	l.Domain = dnsserver.GetConfig(c).Zone

	// Ensure certificates exist (even if placeholders) so the tls plugin setup passes.
	if err := l.EnsureCerts(); err != nil {
		return plugin.Error("lego", err)
	}

	c.OnStartup(func() error {
		return l.OnStartup()
	})

	dnsserver.GetConfig(c).AddPlugin(func(next plugin.Handler) plugin.Handler {
		l.Next = next
		return l
	})

	return nil
}

func legoParse(c *caddy.Controller) (*Lego, error) {
	l := New()

	for c.Next() {
		args := c.RemainingArgs()
		if len(args) > 0 {
			l.Email = args[0]
		}

		for c.NextBlock() {
			switch c.Val() {
			case "email":
				if !c.NextArg() {
					return nil, c.ArgErr()
				}
				l.Email = c.Val()
			case "acme_dir":
				if !c.NextArg() {
					return nil, c.ArgErr()
				}
				l.ACMEDir = c.Val()
			case "cert_dir":
				if !c.NextArg() {
					return nil, c.ArgErr()
				}
				l.CertDir = c.Val()
			default:
				return nil, c.Errf("unknown property '%s'", c.Val())
			}
		}
	}

	if l.Email == "" {
		return nil, c.Err("email is required for lego")
	}

	return l, nil
}
