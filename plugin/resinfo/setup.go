package resinfo

import (
	"github.com/coredns/caddy"
	"github.com/coredns/coredns/core/dnsserver"
	"github.com/coredns/coredns/plugin"
	"github.com/oschwald/maxminddb-golang"
)

func init() {
	caddy.RegisterPlugin("resinfo", caddy.Plugin{
		ServerType: "dns",
		Action:     setup,
	})
}

func setup(c *caddy.Controller) error {
	ri, err := resinfoParse(c)
	if err != nil {
		return plugin.Error("resinfo", err)
	}

	ri.Zone = dnsserver.GetConfig(c).Zone

	dnsserver.GetConfig(c).AddPlugin(func(next plugin.Handler) plugin.Handler {
		ri.Next = next
		return ri
	})

	return nil
}

func resinfoParse(c *caddy.Controller) (*ResInfo, error) {
	ri := New()

	for c.Next() {
		args := c.RemainingArgs()
		if len(args) > 0 {
			ri.Link = args[0]
		}

		for c.NextBlock() {
			key := c.Val()
			switch key {
			case "asn_db", "asn_v4", "asn_v6":
				if !c.NextArg() { return nil, c.ArgErr() }
				db, err := maxminddb.Open(c.Val())
				if err != nil { return nil, err }
				if key == "asn_v6" { ri.ASNv6Reader = db } else { ri.ASNv4Reader = db }
			default:
				return nil, c.Errf("unknown property '%s'", key)
			}
		}
	}

	return ri, nil
}
