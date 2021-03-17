package access

import (
	"context"
	"regexp"

	"github.com/mendersoftware/go-lib-micro/addons"
	hdr "github.com/mendersoftware/go-lib-micro/context/httpheader"
	"github.com/mendersoftware/go-lib-micro/identity"
	"github.com/pkg/errors"
)

const (
	hdrForwardedMethod = "X-Forwarded-Method"
	hdrForwardedURI    = "X-Forwarded-Uri"

	regexDeviceconnectURI = "^/api/devices/v[1-9]/deviceconnect"
	regexDeviceconfigURI  = "^/api/devices/v[1-9]/deviceconfig"
)

type addonRule struct {
	// URI regex for the restricted resource
	URI *regexp.Regexp
	// Methods to which the rule applies (nil means ALL)
	Methods []string
	// Name gives the name of the addon the feature belongs to
	Name string
}

var addonRules = []addonRule{{
	Name: addons.MenderTroubleshoot,
	URI:  regexp.MustCompile(regexDeviceconnectURI),
}, {
	Name: addons.MenderConfigure,
	URI:  regexp.MustCompile(regexDeviceconfigURI),
}}

type addonChecker struct{}

func NewAddonChecker() Checker {
	return new(addonChecker)
}

func (c addonChecker) ValidateWithContext(ctx context.Context) error {
	method := hdr.FromContext(ctx, hdrForwardedMethod)
	URI := hdr.FromContext(ctx, hdrForwardedURI)
	id := identity.FromContext(ctx)
	if id == nil {
		return errors.New("missing tenant context")
	}

	for _, rule := range addonRules {
		if rule.Methods != nil {
			var applies bool = false
			for _, m := range rule.Methods {
				if m == method {
					applies = true
					break
				}
			}
			if !applies {
				continue
			}
		}
		if !rule.URI.MatchString(URI) {
			continue
		}
		// The rule matches, check if the addon permits it
		var enabled bool = false
		for _, addon := range id.Addons {
			if addon.Name == rule.Name {
				if addon.Enabled {
					enabled = true
				}
				break
			}
		}
		if !enabled {
			return PermissionError{
				error: errors.Errorf(
					"operation requires addon: %s",
					rule.Name,
				),
			}
		}
	}
	return nil
}
