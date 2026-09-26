package geo

import (
	"fmt"
	"net/netip"

	"github.com/oschwald/maxminddb-golang"
)

type Location struct {
	Latitude     float64 `json:"latitude"`
	Longitude    float64 `json:"longitude"`
	AccuracyKM   uint16  `json:"accuracy_km"`
	City         string  `json:"city,omitempty"`
	Country      string  `json:"country,omitempty"`
	ASN          uint    `json:"asn,omitempty"`
	Organization string  `json:"organization,omitempty"`
}

type Lookup struct{ city, asn *maxminddb.Reader }

func Open(cityPath, asnPath string) (*Lookup, error) {
	city, err := maxminddb.Open(cityPath)
	if err != nil {
		return nil, fmt.Errorf("open City database: %w", err)
	}
	result := &Lookup{city: city}
	if asnPath != "" {
		result.asn, err = maxminddb.Open(asnPath)
		if err != nil {
			city.Close()
			return nil, fmt.Errorf("open ASN database: %w", err)
		}
	}
	return result, nil
}

func (l *Lookup) Close() error {
	if l.asn != nil {
		_ = l.asn.Close()
	}
	return l.city.Close()
}

func (l *Lookup) Find(ip netip.Addr) *Location {
	if !ip.IsGlobalUnicast() || ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() {
		return nil
	}
	var city struct {
		Location struct {
			Latitude  float64 `maxminddb:"latitude"`
			Longitude float64 `maxminddb:"longitude"`
			Accuracy  uint16  `maxminddb:"accuracy_radius"`
		} `maxminddb:"location"`
		City struct {
			Names map[string]string `maxminddb:"names"`
		} `maxminddb:"city"`
		Country struct {
			ISO string `maxminddb:"iso_code"`
		} `maxminddb:"country"`
	}
	if err := l.city.Lookup(ip.AsSlice(), &city); err != nil || city.Country.ISO == "" {
		return nil
	}
	result := &Location{Latitude: city.Location.Latitude, Longitude: city.Location.Longitude,
		AccuracyKM: city.Location.Accuracy, City: city.City.Names["en"], Country: city.Country.ISO}
	if l.asn != nil {
		var asn struct {
			Number       uint   `maxminddb:"autonomous_system_number"`
			Organization string `maxminddb:"autonomous_system_organization"`
		}
		if l.asn.Lookup(ip.AsSlice(), &asn) == nil {
			result.ASN, result.Organization = asn.Number, asn.Organization
		}
	}
	return result
}
