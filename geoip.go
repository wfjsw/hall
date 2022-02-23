package main

import (
	"crypto/tls"
	"encoding/json"
	"io/ioutil"
	"net"
	"net/http"
	"time"
)

// GeoIPResult describe a GeoIP entry
type GeoIPResult struct {
	IP            string  `json:"ip"`
	CountryCode   string  `json:"country_code"`
	Country       string  `json:"country"`
	ContinentCode string  `json:"continent_code"`
	Latitude      float64 `json:"latitude"`
	Longitude     float64 `json:"longitude"`
	ASNumber      int     `json:"asn"`
	Organization  string  `json:"organization"`
	Timezone      string  `json:"timezone"`
}

func lookupIPAddress(ip net.IP) (result *GeoIPResult, err error) {
	apiURL := "https://api.ip.sb/geoip/"
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: false},
	}

	client := &http.Client{
		Transport: tr,
		Timeout:   15 * time.Second,
	}
	req, _ := http.NewRequest("GET", apiURL+ip.String(), nil)
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}

	defer resp.Body.Close()

	content, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	resultdata := new(GeoIPResult)
	err = json.Unmarshal(content, resultdata)
	if err != nil {
		return nil, err
	}

	return resultdata, nil
}
