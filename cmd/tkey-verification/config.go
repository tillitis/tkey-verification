// Copyright (C) 2022-2024 - Tillitis AB
// SPDX-License-Identifier: BSD-2-Clause

package main

import (
	"crypto/tls"
	"os"

	"gopkg.in/yaml.v2"
)

type Server struct {
	Addr      string
	TLSConfig tls.Config
}

type ServerConfig struct {
	CACert               string `yaml:"cacert"`
	ServerCert           string `yaml:"servercert"`
	ServerKey            string `yaml:"serverkey"`
	ListenAddr           string `yaml:"listen"`
	VendorSigningAppHash string `yaml:"vendorapphash"`
}

type ProvConfig struct {
	CACert         string `yaml:"cacert"`
	ClientCert     string `yaml:"clientcert"`
	ClientKey      string `yaml:"clientkey"`
	ServerAddr     string `yaml:"server"`
	SigningAppHash string `yaml:"signingapphash"`
}

func loadServeSignerConfig(fn string) (ServerConfig, error) {
	var conf ServerConfig

	rawConfig, err := os.ReadFile(fn)
	if err != nil {
		return conf, IOError{path: fn, err: err}
	}

	err = yaml.Unmarshal(rawConfig, &conf)
	if err != nil {
		return conf, ParseError{what: "config", err: err}
	}

	return conf, nil
}

func loadRemoteSignConfig(fn string) (ProvConfig, error) {
	var conf ProvConfig

	rawConfig, err := os.ReadFile(fn)
	if err != nil {
		return conf, IOError{path: fn, err: err}
	}

	err = yaml.Unmarshal(rawConfig, &conf)
	if err != nil {
		return conf, ParseError{what: "config", err: err}
	}

	return conf, nil
}
