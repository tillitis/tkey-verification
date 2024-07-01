// Copyright (C) 2022, 2023 - Tillitis AB
// SPDX-License-Identifier: GPL-2.0-only

package main

import (
	"crypto/tls"
	"net"
	"os"

	"gopkg.in/yaml.v2"
)

type Server struct {
	Addr      string
	TLSConfig tls.Config
}

type Config struct {
	CACert               string `yaml:"cacert"`
	ServerCert           string `yaml:"servercert"`
	ServerKey            string `yaml:"serverkey"`
	ClientCert           string `yaml:"clientcert"`
	ClientKey            string `yaml:"clientkey"`
	ListenAddr           string `yaml:"listen"`
	ServerAddr           string `yaml:"server"`
	VendorSigningAppHash string `yaml:"vendorapphash"`
}

func loadServeSignerConfig(fn string) Config {
	conf, err := loadConfig(fn)
	if err != nil {
		le.Printf("loading config failed: %s\n", err)
		os.Exit(1)
	}
	if conf.ClientCert != "" || conf.ClientKey != "" || conf.ServerAddr != "" {
		le.Printf("Command is \"serve-signer\", but found clientcert/clientkey/server in config file.\n")
		os.Exit(1)
	}
	return conf
}

func loadRemoteSignConfig(fn string) *Server {
	conf, err := loadConfig(fn)
	if err != nil {
		le.Printf("%s\n", err)
		os.Exit(1)
	}
	if conf.ServerCert != "" || conf.ServerKey != "" || conf.ListenAddr != "" {
		le.Printf("Command is \"remote-sign\", but found servercert/serverkey/listen in config file.\n")
		os.Exit(1)
	}

	var server Server

	server.TLSConfig = tls.Config{
		Certificates: []tls.Certificate{
			loadCert(conf.ClientCert, conf.ClientKey),
		},
		RootCAs:    loadCA(conf.CACert),
		MinVersion: tls.VersionTLS13,
	}

	_, _, err = net.SplitHostPort(conf.ServerAddr)
	if err != nil {
		le.Printf("Config server: %s", err)
		os.Exit(1)
	}

	server.Addr = conf.ServerAddr

	return &server
}

func loadConfig(fn string) (Config, error) {
	var conf Config

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
