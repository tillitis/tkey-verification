// SPDX-FileCopyrightText: 2022 Tillitis AB <tillitis.se>
// SPDX-License-Identifier: BSD-2-Clause

package main

import (
	"crypto/tls"
	"fmt"
	"os"

	"gopkg.in/yaml.v2"
)

type Server struct {
	Addr      string
	TLSConfig tls.Config
}

type ServerConfig struct {
	CACert     string `yaml:"cacert"`
	ServerCert string `yaml:"servercert"`
	ServerKey  string `yaml:"serverkey"`
	ListenAddr string `yaml:"listen"`
	ActiveKey  string `yaml:"activekey"`
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
		return conf, fmt.Errorf("couldn't read config file: %w", err)
	}

	err = yaml.Unmarshal(rawConfig, &conf)
	if err != nil {
		return conf, fmt.Errorf("parse error in config file: %w", err)
	}

	return conf, nil
}

func loadRemoteSignConfig(fn string) (ProvConfig, error) {
	var conf ProvConfig

	rawConfig, err := os.ReadFile(fn)
	if err != nil {
		return conf, fmt.Errorf("couldn't read config file: %w", err)
	}

	err = yaml.Unmarshal(rawConfig, &conf)
	if err != nil {
		return conf, fmt.Errorf("parse error in config file: %w", err)
	}

	return conf, nil
}
