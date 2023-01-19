// Copyright (C) 2022, 2023 - Tillitis AB
// SPDX-License-Identifier: GPL-2.0-only

package main

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v2"
)

type Config struct {
	CACert     string `yaml:"cacert"`
	ServerCert string `yaml:"servercert"`
	ServerKey  string `yaml:"serverkey"`
	ClientCert string `yaml:"clientcert"`
	ClientKey  string `yaml:"clientkey"`
	ListenAddr string `yaml:"listen"`
	ServerAddr string `yaml:"server"`
}

func loadServeSignerConfig(fn string) Config {
	conf, err := loadConfig(fn)
	if err != nil {
		le.Printf("%s\n", err)
		os.Exit(1)
	}
	if conf.ClientCert != "" || conf.ClientKey != "" || conf.ServerAddr != "" {
		le.Printf("Command is \"serve-signer\", but found clientcert/clientkey/server in config file.\n")
		os.Exit(1)
	}
	return conf
}

func loadRemoteSignConfig(fn string) Config {
	conf, err := loadConfig(fn)
	if err != nil {
		le.Printf("%s\n", err)
		os.Exit(1)
	}
	if conf.ServerCert != "" || conf.ServerKey != "" || conf.ListenAddr != "" {
		le.Printf("Command is \"remote-sign\", but found servercert/serverkey/listen in config file.\n")
		os.Exit(1)
	}
	return conf
}

func loadConfig(fn string) (Config, error) {
	var conf Config

	rawConfig, err := os.ReadFile(fn)
	if err != nil {
		return conf, fmt.Errorf("ReadFile failed: %w", err)
	}

	err = yaml.Unmarshal(rawConfig, &conf)
	if err != nil {
		return conf, fmt.Errorf("Unmarshal failed: %w", err)
	}

	return conf, nil
}
