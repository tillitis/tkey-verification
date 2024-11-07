// SPDX-FileCopyrightText: 2023 Tillitis AB <tillitis.se>
// SPDX-License-Identifier: BSD-2-Clause

package main

import (
	"crypto/tls"
	"crypto/x509"
	"os"
)

func loadCA(certFile string) *x509.CertPool {
	caPEM, err := os.ReadFile(certFile)
	if err != nil {
		le.Printf("ReadFile failed: %s", err)
		os.Exit(1)
	}
	certPool := x509.NewCertPool()
	if !certPool.AppendCertsFromPEM(caPEM) {
		le.Printf("Append CA failed: %s", err)
		os.Exit(1)
	}
	return certPool
}

func loadCert(certFile string, keyFile string) tls.Certificate {
	serverCert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		le.Printf("Load cert failed: %s", err)
		os.Exit(1)
	}
	return serverCert
}
