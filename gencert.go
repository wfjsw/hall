// Copyright (c) 2011 The Grumble Authors
// The use of this source code is goverened by a BSD-style
// license that can be found in the LICENSE-file.

package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"log"
	"math/big"
	"os"
	"path/filepath"
	"time"
)

// Generate a 4096-bit RSA keypair and a Grumble auto-generated X509
// certificate. Output PEM-encoded DER representations of the resulting
// certificate and private key to certpath and keypath.
func GenerateSelfSignedCert(certpath, keypath string) (err error) {
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(0),
		Subject: pkix.Name{
			CommonName: "Mumble Server",
		},
		NotBefore: now.Add(-300 * time.Second),
		// Valid for 1 year.
		NotAfter: now.Add(24 * time.Hour * 3650),

		SubjectKeyId: []byte{1, 2, 3, 4},
		KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
	}

	priv, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return err
	}

	certbuf, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		log.Printf("Error: %v", err)
		return err
	}
	certblk := pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certbuf,
	}

	keybuf := x509.MarshalPKCS1PrivateKey(priv)
	keyblk := pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: keybuf,
	}

	certfn := filepath.Join(certpath)
	file, err := os.OpenFile(certfn, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0700)
	if err != nil {
		return err
	}
	defer file.Close()
	err = pem.Encode(file, &certblk)
	if err != nil {
		return err
	}

	keyfn := filepath.Join(keypath)
	file, err = os.OpenFile(keyfn, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0700)
	if err != nil {
		return err
	}
	defer file.Close()
	err = pem.Encode(file, &keyblk)
	if err != nil {
		return err
	}

	return nil
}
