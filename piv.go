// {{{ Copyright (c) Paul R. Tagliamonte <paultag@gmail.com>, 2019
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
// THE SOFTWARE. }}}

package main

import (
	"fmt"

	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/asn1"

	"pault.ag/go/piv"
)

var (
	oidMicrosoftSmartcardLogin = asn1.ObjectIdentifier{
		1, 3, 6, 1, 4, 1, 311, 20, 2, 2}
)

func VerifyMicrosoftExtKeyUsage(cert *piv.Certificate) error {
	for _, el := range cert.UnknownExtKeyUsage {
		if el.Equal(oidMicrosoftSmartcardLogin) {
			return nil
		}
	}
	return fmt.Errorf("pampiv: No SmartcardLogin extended key usage")
}

func VerifyCertificate(cert *piv.Certificate, roots, ints *x509.CertPool) ([][]*x509.Certificate, error) {
	chains, err := cert.Verify(x509.VerifyOptions{
		Roots:         roots,
		Intermediates: ints,

		// XXX: set KUs and EKUs to sane values
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	})

	if err != nil {
		return nil, err
	}

	return chains, nil
}

func Challenge(cert *piv.Certificate, signer crypto.Signer) error {
	chal := make([]byte, 32)
	_, err := rand.Read(chal)
	if err != nil {
		return err
	}

	sig, err := signer.Sign(nil, chal, crypto.SHA256)
	if err != nil {
		return err
	}

	// Add support for EC crypto types here
	switch cert.PublicKey.(type) {
	case *rsa.PublicKey:
		pk := cert.PublicKey.(*rsa.PublicKey)
		return rsa.VerifyPKCS1v15(pk, crypto.SHA256, chal, sig)
	default:
		return fmt.Errorf("pivauth: unknown public key algorithm")
	}

	return nil
}

// vim: foldmethod=marker
