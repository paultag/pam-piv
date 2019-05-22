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
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"strings"
)

// Load and split certs into roots and intermediates, fit for use with
// VerifyCertificate.
func loadCerts(path string) (*x509.CertPool, *x509.CertPool, error) {
	rootsPool := x509.NewCertPool()
	intPool := x509.NewCertPool()

	bytes, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, nil, err
	}

	var p *pem.Block
	for {
		p, bytes = pem.Decode(bytes)
		if len(bytes) == 0 {
			break
		}

		if p == nil {
			return nil, nil, fmt.Errorf("pivauth: invalid ca bundle")
		}

		if strings.Compare(p.Type, "CERTIFICATE") != 0 {
			return nil, nil, fmt.Errorf("pivauth: pem chain has a non-cert in it")
		}

		cert, err := x509.ParseCertificate(p.Bytes)
		if err != nil {
			return nil, nil, err
		}

		if !cert.IsCA {
			return nil, nil, fmt.Errorf("pivauth: cert in ca bundle isn't a ca")
		}

		if cert.CheckSignatureFrom(cert) == nil {
			rootsPool.AddCert(cert)
		} else {
			intPool.AddCert(cert)
		}
	}

	return rootsPool, intPool, nil
}

// vim: foldmethod=marker
