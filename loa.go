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

	"pault.ag/go/piv"
)

//
func CheckLOA(config *Config, cert *piv.Certificate) error {
	loa := piv.UnknownAssurance
	switch config.Policy.MinimumAssurance {
	case "rudimentary":
		loa = piv.RudimentaryAssurance
	case "basic":
		loa = piv.BasicAssurance
	case "medium":
		loa = piv.MediumAssurance
	case "high":
		loa = piv.HighAssurance
	default:
		return fmt.Errorf("pampiv: unknown LOA: %s", config.Policy.MinimumAssurance)
	}

	if len(cert.Policies) == 0 {
		return fmt.Errorf("pampiv: CA didn't set any LOA policies")
	}

	for _, policy := range cert.Policies {
		if policy.Issued.AssuranceLevel.Compare(loa) > 0 {
			return fmt.Errorf("pampiv: %s below LOA %s", policy.Name, loa)
		}

		if config.Policy.Hardware && !policy.Issued.Hardware {
			return fmt.Errorf("pampiv: %s is not a hardware token", policy.Name)
		}
	}

	return nil
}

// vim: foldmethod=marker
