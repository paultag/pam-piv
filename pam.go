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

/*
#include <security/pam_ext.h>
*/
import "C"

import (
	"fmt"
	"strings"

	"pault.ag/go/pampiv/pkcs11"
)

func main() {}

//export piv_sm_authenticate
func piv_sm_authenticate(pamh *C.pam_handle_t, flags, argc C.int, argv **C.char) C.int {
	pamUsername, retval := getUsername(pamh)
	if retval != C.PAM_SUCCESS {
		return retval
	}

	// change to to acually do some arg parsing
	args := GoStrings(argc, argv)

	// XXX: make this fail more gracefully
	config, err := LoadConfig(args[0])
	if err != nil {
		textInfo(pamh, err.Error())
		return C.PAM_AUTH_ERR
	}

	roots, ints, err := loadCerts(config.CAPath)
	if err != nil {
		textInfo(pamh, err.Error())
		return C.PAM_AUTH_ERR
	}

	textInfo(pamh, "Searching for a PIV card...")

	// This should likely be shimmed out so other libraries (like things
	// that talk custom protocols or things like `pault.ag/go/ykpiv`.
	store, err := pkcs11.New(pkcs11.Config{
		Module:           config.PKCS11Path,
		CertificateLabel: "Certificate for PIV Authentication",
		PrivateKeyLabel:  "PIV AUTH key",
		TokenLabel:       config.TokenLabel,
	})
	if err != nil {
		textInfo(pamh, err.Error())
		return C.PAM_AUTH_ERR
	}
	defer store.Close()

	_, err = VerifyCertificate(store.Certificate, roots, ints)
	if err != nil {
		textInfo(pamh, err.Error())
		return C.PAM_AUTH_ERR
	}

	if config.KeyUsageSmartcardLogin {
		if err := VerifyMicrosoftExtKeyUsage(store.Certificate); err != nil {
			textInfo(pamh, err.Error())
			return C.PAM_PERM_DENIED
		}
	}

	if err := CheckLOA(config, store.Certificate); err != nil {
		textInfo(pamh, err.Error())
		return C.PAM_AUTH_ERR
	}

	username, err := GetLocalUsername(config, store.Certificate)
	if err != nil {
		if err == KeyNotFound {
			textInfo(pamh, "Token isn't mapped to a local user")
			return C.PAM_USER_UNKNOWN
		}
		textInfo(pamh, err.Error())
		return C.PAM_AUTH_ERR
	}

	if strings.Compare(username, pamUsername) != 0 {
		textInfo(pamh, fmt.Sprintf("Certificate is for %s, not for %s\n",
			username, pamUsername))
		return C.PAM_PERM_DENIED
	}

	pin, retval := getAuthTok(pamh, fmt.Sprintf(
		"PIN for %s: ",
		store.Certificate.Subject.CommonName,
	))
	if retval != C.PAM_SUCCESS {
		return C.PAM_PERM_DENIED
	}

	if len(pin) == 0 {
		return C.PAM_AUTH_ERR
	}

	if err := store.Login(pin); err != nil {
		textInfo(pamh, err.Error())
		return C.PAM_AUTH_ERR
	}

	if err := Challenge(store.Certificate, store); err != nil {
		textInfo(pamh, err.Error())
		return C.PAM_PERM_DENIED
	}

	return C.PAM_SUCCESS
}

// vim: foldmethod=marker
