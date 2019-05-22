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
#include <security/pam_modules.h>
#include <security/pam_ext.h>

#include <stdlib.h>

// defined in pam_c.go
int piv_info(pam_handle_t*, char*);

*/
import "C"

import (
	"unsafe"
)

// Get an authentication token from the user. The token we want is the PIN
// to log into the token so that we can preform a signature over our challange.
func getAuthTok(pamh *C.pam_handle_t, what string) (string, C.int) {
	cPrompt := (*C.char)(C.CString(what))
	defer C.free(unsafe.Pointer(cPrompt))

	var target *C.char = nil

	retval := C.pam_get_authtok(pamh, C.PAM_AUTHTOK, &target, cPrompt)
	if retval != C.PAM_SUCCESS {
		return "", retval
	}

	return C.GoString(target), C.PAM_SUCCESS
}

// Send a message to the user informing them of what's going on.
func textInfo(pamh *C.pam_handle_t, what string) C.int {
	cWhat := (*C.char)(C.CString(what))
	defer C.free(unsafe.Pointer(cWhat))
	return C.piv_info(pamh, cWhat)
}

// Get the username from either the pam_handle, or the user provided
// value. We return the username string, and the PAM error value (so,
// PAM_SUCCESS in the case of success) from the underlying `pam_get_user`
// call.
func getUsername(pamh *C.pam_handle_t) (string, C.int) {
	cPrompt := (*C.char)(C.CString("Username: "))
	defer C.free(unsafe.Pointer(cPrompt))

	var cUsername *C.char = nil
	if retval := C.pam_get_user(pamh, &cUsername, cPrompt); retval != C.PAM_SUCCESS {
		return "", retval
	}

	return C.GoString(cUsername), C.PAM_SUCCESS
}

// vim: foldmethod=marker
