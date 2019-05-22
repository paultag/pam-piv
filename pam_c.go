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
#cgo LDFLAGS: -lpam -fPIC

#define PAM_SM_AUTH

#include <security/pam_ext.h>

// defined in pam.go as a Go function
int piv_sm_authenticate(pam_handle_t*, int, int, char**);

// This has to be in C, so we can (maybe in bad taste) change the const char
// argv into a char, since Go functions can't express `const char`, and
// while avoiding the import would work, causes us to miss out on functions
// that are actually useful, like `pam_get_user`.
int pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, const char **argv) {
	return piv_sm_authenticate(pamh, flags, argc, (char**)argv);
}

// For some reason, cgo barfs on `...);`, so we're going to provide a simple
// typed helper to use throughout.
int piv_info(pam_handle_t* pamh, char* text) {
	return pam_prompt(pamh, PAM_TEXT_INFO, NULL, text);
}

*/
import "C"

// vim: foldmethod=marker
