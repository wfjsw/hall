//go:build lang_en
// +build lang_en

package main

// English

const (
	trnDirectVoiceBlock             = "<strong>WARNING:</strong> Voice broadcast without <b>Whisper/Shout</b> set is prohibited on this server. We will suppress you for now. Please reconnect after you fixed this."
	trnCertRequired                 = "A certificate is mandatory for this server"
	trnInvalidUsername              = "Please specify a username to log in"
	trnAuthenticatorFail            = "Authenticator returns failure"
	trnAuthenticatorNoUser          = "Authenticator says no such user"
	trnAuthenticatorInvalidCred     = "Username or Password do not match"
	trnRequiredGroupNotMet          = "Not authorized"
	trnSimultaneousLoginDifferentIP = "A client is already connected using those credentials"
	trnTooManySimultaneousLogin     = "You have exceeded the max simultaneous login count"
	trnNoCELTSupport                = "<strong>WARNING:</strong> Your client doesn't support the CELT codec, you won't be able to talk to or hear most clients. Please make sure your client was built with CELT support."
	trnNoOpusSupport                = "<strong>WARNING:</strong> Your client doesn't support the Opus codec the server is switching to, you won't be able to talk or hear anyone. Please upgrade to a client with Opus support."
	trnVersionTooOld                = "Your client does not meet with the minimum version limit. Please upgrade to latest version."
	trnServerIsFull                 = "Server is full"
	trnPlatformInfoMissing          = "You are required to present your platform information."
)
