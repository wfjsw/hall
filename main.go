// Copyright (c) 2010 The Grumble Authors
// The use of this source code is goverened by a BSD-style
// license that can be found in the LICENSE-file.

package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"math/rand"
	"net/http"
	_ "net/http/pprof"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strconv"
	"syscall"
	"time"

	"github.com/wfjsw/hall/blobstore"
	"github.com/wfjsw/hall/logtarget"
)

var blobStore blobstore.BlobStore

func main() {
	rand.Seed(time.Now().UnixNano())

	var err error

	flag.Parse()
	if Args.ShowHelp == true {
		Usage()
		return
	}

	if Args.PProf != "" {
		runtime.SetMutexProfileFraction(10)
		runtime.SetBlockProfileRate(128)
		go http.ListenAndServe(Args.PProf, nil)
	}

	// workingDir, _ := os.Getwd()
	strDataDir := Args.DataDir
	strLogPath := Args.LogPath
	strConfigPath := Args.ConfigPath

	// Set up logging

	var logTarget io.Writer

	if strLogPath != "" {
		err = logtarget.Target.OpenFile(strLogPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Unable to open log file (%v): %v", strLogPath, err)
			return
		}
		logTarget = &logtarget.Target
		log.SetOutput(&logtarget.Target)
	} else {
		logTarget = os.Stdout
		log.SetOutput(logTarget)
	}

	fmt.Printf("%s %s\n", verRelease, VERSION)
	fmt.Printf("Mumble Protocol %s (Revision %s)\n", verProtoverText, strconv.Itoa(verProtover))
	fmt.Printf("Built on %s\n\n", BUILDDATE)

	log.SetPrefix("[Coordinator] ")
	log.SetFlags(0)

	// Open the data dir to check whether it exists.
	dataDir, err := os.Open(strDataDir)
	if err != nil {
		log.Printf("Unable to open data directory (%v): %v", strDataDir, err)
		log.Printf("Creating new data directory")
		err1 := os.Mkdir(strDataDir, 0700)
		if err1 != nil {
			log.Fatalf("Unable to create data directory (%v): %v", strDataDir, err1)
			return
		}
	} else {
		dataDir.Close()
	}

	log.Printf("Using data directory: %s", strDataDir)

	log.Printf("Loading config file")

	configFile := strConfigPath

	r, err := os.Open(configFile)
	if err != nil {
		log.Fatalf("Unable to open config file (%v): %v", configFile, err)
		return
	}
	defer r.Close()

	bufConfig, err := ioutil.ReadAll(r)
	if err != nil {
		log.Fatalf("Unable to read config file (%v): %v", configFile, err)
		return
	}

	var config ServerConfig
	err = json.Unmarshal(bufConfig, &config)
	if err != nil {
		log.Fatalf("Unable to decode config file (%v): %v", configFile, err)
		return
	}

	// Open the blobstore.  If the directory doesn't
	// already exist, create the directory and open
	// the blobstore.
	// The Open method of the blobstore performs simple
	// sanity checking of content of the blob directory,
	// and will return an error if something's amiss.
	blobDir := filepath.Join(strDataDir, "blob")
	err = os.Mkdir(blobDir, 0700)
	if err != nil && !os.IsExist(err) {
		log.Fatalf("Unable to create blob directory (%v): %v", blobDir, err)
	}
	blobStore = blobstore.Open(blobDir)

	// Check whether we should regenerate the default global keypair
	// and corresponding certificate.
	// These are used as the default certificate of all virtual servers
	// and the SSH admin console, but can be overridden using the "key"
	// and "cert" arguments to Grumble.
	certFn := filepath.Join(strDataDir, config.SSLCert)
	keyFn := filepath.Join(strDataDir, config.SSLKey)
	shouldRegen := false
	if Args.RegenKeys {
		shouldRegen = true
	} else {
		// OK. Here's the idea:  We check for the existence of the cert.pem
		// and key.pem files in the data directory on launch. Although these
		// might be deleted later (and this check could be deemed useless),
		// it's simply here to be convenient for admins.
		hasKey := true
		hasCert := true
		_, err = os.Stat(certFn)
		if err != nil && os.IsNotExist(err) {
			hasCert = false
		}
		_, err = os.Stat(keyFn)
		if err != nil && os.IsNotExist(err) {
			hasKey = false
		}
		if !hasCert && !hasKey {
			shouldRegen = true
		} else if !hasCert || !hasKey {
			if !hasCert {
				log.Fatalf("Grumble could not find its certificate (%v)", certFn)
			}
			if !hasKey {
				log.Fatalf("Grumble could not find its private key (%v)", keyFn)
			}
		}
	}
	if shouldRegen {
		log.Printf("Generating 4096-bit RSA keypair for self-signed certificate...")

		err := GenerateSelfSignedCert(certFn, keyFn)
		if err != nil {
			log.Printf("Error: %v", err)
			return
		}

		log.Printf("Certificate output to %v", certFn)
		log.Printf("Private key output to %v", keyFn)
	}

	// New Server
	server, err := NewServer(strDataDir, config, logTarget)
	if err != nil {
		log.Fatalf("Couldn't start server: %s", err.Error())
	}

	err = server.Start()
	if err != nil {
		log.Printf("Unable to start server %v: %v", server.ID, err.Error())
	}

	go func() {
		sigchan := make(chan os.Signal, 10)
		signal.Notify(sigchan, os.Interrupt, os.Kill, syscall.SIGTERM, syscall.SIGHUP)
		for sig := range sigchan {
			if sig == os.Interrupt || sig == syscall.SIGTERM || sig == os.Kill {
				// err := logtarget.Target.Rotate()
				// if err != nil {
				// 	fmt.Fprintf(os.Stderr, "unable to rotate log file: %v", err)
				// }
				log.Printf("Received %v signal, shutting down", sig)
				server.Stop()
				os.Exit(0)
			} else if sig == syscall.SIGHUP {
				func(server *Server, configFile string) {
					r, err := os.Open(configFile)
					if err != nil {
						log.Fatalf("Unable to open config file (%v): %v", configFile, err)
						return
					}
					defer r.Close()

					bufConfig, err := ioutil.ReadAll(r)
					if err != nil {
						log.Fatalf("Unable to read config file (%v): %v", configFile, err)
						return
					}

					var config ServerConfig
					err = json.Unmarshal(bufConfig, &config)
					if err != nil {
						log.Fatalf("Unable to decode config file (%v): %v", configFile, err)
						return
					}

					server.ReloadConfig(config)
				}(server, configFile)
			}
		}
	}()
	select {}
}
