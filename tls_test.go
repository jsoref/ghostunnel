/*-
 * Copyright 2015 Square Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package main

import (
	"crypto/tls"
	"encoding/base64"
	"io/ioutil"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
)

var testCertificate = `

var testPrivateKey = `

var testKeystore, _ = base64.StdEncoding.DecodeString(`
`)

var testKeystorePassword = "password"

func init() {
	if testKeystore == nil {
		panic("invalid test keystore data")
	}
}

func TestParseKeystore(t *testing.T) {
	certs, key, err := parseKeystore(testKeystore, testKeystorePassword)
	assert.NotNil(t, certs, "must parse certs")
	assert.NotNil(t, key, "must parse private key")
	assert.Nil(t, err, "must parse keystore")
}

func TestBuildConfig(t *testing.T) {
	tmpKeystore, err := ioutil.TempFile("", "ghostunnel-test")
	panicOnError(err)

	tmpCaBundle, err := ioutil.TempFile("", "ghostunnel-test")
	panicOnError(err)

	tmpKeystore.Write(testKeystore)
	tmpCaBundle.WriteString(testCertificate)
	tmpCaBundle.WriteString("\n")

	tmpKeystore.Sync()
	tmpCaBundle.Sync()

	defer os.Remove(tmpKeystore.Name())
	defer os.Remove(tmpCaBundle.Name())

	conf, err := buildConfig(tmpKeystore.Name(), testKeystorePassword, tmpCaBundle.Name(), "1.2")
	assert.Nil(t, err, "should be able to build TLS config")
	assert.NotNil(t, conf.Certificates, "config must have certs")
	assert.NotNil(t, conf.RootCAs, "config must have CA certs")
	assert.NotNil(t, conf.ClientCAs, "config must have CA certs")
	assert.True(t, conf.MinVersion == tls.VersionTLS12, "must have correct TLS min version")

	conf, err = buildConfig(tmpKeystore.Name(), testKeystorePassword, tmpCaBundle.Name(), "1.1")
	assert.True(t, conf.MinVersion == tls.VersionTLS11, "must have correct TLS min version")

	conf, err = buildConfig(tmpKeystore.Name(), testKeystorePassword, tmpCaBundle.Name(), "1.0")
	assert.True(t, conf.MinVersion == tls.VersionTLS10, "must have correct TLS min version")
}
