package main

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io/ioutil"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	flag "github.com/spf13/pflag"
	"github.com/vocdoni/blind-ca/blindca"
	"github.com/vocdoni/blind-ca/handlers"
	"github.com/vocdoni/multirpc/endpoint"
	"github.com/vocdoni/multirpc/router"
	"github.com/vocdoni/multirpc/transports"
	"go.vocdoni.io/dvote/crypto/ethereum"
	"go.vocdoni.io/dvote/log"
)

func main() {
	home, err := os.UserHomeDir()
	if err != nil {
		panic("cannot get user home directory")
	}
	privKey := flag.String("key", "",
		"private CA key as hexadecimal string (leave empty for autogenerate)")
	datadir := flag.String("dataDir",
		home+"/.vocdoni-ca", "datadir for storing files and config")
	domain := flag.String("domain", "",
		"domain name for tls with letsencrypt (port 443 must be forwarded)")
	loglevel := flag.String("loglevel", "info",
		"log level {debug,info,warn,error}")
	handler := flag.String("handler", "dummy",
		fmt.Sprintf("the authentication handler to use for the CA, available: {%s}",
			handlers.HandlersList()))
	port := flag.Int("port", 5000, "port to listen")
	certificates := flag.StringArray("certs", []string{},
		"list of PEM certificates to import to the HTTP(s) server")
	flag.Parse()

	log.Init(*loglevel, "stdout")
	signer := ethereum.SignKeys{}
	if *privKey == "" {
		if err := signer.Generate(); err != nil {
			log.Fatal(err)
		}
		_, priv := signer.HexString()
		log.Infof("new private key generated: %s", priv)
	} else {
		if err := signer.AddHexKey(*privKey); err != nil {
			log.Fatal(err)
		}
	}
	log.Infof("using ECDSA signer with address %s", signer.Address().Hex())

	// Create the channel for incoming messages and attach to transport
	listener := make(chan transports.Message)

	// Create HTTP endpoint (for HTTP(s) handling) using the endpoint interface
	ep := endpoint.HTTPWSendPoint{}

	// Configures the endpoint
	if err := ep.SetOption(endpoint.OptionListenHost, "0.0.0.0"); err != nil {
		log.Fatal(err)
	}
	if err := ep.SetOption(endpoint.OptionListenPort, int32(*port)); err != nil {
		log.Fatal(err)
	}
	if err := ep.SetOption(endpoint.OptionTLSdomain, *domain); err != nil {
		log.Fatal(err)
	}
	if err := ep.SetOption(endpoint.OptionTLSdirCert, *datadir+"/tls"); err != nil {
		log.Fatal(err)
	}
	if err := ep.SetOption(endpoint.OptionSetMode, endpoint.ModeHTTPonly); err != nil {
		log.Fatal(err)
	}

	// Create the auth handler (currently a dummy one that only checks the IP)
	authHandler := handlers.Handlers[*handler]

	// Create the TLS configuration with the certificates (if required by the handler)
	tls, err := tlsConfig(*certificates, authHandler.HardcodedCertificate())
	if err != nil {
		log.Fatalf("cannot import tls certificate %v", err)
	}
	if err := ep.SetOption(endpoint.OptionTLSconfig, tls); err != nil {
		log.Fatal(err)
	}
	if err := ep.Init(listener); err != nil {
		log.Fatal(err)
	}

	// Create the transports map, this allows adding several transports on the same router
	transportMap := make(map[string]transports.Transport)
	transportMap[ep.ID()] = ep.Transport()

	// Check that the requiered certificate has been included (if any)
	if authHandler.RequireCertificate() {
		certFound := false
		for _, cert := range tls.ClientCAs.Subjects() {
			certFound = authHandler.CertificateCheck(cert)
			if certFound {
				break
			}
		}
		if !certFound {
			log.Fatalf("handler %s requires a TLS CA valid certificate", *handler)
		}
	}

	// Create the blind CA API and assign the IP auth function
	ca := new(blindca.BlindCA)
	pub, priv := signer.HexString()
	log.Infof("CA public key: %s", pub)
	if err := ca.Init(priv, authHandler.Auth); err != nil {
		log.Fatal(err)
	}

	// Create a new router and attach the transports
	r := router.NewRouter(listener, transportMap, &signer, ca.NewAPI)

	// Add namespace /main to the transport httpws
	if err := r.Transports[ep.ID()].AddNamespace("/ca"); err != nil {
		log.Fatal(err)
	}
	// And handler for namespace main and method hello
	log.Infof("adding request method under /ca namespace")
	if err := r.AddHandler("auth", "/ca", ca.SignatureReq, false, true); err != nil {
		log.Fatal(err)
	}
	// And handler for namespace main and method hello
	log.Infof("adding sign method under /ca namespace")
	if err := r.AddHandler("sign", "/ca", ca.Signature, false, true); err != nil {
		log.Fatal(err)
	}
	// Start routing
	go r.Route()

	// Wait for SIGTERM
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)
	<-c
	log.Warnf("received SIGTERM, exiting at %s", time.Now().Format(time.RFC850))
	os.Exit(0)
}

func tlsConfig(fileCertificates []string, defaultCertificate []byte) (*tls.Config, error) {
	caCertPool := x509.NewCertPool()
	// Try to load the certificates provided by the user
	for _, c := range fileCertificates {
		fp, err := filepath.Abs(c)
		if err != nil {
			return nil, err
		}
		caCert, err := ioutil.ReadFile(filepath.Clean(fp))
		if err != nil {
			return nil, err
		}
		if ok := caCertPool.AppendCertsFromPEM(caCert); !ok {
			return nil, fmt.Errorf("unable to load %s CA certificate", c)
		}
		log.Infof("imported CA certificate %s", c)
	}
	// If no certificates provided by user, then add the default one (if exist)
	if len(caCertPool.Subjects()) == 0 && len(defaultCertificate) > 1 {
		log.Debugf("adding certificate %s", defaultCertificate)
		if ok := caCertPool.AppendCertsFromPEM(defaultCertificate); !ok {
			return nil, fmt.Errorf("unable to load CA default certificate")
		}
		log.Infof("imported CA default certificate")
	}
	tlsConfig := &tls.Config{
		ClientCAs:  caCertPool,
		ClientAuth: tls.RequestClientCert,
		MinVersion: 1000,
	}
	tlsConfig.BuildNameToCertificate()
	return tlsConfig, nil
}
