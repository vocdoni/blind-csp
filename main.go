package main

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io/ioutil"
	"os"
	"os/signal"
	"path"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	flag "github.com/spf13/pflag"
	"github.com/spf13/viper"
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
	flag.String("key", "",
		"private CA key as hexadecimal string (leave empty for autogenerate)")
	flag.String("dataDir",
		home+"/.blind-ca", "datadir for storing files and config")
	flag.String("domain", "",
		"domain name for tls with letsencrypt (port 443 must be forwarded)")
	flag.String("logLevel", "info",
		"log level {debug,info,warn,error}")
	flag.String("handler", "dummy",
		fmt.Sprintf("the authentication handler to use for the CA, available: {%s}",
			handlers.HandlersList()))
	flag.Int("port", 5000, "port to listen")
	flag.StringArray("certs", []string{},
		`list of PEM CA certificates to import to the HTTP(s) server. 
		Will override the hardcoed one by the handler (if any)`)
	flag.Parse()

	// Setting up viper
	viper := viper.New()
	viper.SetConfigName("blindca")
	viper.SetConfigType("yml")
	viper.SetEnvPrefix("BLINDCA")
	viper.AutomaticEnv()
	viper.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))

	// Set FlagVars first
	if err := viper.BindPFlag("dataDir", flag.Lookup("dataDir")); err != nil {
		panic(err)
	}
	dataDir := path.Clean(viper.GetString("dataDir"))
	viper.AddConfigPath(dataDir)
	fmt.Printf("Using path %s\n", dataDir)
	if err := viper.BindPFlag("logLevel", flag.Lookup("logLevel")); err != nil {
		panic(err)
	}
	if err := viper.BindPFlag("key", flag.Lookup("key")); err != nil {
		panic(err)
	}
	if err := viper.BindPFlag("domain", flag.Lookup("domain")); err != nil {
		panic(err)
	}
	if err := viper.BindPFlag("port", flag.Lookup("port")); err != nil {
		panic(err)
	}
	if err := viper.BindPFlag("handler", flag.Lookup("handler")); err != nil {
		panic(err)
	}
	if err := viper.BindPFlag("certs", flag.Lookup("certs")); err != nil {
		panic(err)
	}

	// check if config file exists
	_, err = os.Stat(path.Join(dataDir, "blindca.yml"))
	if os.IsNotExist(err) {
		fmt.Printf("creating new config file in %s\n", dataDir)
		// creting config folder if not exists
		err = os.MkdirAll(dataDir, os.ModePerm)
		if err != nil {
			panic(fmt.Sprintf("cannot create data directory: %v", err))
		}
		// create config file if not exists
		if err := viper.SafeWriteConfig(); err != nil {
			panic(fmt.Sprintf("cannot write config file into config dir: %v", err))
		}

	} else {
		// read config file
		err = viper.ReadInConfig()
		if err != nil {
			panic(fmt.Sprintf("cannot read loaded config file in %s: %v", dataDir, err))
		}
	}
	// save config file
	if err := viper.WriteConfig(); err != nil {
		panic(fmt.Sprintf("cannot write config file into config dir: %v", err))
	}

	// Set Viper/Flag variables
	domain := viper.GetString("domain")
	privKey := viper.GetString("key")
	loglevel := viper.GetString("logLevel")
	handler := viper.GetString("handler")
	port := viper.GetInt("port")
	certificates := []string{}
	for _, c := range viper.GetStringSlice("certs") {
		if len(c) > 2 {
			certificates = append(certificates, strings.ReplaceAll(strings.ReplaceAll(c, "[", ""), "]", ""))
		}
	}
	// Start
	log.Init(loglevel, "stdout")
	signer := ethereum.SignKeys{}
	if privKey == "" {
		if err := signer.Generate(); err != nil {
			log.Fatal(err)
		}
		_, privKey = signer.HexString()
		log.Infof("new private key generated: %s", privKey)
		viper.Set("key", privKey)
		viper.Set("pubKey", fmt.Sprintf("%x", signer.PublicKey()))
		if err := viper.WriteConfig(); err != nil {
			log.Fatal(err)
		}
	} else {
		if err := signer.AddHexKey(privKey); err != nil {
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
	if err := ep.SetOption(endpoint.OptionListenPort, int32(port)); err != nil {
		log.Fatal(err)
	}
	if err := ep.SetOption(endpoint.OptionTLSdomain, domain); err != nil {
		log.Fatal(err)
	}
	if err := ep.SetOption(endpoint.OptionTLSdirCert, dataDir+"/tls"); err != nil {
		log.Fatal(err)
	}
	if err := ep.SetOption(endpoint.OptionSetMode, endpoint.ModeHTTPonly); err != nil {
		log.Fatal(err)
	}

	// Create the auth handler (currently a dummy one that only checks the IP)
	authHandler := handlers.Handlers[handler]
	if authHandler == nil {
		log.Fatalf("handler %s is unknown", handler)
	}
	if err := authHandler.Init(dataDir); err != nil {
		log.Fatal(err)
	}
	log.Infof("using handler %s", handler)
	// Create the TLS configuration with the certificates (if required by the handler)
	if authHandler.RequireCertificate() {
		tls, err := tlsConfig(certificates, authHandler.Certificate())
		if err != nil {
			log.Fatalf("cannot import tls certificate %v", err)
		}
		if err := ep.SetOption(endpoint.OptionTLSconfig, tls); err != nil {
			log.Fatal(err)
		}
		// Check that the requiered certificate has been included (if any)
		certFound := false
		for _, cert := range tls.ClientCAs.Subjects() {
			certFound = authHandler.CertificateCheck(cert)
			if certFound {
				break
			}
		}
		if !certFound {
			log.Fatalf("handler %s requires a TLS CA valid certificate", handler)
		}
	}
	// Init the endpoint
	if err := ep.Init(listener); err != nil {
		log.Fatal(err)
	}

	// Create the transports map, this allows adding several transports on the same router
	transportMap := make(map[string]transports.Transport)
	transportMap[ep.ID()] = ep.Transport()

	// Create the blind CA API and assign the IP auth function
	ca := new(blindca.BlindCA)
	pub, priv := signer.HexString()
	log.Infof("CSP/CA public key: %s", pub)
	if err := ca.Init(priv, authHandler.Auth, path.Join(dataDir, authHandler.GetName())); err != nil {
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

func tlsConfig(fileCertificates []string, x509defaultCertificate []byte) (*tls.Config, error) {
	caCertPool := x509.NewCertPool()
	// Try to load the certificates provided by the user (PEM)
	for _, c := range fileCertificates {
		fp, err := filepath.Abs(c)
		if err != nil {
			return nil, err
		}
		caCert, err := ioutil.ReadFile(fp)
		if err != nil {
			return nil, err
		}
		if ok := caCertPool.AppendCertsFromPEM(caCert); !ok {
			return nil, fmt.Errorf("unable to load %s CA certificate", c)
		}
		log.Infof("imported CA certificate %s", c)
	}
	// If no certificates provided by user, then add the default one (if exist)
	if len(caCertPool.Subjects()) == 0 && len(x509defaultCertificate) > 1 {
		c, err := x509.ParseCertificate(x509defaultCertificate)
		if err != nil {
			return nil, err
		}
		caCertPool.AddCert(c)
		log.Infof("imported CA default certificate from %s", c.Issuer)
	}
	tlsConfig := &tls.Config{
		ClientCAs:  caCertPool,
		ClientAuth: tls.RequestClientCert,
	}
	return tlsConfig, nil
}
