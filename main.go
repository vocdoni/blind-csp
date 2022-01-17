package main

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"
	"os/signal"
	"path"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	flag "github.com/spf13/pflag"
	"github.com/spf13/viper"
	"github.com/vocdoni/blind-csp/csp"
	"github.com/vocdoni/blind-csp/handlers"
	"go.vocdoni.io/dvote/crypto/ethereum"
	"go.vocdoni.io/dvote/httprouter"
	"go.vocdoni.io/dvote/log"
)

func main() {
	home, err := os.UserHomeDir()
	if err != nil {
		panic("cannot get user home directory")
	}
	flag.String("key", "",
		"private CSP key as hexadecimal string (leave empty for autogenerate)")
	flag.String("dataDir",
		home+"/.blindcsp", "datadir for storing files and config")
	flag.String("domain", "",
		"domain name for tls with letsencrypt (port 443 must be forwarded)")
	flag.String("baseURL", "/v1/auth/elections",
		"base URL path for serving the API")
	flag.String("logLevel", "info",
		"log level {debug,info,warn,error}")
	flag.String("handler", "dummy",
		fmt.Sprintf("the authentication handler to use, available: {%s}",
			handlers.HandlersList()))
	flag.StringSlice("handlerOpts", []string{}, "options that will be passed to the handler")
	flag.Int("port", 5000, "port to listen")
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
	if err := viper.BindPFlag("baseURL", flag.Lookup("baseURL")); err != nil {
		panic(err)
	}
	if err := viper.BindPFlag("port", flag.Lookup("port")); err != nil {
		panic(err)
	}
	if err := viper.BindPFlag("handler", flag.Lookup("handler")); err != nil {
		panic(err)
	}
	if err := viper.BindPFlag("handlerOpts", flag.Lookup("handlerOpts")); err != nil {
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
	baseURL := viper.GetString("baseURL")
	privKey := viper.GetString("key")
	loglevel := viper.GetString("logLevel")
	handler := viper.GetString("handler")
	port := viper.GetInt("port")
	handlerOpts := []string{dataDir}
	for _, h := range viper.GetStringSlice("handlerOpts") {
		if !strings.Contains(h, "[") && len(h) > 0 {
			handlerOpts = append(handlerOpts, h)
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

	// Create the HTTP router
	router := httprouter.HTTProuter{}
	router.TLSdomain = domain
	router.TLSdirCert = filepath.Join(dataDir, "tls")

	// Create the auth handler (currently a dummy one that only checks the IP)
	authHandler := handlers.Handlers[handler]
	if authHandler == nil {
		log.Fatalf("handler %s is unknown", handler)
	}
	if err := authHandler.Init(handlerOpts...); err != nil {
		log.Fatal(err)
	}
	log.Infof("using handler %s", handler)

	// Create the TLS configuration with the certificates (if required by the handler)
	if authHandler.RequireCertificate() {
		tls, err := tlsConfig(authHandler.Certificates())
		if err != nil {
			log.Fatalf("cannot import tls certificate %v", err)
		}
		router.TLSconfig = tls
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

	// Start the router
	if err := router.Init("0.0.0.0", port); err != nil {
		log.Fatal(err)
	}

	// Create the blind CA API and assign the auth function
	pub, priv := signer.HexString()
	log.Infof("CSP root public key: %s", pub)
	cs, err := csp.NewBlindCSP(priv, path.Join(dataDir, authHandler.GetName()), authHandler.Auth)
	if err != nil {
		log.Fatal(err)
	}
	if err := cs.ServeAPI(&router, baseURL); err != nil {
		log.Fatal(err)
	}

	// Wait for SIGTERM
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)
	<-c
	log.Warnf("received SIGTERM, exiting at %s", time.Now().Format(time.RFC850))
	os.Exit(0)
}

func tlsConfig(x509certificates [][]byte) (*tls.Config, error) {
	caCertPool := x509.NewCertPool()
	for _, cert := range x509certificates {
		c, err := x509.ParseCertificate(cert)
		if err != nil {
			return nil, err
		}
		caCertPool.AddCert(c)
		log.Infof("imported CA certificate from %s", c.Issuer.String())
	}
	tlsConfig := &tls.Config{
		ClientCAs:  caCertPool,
		ClientAuth: tls.RequestClientCert,
	}
	return tlsConfig, nil
}
