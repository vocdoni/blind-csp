<p align="center" width="100%">
    <img src="https://developer.vocdoni.io/img/vocdoni_logotype_full_white.svg" />
</p>

<p align="center" width="100%">
    <a href="https://github.com/vocdoni/blind-csp/commits/main/"><img src="https://img.shields.io/github/commit-activity/m/vocdoni/blind-csp" /></a>
    <a href="https://github.com/vocdoni/blind-csp/issues"><img src="https://img.shields.io/github/issues/vocdoni/blind-csp" /></a>
    <a href="https://github.com/vocdoni/blind-csp/actions/workflows/main.yml/"><img src="https://github.com/vocdoni/blind-csp/actions/workflows/main.yml/badge.svg" /></a>
    <a href="https://discord.gg/xFTh8Np2ga"><img src="https://img.shields.io/badge/discord-join%20chat-blue.svg" /></a>
    <a href="https://twitter.com/vocdoni"><img src="https://img.shields.io/twitter/follow/vocdoni.svg?style=social&label=Follow" /></a>
</p>


  <div align="center">
    Vocdoni is the first universally verifiable, censorship-resistant, anonymous, and self-sovereign governance protocol. <br />
    Our main aim is a trustless voting system where anyone can speak their voice and where everything is auditable. <br />
    We are engineering building blocks for a permissionless, private and censorship resistant democracy.
    <br />
    <a href="https://developer.vocdoni.io/"><strong>Explore the developer portal »</strong></a>
    <br />
    <h3>More About Us</h3>
    <a href="https://vocdoni.io">Vocdoni Website</a>
    |
    <a href="https://vocdoni.app">Web Application</a>
    |
    <a href="https://explorer.vote/">Blockchain Explorer</a>
    |
    <a href="https://law.mit.edu/pub/remotevotingintheageofcryptography/release/1">MIT Law Publication</a>
    |
    <a href="https://chat.vocdoni.io">Contact Us</a>
    <br />
    <h3>Key Repositories</h3>
    <a href="https://github.com/vocdoni/vocdoni-node">Vocdoni Node</a>
    |
    <a href="https://github.com/vocdoni/vocdoni-sdk/">Vocdoni SDK</a>
    |
    <a href="https://github.com/vocdoni/ui-components">UI Components</a>
    |
    <a href="https://github.com/vocdoni/ui-scaffold">Application UI</a>
    |
    <a href="https://github.com/vocdoni/census3">Census3</a>
  </div>

# blind-csp

Vocdoni blind-csp is a modular API backend for [Certification Service Providers (CSP)](https://en.wikipedia.org/wiki/Certificate_authority) using [Blind signatures](https://en.wikipedia.org/wiki/Blind_signature) (among others).

Blind signatures were first suggested by David Chaum: a cryptographic scheme that enables the creation of signatures on disguised (blinded) messages. The blinder (voter in our scenario) can then un-blind this signature and use it as a standard one. This protocol was designed for RSA, but we use it over [EC secp256k1](https://github.com/arnaucube/go-blindsecp256k1).

The API server supports [x509 certificates](https://en.wikipedia.org/wiki/X.509) for client authentication so it is a convenient way to authenticate official certificates while preserving privacy.

Its design makes very easy to write new authentication handlers such as the ones found in the `handlers/` directory. A pretty useful use case is to authenticate via SMS (already supported), but there are other cool handlers that can be implemented such as authentication via Discord, Twitter or E-residency cards.

### Table of Contents
- [Getting Started](#getting-started)
- [Reference](#reference)
- [Examples](#examples)
- [Contributing](#contributing)


## Getting Started

You can run a blind-csp server locally with just a working golang environment:

```golang
$ go run . --help
      --baseURL string        base URL path for serving the API (default "/v1/auth")
      --dataDir string        datadir for storing files and config (default "/home/user/.blindcsp")
      --domain string         domain name for tls with letsencrypt (port 443 must be forwarded)
      --handler string        the authentication handler to use, available: {dummy uniqueIp idCat rsa} (default "dummy")
      --handlerOpts strings   options that will be passed to the handler
      --key string            private CSP key as hexadecimal string (leave empty for autogenerate)
      --logLevel string       log level {debug,info,warn,error} (default "info")
      --port int              port to listen (default 5000)
```

For a mock example that allows you to authenticate anyone with a simple arithmetic problem, use the 'simpleMath' handler:

```golang
$ go run . --logLevel=debug --handler=simpleMath
```

## Reference

The blind CSP protocol is documented at the [developer portal](https://developer.vocdoni.io/protocol/census/off-chain-csp).
The REST API for interacting with the CSP service is documented [here](https://developer.vocdoni.io/protocol/census/off-chain-csp/api)

## Examples

See the `test.sh` file for a full flow example.
You can also see how the vocdoni-sdk [implements](https://github.com/vocdoni/vocdoni-sdk/blob/main/src/services/csp.ts) its interaction with the CSP, usage documented [here](https://developer.vocdoni.io/sdk/integration-details/census-types/off-chain-csp).

## Contributing 

While we welcome contributions from the community, we do not track all of our issues on Github and we may not have the resources to onboard developers and review complex pull requests. That being said, there are multiple ways you can get involved with the project. 

Please review our [development guidelines](https://developer.vocdoni.io/development-guidelines).
