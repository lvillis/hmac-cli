<div align=right>Table of Contents↗️</div>

<h1 align=center><code>hmac-cli</code></h1>

<p align=center>🛠️ A command-line tool for generating HMAC signatures.</p>

<div align=center>
  <a href="https://crates.io/crates/hmac-cli">
    <img src="https://img.shields.io/crates/v/hmac-cli.svg" alt="crates.io version">
  </a>
  <a href="https://crates.io/crates/hmac-cli">
    <img src="https://img.shields.io/github/repo-size/lvillis/hmac-cli?style=flat-square&color=328657" alt="crates.io version">
  </a>
  <a href="https://github.com/lvillis/hmac-cli/actions">
    <img src="https://github.com/lvillis/hmac-cli/actions/workflows/ci.yaml/badge.svg" alt="build status">
  </a>
  <a href="mailto:lvillis@outlook.com?subject=Thanks%20for%20hmac-cli!">
    <img src="https://img.shields.io/badge/Say%20Thanks-!-1EAEDB.svg" alt="say thanks">
  </a>
</div>

---

## Example

```bash
$ hmac -h
Usage: hmac.exe [OPTIONS] --url <URL>

Options:
  -a, --ak <AK>                Access Key ID (can be provided via config file `ak`)
  -s, --sk <SK>                Secret Key (can be provided via config file `sk`)
  -m, --method <METHOD>        Request method (default: POST) [default: POST]
  -u, --url <URL>              Request URL
  -b, --body <BODY>            Request body (JSON format)
  -g, --gateway <GATEWAY>      Gateway type (default: traefik) [default: traefik] [possible values: apisix, traefik, higress]
      --algorithm <ALGORITHM>  HMAC algorithm (default: hmac-sha256) [default: hmac-sha256] [possible values: hmac-sha256, hmac-sha384, hmac-sha512]
  -h, --help                   Print help
  -V, --version                Print version
```

```bash
# Generate an HMAC signature for a POST request
$ hmac --ak <HMAC_AK> --sk <HMAC_SK> --method POST --url https://exmaple.com/api --body "{\"hello\":\"world\"}" --gateway traefik

# AK\SK can be set as environment variables (HMAC_AK\HMAC_SK)
$ hmac --method POST --url https://exmaple.com/api --body "{\"hello\":\"world\"}" --gateway apisix

# AK\SK can be set in a configuration file (~/.hmac/config.toml)
# vi ~/.hmac/config.toml
# HMAC_AK = "<HMAC_AK>"
# HMAC_SK = "<HMAC_SK>"
$ hmac --method POST --url https://exmaple.com/api --body "{\"hello\":\"world\"}" --gateway higress
```
