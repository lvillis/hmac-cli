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
# Generate an HMAC signature for a POST request
$ hmac --ak <HMAC_AK> --sk <HMAC_SK> --method POST --url https://exmaple.com/api --body "{\"hello\":\"world\"}" --gateway traefik

# AK\SK can be set as environment variables (HMAC_AK\HMAC_SK)
$ hmac --method POST --url https://exmaple.com/api --body "{\"hello\":\"world\"}" --gateway apisix

# AK\SK can be set in a configuration file (~/.hmac/config.toml)
$ hmac --method POST --url https://exmaple.com/api --body "{\"hello\":\"world\"}" --gateway higress
```
