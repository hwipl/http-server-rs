# http-server-rs

http-server-rs is an HTTP server inspired by `python -m http.server`. It serves
files from a local directory (default: current directory). In addition to HTTP,
it supports HTTPS. If the user provides no TLS key and certificate, it
generates a self-signed certificate automatically. Currently, it does not
support cgi-bin.

## Usage

You can run `http-server-rs` with the following command line arguments:

```
HTTP server that serves files from a local directory (default: current directory)

Usage: http-server-rs [OPTIONS] [PORT]

Arguments:
  [PORT]  Specify the TCP port the server is listening on [default: 3000]

Options:
  -b, --bind <ADDRESS>                 Specify the IP address the server is listening on [default: 127.0.0.1]
  -d, --directory <DIRECTORY>          Specify the directory that is accessible by clients [default: current directory]
  -t, --tls                            Run server in TLS mode
      --tls-cert-file <TLS_CERT_FILE>  Load TLS certificate from file
      --tls-key-file <TLS_KEY_FILE>    Load TLS key from file
      --tls-show-accept-errors         Show TLS accept errors
  -h, --help                           Print help
```
