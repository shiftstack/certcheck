# certcheck

Checks the HTTPS certificate securing a domain name.

Returns PASS if the certificate contains a Subject Alternative Name (SAN).
Returns INVALID if the certificate does not contain any SAN field.

## Usage

```shell
./certcheck.sh redhat.com
# PASS: redhat.com
```

## Test

The included `main.go` codes a self-contained Go webserver to be used for testing purposes.

It listens on two ports:
* `:8000`: exposes an HTTPS certificate complete with SAN DNSNames
* `:8001`: exposes an HTTPS certificate without any SAN fields

```shell
go run .
```

```shell
./certcheck.sh localhost:8000
# PASS: localhost:8000

./certcheck.sh localhost:8001
# INVALID (missing SAN): localhost:8001
```
