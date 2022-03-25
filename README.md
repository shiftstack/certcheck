# certcheck

Checks the HTTPS certificate securing a domain name.

Returns PASS if the certificate contains a Subject Alternative Name (SAN).
Returns INVALID if the certificate does not contain any SAN field.

## Usage

```shell
./certcheck.sh redhat.com
# PASS: redhat.com
```
