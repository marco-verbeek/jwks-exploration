# JWKS Exploration

## What am I trying to simulate ?

LTI 1.3 requires a `/.well-known/jwks.json` endpoint, as it needs to make sure the payload containing the grades it receives is securely coming from our backend. It verifies the payload using our public key, which we aim to provide in the JWKS endpoint.

The other way around works as well: we're making sure the received payloads are secure and have been signed by the LMSs themselves. We're doing this by fetching their public keys using their JWKS endpoint and verifying the received JWT with it.

## How can you test this simulation ?

I created a small project that aims at 

- reading asymetric PEM keys (private and public)
- using the public key to supply the `/.well-known/jwks.json` endpoint
- using the private key to encrypt a payload using the `/get-jwt` endpoint
- testing the received JWT using the JWKS endpoint by doing a GET on `/check/:jwt` endpoint

Do not forget to generate the certificates using following commands:

```bash
$ openssl ecparam -name prime256v1 -genkey -noout -out ./certs/private.pem
$ openssl ec -in ./certs/private.pem -pubout -out ./certs/public.pem
```

The test can be ran using any rest client and by doing two requests:

1. GET `/get-jwt`
2. GET `/check/:jwt`

I reccomend using the REST Client extension of VS Code, so that you may run the requests firectly from the client.rest file.