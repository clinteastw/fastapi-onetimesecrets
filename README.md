# FastAPI Onetimesecrets
Encrypt a secret message using provided passphrase or a default key if no passphrase was provided.
If a passphrase is provided, it is hashed using bcrypt and then used to encrypt the secret message.

## Run with docker

`docker-compose build` \
`docker-compose up -d`
