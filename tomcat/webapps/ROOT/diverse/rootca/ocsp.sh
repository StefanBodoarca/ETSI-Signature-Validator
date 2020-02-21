file_name="ocsp3"
openssl genrsa -aes256 -out ./private/$file_name".key" 2048
openssl req -new -key ./private/$file_name".key" -out ./csr/$file_name".csr" -config rootca.conf
openssl ca -in ./csr/$file_name".csr" -out ./certs/$file_name".crt" -cert root-ca.crt -keyfile ./private/root-ca.key -config rootca.conf -extensions v3_OCSP
