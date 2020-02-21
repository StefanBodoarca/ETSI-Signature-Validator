file_name=$1
openssl genrsa -aes256 -out ./private/$file_name".key" 2048
openssl req -new -key ./private/$file_name".key" -out ./csr/$file_name".csr" -config rootca2.conf
openssl ca -in ./csr/$file_name".csr" -out ./certs/$file_name".crt" -cert root-ca.crt -keyfile ./private/root-ca.key -config rootca2.conf
