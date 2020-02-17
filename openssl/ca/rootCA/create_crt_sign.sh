file_name=$1
openssl genrsa -aes128 -out $file_name".key" 1024
openssl req -new -key $file_name".key" -out $file_name".csr" -config openssl.cnf
openssl ca -in $file_name".csr" -out $file_name".crt" -cert root-ca.crt -keyfile ./private/root-ca.key -config openssl.cnf
