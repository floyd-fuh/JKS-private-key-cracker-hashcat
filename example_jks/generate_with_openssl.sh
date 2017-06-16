openssl genrsa -passout pass:123456 -aes256 -out cakey.pem 4096
openssl req -new -x509 -days 3650 -key cakey.pem -passin pass:123456 -out cacert.pem -set_serial 1 -subj '/CN=test/O=test/C=CH'
touch index.txt
echo "01" > serial

#An example "server"
openssl req -new -newkey rsa:2048 -nodes -out servercsr.pem -keyout serverkey.pem -days 3650 -subj '/CN=test/O=test/C=CH'
openssl x509 -req -in servercsr.pem -out servercert.pem -CA cacert.pem -CAkey cakey.pem -passin pass:123456 -CAserial ./serial -days 3650
openssl pkcs12 -export -passin pass:123456 -passout pass:123456 -in servercert.pem -inkey serverkey.pem -out server.p12 -name server -CAfile cacert.pem -caname RootName

#An example "client"
#just as a small additional test, we add the server certificate as part of the chain (so as an intermediate certificate), which shouldn't make a difference for our cracking routine anyway
openssl req -new -newkey rsa:1024 -nodes -out clientcsr.pem -keyout clientkey.pem -days 3650 -subj '/CN=test2/O=test2/C=CH'
openssl x509 -req -in clientcsr.pem -out clientcert.pem -CA cacert.pem -CAkey cakey.pem -passin pass:123456 -CAserial ./serial -days 3650
echo servercert.pem >> clientcert.pem
openssl pkcs12 -export -passin pass:123456 -chain -passout pass:123456 -in clientcert.pem -inkey clientkey.pem -out client.p12 -name client -CAfile cacert.pem -caname RootName

#create JKS
keytool -importkeystore -deststorepass 654321 -destkeypass 123456 -destkeystore openssl_with_ca.jks -srckeystore server.p12 -srcstoretype PKCS12 -srcstorepass 123456 -alias server
keytool -importkeystore -deststorepass 654321 -destkeypass 123456 -destkeystore openssl_with_ca.jks -srckeystore client.p12 -srcstoretype PKCS12 -srcstorepass 123456 -alias client

#cleanup
rm serial cakey.pem cacert.pem index.txt serverkey.pem servercsr.pem servercert.pem clientcsr.pem clientcert.pem clientkey.pem server.p12 client.p12

