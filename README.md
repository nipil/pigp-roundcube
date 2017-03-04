# pigp-roundcube


# generate certificate

	openssl genrsa -out key.pem 4096

	openssl req -out csr.pem -key key.pem -new

	openssl x509 -signkey key.pem -in csr.pem -req -days 365 -out cert.pem
