#include <openssl/ssl.h>
#include <sys/socket.h>
#include <unistd.h>
#include <netdb.h>
#include <string.h>

#define HOST "github.com"
#define DIR "/IDesteny"

/* 128 KB */
#define SRES 128 * 1024

int main(void)
{
	const char *port = "443";
	struct addrinfo *pAddr = NULL;

	int iResultGetAddrInfo = getaddrinfo(HOST, port, NULL, &pAddr);
	if (iResultGetAddrInfo != 0) return 1;

	int sock = socket(pAddr->ai_family, pAddr->ai_socktype, pAddr->ai_protocol);
	if (sock == -1) return 1;

	int iResultConnet = connect(sock, pAddr->ai_addr, pAddr->ai_addrlen);
	if (iResultConnet != 0) return 1;

	SSL_library_init();
	SSL *ssl = SSL_new(SSL_CTX_new(SSLv23_method()));
	if (ssl == NULL) return 1;

	int iResultSSL_set_fd = SSL_set_fd(ssl, sock);
	if (iResultSSL_set_fd == 0) return 1;

	int iResultSSL_connect = SSL_connect(ssl);
	if (iResultSSL_connect != 1) return 1;

	const char *template_headers = "GET %s HTTP/1.1\r\nHOST:%s\r\nConnection:close\r\n\r\n";
	size_t headers_len = strlen(template_headers) + strlen(HOST) + strlen(DIR);
	char *headers = malloc(headers_len);
	if (headers == NULL) return 1;

	int iResultSprintf_s = snprintf(headers, headers_len, template_headers, DIR, HOST);
	if (iResultSprintf_s == -1) return 1;

	int iResultSSL_write = SSL_write(ssl, headers, headers_len);
	if (iResultSSL_write <= 0) return 1;

	char *res = calloc(SRES, sizeof(char));
	if (res == NULL) return 1;

	int iResultSSL_read = 0;
	int countReaded = 0;
	do
	{
		iResultSSL_read = SSL_read(ssl, res + countReaded, SRES - countReaded);
		countReaded += iResultSSL_read;
	} while (iResultSSL_read > 0 && countReaded < SRES);

	int iResultSSL_shutdown = SSL_shutdown(ssl);
	if (iResultSSL_shutdown < 0) return 1;

	int iResultSSL_clear = SSL_clear(ssl);
	if (iResultSSL_clear == 0) return 1;

	free(headers);
	free(res);
	SSL_free(ssl);
	freeaddrinfo(pAddr);

	int iResultShutdown = shutdown(sock, 2);
	if (iResultShutdown != 0) return 1;

	int iResultClose = close(sock);
	if (iResultClose == -1) return 1;

	return 0;
}
