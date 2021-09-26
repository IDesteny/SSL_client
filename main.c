#include <openssl/ssl.h>
#include <winsock2.h>
#include <Ws2tcpip.h>

#pragma comment(lib, "ws2_32.lib")

#define HOST "github.com"
#define DIR "IDesteny"

#define SRES 128 * 1024

INT WINAPI main(VOID)
{
	WSADATA wsaData;
	INT iResultWSAStartup = WSAStartup(MAKEWORD(2, 2), &wsaData);
	if (iResultWSAStartup != EXIT_SUCCESS) return EXIT_FAILURE;

	SSL_library_init();
	SSL *ssl = SSL_new(SSL_CTX_new(SSLv23_method()));
	if (ssl == NULL) return EXIT_FAILURE;

	LPCSTR port = "443";
	PADDRINFOA pAddr = NULL;
	INT iResultGetAddrInfo = getaddrinfo(HOST, port, NULL, &pAddr);
	if (iResultGetAddrInfo != EXIT_SUCCESS) return EXIT_FAILURE;

	SOCKET sock = socket(pAddr->ai_family, pAddr->ai_socktype, pAddr->ai_protocol);
	if (sock == INVALID_SOCKET) return EXIT_FAILURE;

	INT iResultConnet = connect(sock, pAddr->ai_addr, (INT)pAddr->ai_addrlen);
	if (iResultConnet != EXIT_SUCCESS) return EXIT_FAILURE;

	INT iResultSSL_set_fd = SSL_set_fd(ssl, (INT)sock);
	if (iResultSSL_set_fd == FALSE) return EXIT_FAILURE;

	INT iResultSSL_connect = SSL_connect(ssl);
	if (iResultSSL_connect != TRUE) return EXIT_FAILURE;

	LPCSTR template_headres =
		"GET /%s HTTP/1.1\r\n"
		"Host: %s\r\n"
		"Connection: close\r\n"
		"\r\n";

	SIZE_T headers_len =
		strlen(template_headres) +
		strlen(HOST) +
		strlen(DIR);

	LPSTR headres = malloc(headers_len);
	if (headres == NULL) return EXIT_FAILURE;

	INT iResultSprintf_s = sprintf_s(headres, headers_len, template_headres, DIR, HOST);
	if (iResultSprintf_s == EOF) return EXIT_FAILURE;

	INT iResultSSL_write = SSL_write(ssl, headres, (INT)headers_len - 4);
	if (iResultSSL_write <= EXIT_SUCCESS) return EXIT_FAILURE;

	LPSTR res = calloc(SRES, sizeof(CHAR));
	if (res == NULL) return EXIT_FAILURE;

	INT iResultSSL_read = 0, countReaded = 0;
	do
	{
		iResultSSL_read = SSL_read(ssl, res + countReaded, SRES - countReaded);
		countReaded += iResultSSL_read;
	} while (iResultSSL_read > FALSE && countReaded < SRES);

	INT iResultSSL_shutdown = SSL_shutdown(ssl);
	if (iResultSSL_shutdown < EXIT_SUCCESS) return EXIT_FAILURE;

	INT iResultSSL_clear = SSL_clear(ssl);
	if (iResultSSL_clear == FALSE) return EXIT_FAILURE;

	free(headres);
	free(res);
	SSL_free(ssl);
	freeaddrinfo(pAddr);

	INT iResultShutdown = shutdown(sock, SD_BOTH);
	if (iResultShutdown != EXIT_SUCCESS) return EXIT_FAILURE;

	INT iResultClosesocket = closesocket(sock);
	if (iResultClosesocket != EXIT_SUCCESS) return EXIT_FAILURE;

	INT iResultWSACleanup = WSACleanup();
	if (iResultWSACleanup != EXIT_SUCCESS) return EXIT_FAILURE;

	return EXIT_SUCCESS;
}