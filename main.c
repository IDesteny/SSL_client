#include <openssl/ssl.h>
#include <winsock2.h>
#include <Ws2tcpip.h>

#pragma comment(lib, "ws2_32.lib")

#define HOST "www.pnzgu.ru"
#define DIR "/"

/* 64 KB */
#define RESSIZE 64 * 1024 

INT WINAPI main(VOID)
{
	WSADATA wsaData;
	INT iResultWSAStartup = WSAStartup(MAKEWORD(2, 2), &wsaData);
	if (iResultWSAStartup != 0) return EXIT_FAILURE;

	PADDRINFOA pAddr = NULL;
	INT iResultGetAddrInfo = getaddrinfo(HOST, "443", NULL, &pAddr);
	if (iResultGetAddrInfo != 0) return EXIT_FAILURE;

	SOCKET sock = socket(pAddr->ai_family, pAddr->ai_socktype, pAddr->ai_protocol);
	if (sock == INVALID_SOCKET) return EXIT_FAILURE;

	INT iResultConnet = connect(sock, pAddr->ai_addr, (INT)pAddr->ai_addrlen);
	if (iResultConnet != 0) return EXIT_FAILURE;

	SSL_library_init();
	SSL *ssl = SSL_new(SSL_CTX_new(SSLv23_method()));
	if (ssl == NULL) return EXIT_FAILURE;

	INT iResultSSL_set_fd = SSL_set_fd(ssl, (INT)sock);
	if (iResultSSL_set_fd == 0) return EXIT_FAILURE;

	INT iResultSSL_connect = SSL_connect(ssl);
	if (iResultSSL_connect != 1) return EXIT_FAILURE;

	LPCSTR template_headres = "GET %s HTTP/1.1\r\nHOST:%s\r\n\r\n";
	SIZE_T headers_len = strlen(template_headres) + strlen(HOST) + strlen(DIR);
	LPSTR headres = malloc(headers_len);
	if (headres == NULL) return EXIT_FAILURE;

	INT iResultSprintf_s = sprintf_s(headres, headers_len, template_headres, DIR, HOST);
	if (iResultSprintf_s == -1) return EXIT_FAILURE;

	INT iResultSSL_write = SSL_write(ssl, headres, (INT)strlen(headres));
	if (iResultSSL_write <= 0) return EXIT_FAILURE;

	LPSTR res = calloc(RESSIZE, sizeof(CHAR));
	if (res == NULL) return EXIT_FAILURE;

	/* TODO: Handle no data signal in non-blocking mode */
	for (INT iResultSSL_read = 0; iResultSSL_read < RESSIZE; iResultSSL_read += SSL_read(ssl, res + iResultSSL_read, RESSIZE - iResultSSL_read));

	INT iResultPrintf_s = printf_s("%s", res);
	if (iResultPrintf_s < 0) return EXIT_FAILURE;

	INT iResultSSL_shutdown = SSL_shutdown(ssl);
	if (iResultSSL_shutdown < 0) return EXIT_FAILURE;

	INT iResultSSL_clear = SSL_clear(ssl);
	if (iResultSSL_clear == 0) return EXIT_FAILURE;

	free(headres);
	free(res);
	SSL_free(ssl);
	freeaddrinfo(pAddr);

	INT iResultShutdown = shutdown(sock, SD_BOTH);
	if (iResultShutdown != 0) return EXIT_FAILURE;

	INT iResultClosesocket = closesocket(sock);
	if (iResultClosesocket != 0) return EXIT_FAILURE;

	INT iResultWSACleanup = WSACleanup();
	if (iResultWSACleanup != 0) return EXIT_FAILURE;
	
	return EXIT_SUCCESS;
}