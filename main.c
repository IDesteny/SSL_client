#include <openssl/ssl.h>
#include <winsock2.h>
#include <Ws2tcpip.h>
#include <stdio.h>
#include <tchar.h>

#pragma comment(lib, "ws2_32.lib")

#define HOST "github.com"
#define PORT "443"

#define RESSIZE 1024
#define HEADSIZE 64

#define ERRLOG(funcname) \
	_ftprintf(stderr, TEXT("\n### ERROR: %s() ###\n"), funcname);	

typedef SSL *LPSSL;


INT WINAPI _tmain(VOID)
{
	WSADATA wsaData;
	INT iResultWSAStartup = WSAStartup(MAKEWORD(2, 2), &wsaData);
	if (iResultWSAStartup != 0)
	{
		ERRLOG(TEXT("WSAStartup"));
		return EXIT_FAILURE;
	}

	PADDRINFOW pAddr = { 0 };
	INT iResultGetAddrInfo = GetAddrInfo(TEXT(HOST), TEXT(PORT), NULL, &pAddr);
	if (iResultGetAddrInfo != 0)
	{
		ERRLOG(TEXT("GetAddrInfo"));
		return EXIT_FAILURE;
	}

	SOCKET sock = socket(pAddr->ai_family, pAddr->ai_socktype, pAddr->ai_protocol);
	if (sock == INVALID_SOCKET)
	{
		ERRLOG(TEXT("socket"));
		return EXIT_FAILURE;
	}

	INT iResultConnet = connect(sock, pAddr->ai_addr, (INT)pAddr->ai_addrlen);
	if (iResultConnet != 0)
	{
		ERRLOG(TEXT("connect"));
		return EXIT_FAILURE;
	}

	SSL_library_init();
	LPSSL ssl = SSL_new(SSL_CTX_new(SSLv23_client_method()));
	if (ssl == NULL)
	{
		ERRLOG(TEXT("SSL_new"));
		return EXIT_FAILURE;
	}

	INT iResultSSL_set_fd = SSL_set_fd(ssl, (INT)sock);
	if (iResultSSL_set_fd == 0)
	{
		ERRLOG(TEXT("SSL_set_fd"));
		return EXIT_FAILURE;
	}

	INT iResultSSL_connect = SSL_connect(ssl);
	if (iResultSSL_connect != 1)
	{
		ERRLOG(TEXT("SSL_connect"));
		return EXIT_FAILURE;
	}

	LPCSTR template_headres = "GET / HTTP/1.1\r\nHOST: %s\r\n\r\n";
	CHAR headres[HEADSIZE] = { 0 };
	sprintf_s(headres, HEADSIZE, template_headres, HOST);

	INT iResultSSL_write = SSL_write(ssl, headres, (INT)strlen(headres));
	if (iResultSSL_write <= 0)
	{
		ERRLOG(TEXT("SSL_write"));
		return EXIT_FAILURE;
	}

	LPSTR res = malloc(RESSIZE);
	if (res == NULL)
	{
		ERRLOG(TEXT("malloc"));
		return EXIT_FAILURE;
	}

	INT iResultSSL_read = SSL_read(ssl, res, RESSIZE);
	if (iResultSSL_read <= 0)
	{
		ERRLOG(TEXT("SSL_read"));
		return EXIT_FAILURE;
	}

	INT iResultPrintf_s = printf_s("%s", res);
	if (iResultPrintf_s < 0)
	{
		ERRLOG(TEXT("printf_s"));
		return EXIT_FAILURE;
	}

	INT iResultSSL_shutdown = SSL_shutdown(ssl);
	if (iResultSSL_shutdown < 0)
	{
		ERRLOG(TEXT("SSL_shutdown"));
		return EXIT_FAILURE;
	}

	INT iResultSSL_clear = SSL_clear(ssl);
	if (iResultSSL_clear == 0)
	{
		ERRLOG(TEXT("SSL_clear"));
		return EXIT_FAILURE;
	}

	free(res);
	SSL_free(ssl);
	FreeAddrInfo(pAddr);

	INT iResultClosesocket = closesocket(sock);
	if (iResultClosesocket != 0)
	{
		ERRLOG(TEXT("closesocket"));
		return EXIT_FAILURE;
	}
	
	INT iResultWSACleanup = WSACleanup();
	if (iResultWSACleanup != 0)
	{
		ERRLOG(TEXT("WSACleanup"));
		return EXIT_FAILURE;
	}

	return EXIT_SUCCESS;
}