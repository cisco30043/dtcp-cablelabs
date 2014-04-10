/*
** Copyright (C) 2013  Cable Television Laboratories, Inc.
** Contact: http://www.cablelabs.com/
*/

#include "DTCPAPI.h"
#include "DTCPError.h"
#include "DTCPTest.h"

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#ifdef __linux__
#include <pthread.h>
#endif

#include <curl/curl.h>
#include <iostream>
#include <cstring>
#include <string>
#include <fstream>
#include <iterator>

//  g++ -g -o testexe.exe obj/linux/* -ldl

// IP address used by source for AKE in decryption tests.
// It is passed to the sink during snk_open(). 
// Linux machine where this test program is running
char akeSrcIPMfr1[] = "192.168.1.102";
// Windows machine where the Mfr2 source exe is running
char akeSrcIPMfr2[] = "192.168.1.103";

// Port used by source for AKE in decryption tests.
// It is passed to the sink during snk_open(). 
//unsigned short akeSrcPort = 6677; // set to 8999 for httpTest() per ScottD ????
unsigned short akeSrcPort = 6677;

// Mfr1 DTCP Library path
char dllPathMfr1[] = "/home/dhooley/mfr1/dtcpip_mfr1_linux32_test.so";
// Mfr1 DTCP keys directory
char configStrMfr1[] = "/home/dhooley/mfr1/test_keys";
 
// Mfr2 DTCP Library path
char dllPathMfr2[] = "/home/dhooley/mfr2/dtcpip_mfr2_linux32_test.so";
// Mfr2 sink address and port first;source address and port second
char configStrMfr2[] = "192.168.1.103:49001;192.168.1.103:49002";

// Local filenames used in httpRequest() and then httpTest()
char httpFilename[FILENAME_MAX] = "from-http";
char httpHeaderFilename[FILENAME_MAX] = "from-http-headers";

int checkIPAndPort(char *pIPAndPort);
int httpTest(const char *sinkName);
int httpRequest();
int authTest1();
int authTest2();
int decryptionTestMfr1Src(const char *sinkName, int useMultiplePCPPackets);
int decryptionTestMfr2Src(const char *sinkName, int useMultiplePCPPackets);
int WaitForAKETest();
int getMultPCPPktExample (CDTCPTest *pSource, int source_session_handle, 
    unsigned char cci, char **ppEncryptedData, unsigned int *pEncryptedDataSz);
size_t writeData(void *ptr, size_t size, size_t nmemb, FILE *stream);

// Used when we need to block waiting for AKE to complete
int g_bAKEComplete = 0;
int g_session_handle;

#if defined ( _WIN32) || defined (__CYGWIN__)
DWORD WINAPI DecryptionThreadProc(LPVOID lpParameter);
#else
void *DecryptionThreadProc ( void *lpParameter );
#endif

int main(int argc, char* argv[])
{
    printf ("Hi There\n");
    printf ("argc = %d\n", argc);
    for (int i=0; i<argc; i++)
    {
        printf ("argv[%d] = %s\n", i, argv[i]);
    }
	char *whichTest = NULL;

	// checkIPAndPort(configStrMfr2);

	if (argc < 2)
	{
		printf("Test choices are:\n");
		printf("\tauthTest1:Local Cert from Mfr1;Verify from Mfr2\n");
		printf("\tauthTest2:Local Cert from Mfr2;Verify from Mfr1\n");
		printf("\tdecryptionTest1:Encrypts from Mfr1;Decrypts from Mfr2\n");
		printf("\t  decryptionTest1A:Uses multiple PCP Packets\n");
		printf("\tdecryptionTest2:Encrypts from Mfr2;Decrypts from Mfr1\n");
		printf("\t  decryptionTest2A:Uses multiple PCP Packets\n");
		printf("\tdecryptionTest3:Encrypts from Mfr1;Decrypts from Mfr1\n");
		printf("\t  decryptionTest3A:Uses multiple PCP Packets\n");
		printf("\tdecryptionTest4:Encrypts from Mfr2;Decrypts from Mfr2\n");
		printf("\t  decryptionTest4A:Uses multiple PCP Packets\n");
		printf("\thttpTest1:Uses Mfr1 library\n");
		printf("\thttpTest2:Uses Mfr2 library\n");
		printf("\tWaitForAKETest:Calls Mfr2 WaitForAKE with infinite timeout\n");
	}
	else 
	{
		// We only run 1 test at a time
		whichTest = argv[1];
		if (strcmp(whichTest, "authTest1") == 0)
		{
			authTest1();
		}
		else if (strcmp(whichTest, "authTest2") == 0)
		{
			authTest2();
		}
		else if (strcmp(whichTest, "decryptionTest1") == 0)
		{
			// use Mfr1 src;Mfr2 sink;single PCP packet
			decryptionTestMfr1Src("Mfr2", 0);
		}
		else if (strcmp(whichTest, "decryptionTest1A") == 0)
		{
			// use Mfr1 src;Mfr2 sink;multiple PCP packets
			decryptionTestMfr1Src("Mfr2", 1);
		}
		else if (strcmp(whichTest, "decryptionTest2") == 0)
		{
			// use Mfr2 src;Mfr1 sink;single PCP packet
			decryptionTestMfr2Src("Mfr1", 0);
		}
		else if (strcmp(whichTest, "decryptionTest2A") == 0)
		{
			// use Mfr2 src;Mfr1 sink;multiple PCP packets
			decryptionTestMfr2Src("Mfr1", 1);
		}
		else if (strcmp(whichTest, "decryptionTest3") == 0)
		{
			// use Mfr1 src;Mfr1 sink;single PCP packet
			decryptionTestMfr1Src("Mfr1", 0);
		}
		else if (strcmp(whichTest, "decryptionTest3A") == 0)
		{
			// use Mfr1 src;Mfr1 sink;multiple PCP packets
			decryptionTestMfr1Src("Mfr1", 1);
		}
		else if (strcmp(whichTest, "decryptionTest4") == 0)
		{
			// use Mfr2 src;Mfr2 sink;single PCP packet
			decryptionTestMfr2Src("Mfr2", 0);
		}
		else if (strcmp(whichTest, "decryptionTest4A") == 0)
		{
			// use Mfr2 src;Mfr2 sink;multiple PCP packets
			decryptionTestMfr2Src("Mfr2", 1);
		}
		else if (strcmp(whichTest, "httpTest1") == 0)
		{
			if (httpRequest() == DTCP_ERROR_SUCCESS)
			{
				httpTest("Mfr1");
			}
		}
		else if (strcmp(whichTest, "httpTest2") == 0)
		{
			if (httpRequest() == DTCP_ERROR_SUCCESS)
			{
				httpTest("Mfr2");
			}
		}
		else if (strcmp(whichTest, "WaitForAKETest") == 0)
		{
			WaitForAKETest();
		}
		else
		{
    		printf ("Unknown test: %s\n", whichTest);
		}
	}

    return 0;
} // main()

int checkIPAndPort(char *pIPAndPort)
{
    // pIPAndPort is of the form n.n.n.n:port;n.n.n.n:port, with sink first
    // and source second, so need to parse it.

    char sinkSvrAddr[100];
    unsigned int sinkSvrPort = 0;
    char sourceSvrAddr[100];
    unsigned int sourceSvrPort = 0;

    printf ("pIPAndPort = %s\n", pIPAndPort);

    char *pTempString = strtok (pIPAndPort, ";");
    char * pDelimiter = strchr (pTempString, ':');
    if (pDelimiter == NULL)
    {
        return DTCP_ERROR_INVALID_IP_PORT_STRING;
    }

    int nReturnCode = sscanf (pDelimiter+1, "%d", &sinkSvrPort);
    if (nReturnCode <= 0)
    {
        return DTCP_ERROR_INVALID_IP_PORT_STRING;
    }

    int delta = pDelimiter - pIPAndPort;
    memcpy (sinkSvrAddr, pIPAndPort, delta);
    memcpy (sinkSvrAddr + delta, "", 1);

    pTempString = strtok (NULL, ";");
    pDelimiter = strchr (pTempString, ':');
    if (pDelimiter == NULL)
    {
        return DTCP_ERROR_INVALID_IP_PORT_STRING;
    }
    nReturnCode = sscanf (pDelimiter+1, "%d", &sourceSvrPort);
    if (nReturnCode <= 0)
    {
        return DTCP_ERROR_INVALID_IP_PORT_STRING;
    }

    delta = pDelimiter - pTempString;
    memcpy (sourceSvrAddr, pTempString, delta);
    memcpy (sourceSvrAddr + delta, "", 1);

    printf ("g_sinkSvrAddr = %s\n", sinkSvrAddr);
    printf ("g_sinkSvrPort = %d\n", sinkSvrPort);
    printf ("g_sourceSvrAddr = %s\n", sourceSvrAddr);
    printf ("g_sourceSvrPort = %d\n", sourceSvrPort);

	return DTCP_ERROR_SUCCESS;
} // checkIPAndPort()

int httpTest(const char *sinkName)
{
    char* encrypted_data = 0;
    std::ifstream::pos_type encrypted_size = 0;
	char *dllPath = NULL;
	char *configStr = NULL;
	char *akeSrcIP = NULL;

    printf ("Starting HTTP decryption test using %s DTCP Library...\n", sinkName);
	if (strcmp(sinkName, "Mfr2") == 0)
	{
		dllPath = dllPathMfr2;
		configStr = configStrMfr2;
		akeSrcIP = akeSrcIPMfr2;
	}
	else if (strcmp(sinkName, "Mfr1") == 0)
	{
		dllPath = dllPathMfr1;
		configStr = configStrMfr1;
		akeSrcIP = akeSrcIPMfr1;
	}
	else
	{
    	printf("Unrecognized DTCP library name %s\n", sinkName);
		return DTCP_ERROR_UNKNOWN_DTCP_LIBRARY;
	}

    std::ifstream file (httpFilename, std::ios::in|std::ios::binary|std::ios::ate);
    if(file.is_open())
    {
        encrypted_size = file.tellg();
        file.seekg (0, std::ios::beg);
        encrypted_data = new char [encrypted_size];
        file.read (encrypted_data, encrypted_size);
        file.close();
        printf("File %s available - size: %d\n", httpFilename, (int)encrypted_size);
    }
    else
    {
       printf("File %s is not available!\n", httpFilename);
       return DTCP_ERROR_FILE_NOT_AVAILABLE;
    }

    int nReturnCode;
    CDTCPTest *pSink = new CDTCPTest();

    printf ("Initializing %s ...\n", sinkName);
    nReturnCode = pSink->initDTCP(dllPath, configStr);
    if (nReturnCode != DTCP_ERROR_SUCCESS)
    {
        printf ("Error %d initializing %s\n", nReturnCode, sinkName);
        return nReturnCode;
    }
    printf ("Initialized %s!\n", sinkName);

    int session_handle;
    printf ("%s: dtcpip_snk_open...\n", sinkName);
    nReturnCode = pSink->dtcpip_snk_open (akeSrcIP, akeSrcPort, &session_handle);
    printf ("%s: dtcpip_snk_open...session_handle = %d\n", sinkName, session_handle);
    if (nReturnCode != DTCP_ERROR_SUCCESS)
    {
        printf ("%s: Error %d opening sink\n", sinkName, nReturnCode);
        return nReturnCode;
    }

	sleep (5);

    char* final_cleartext_data;
    unsigned int final_cleartext_size;
    printf ("%s: dtcpip_snk_alloc_decrypt...session_handle = %d\n", sinkName, session_handle);
    nReturnCode = pSink->dtcpip_snk_alloc_decrypt(session_handle, encrypted_data, encrypted_size,
        &final_cleartext_data, &final_cleartext_size);
    if (nReturnCode != DTCP_ERROR_SUCCESS)
    {
        printf ("%s: Error %d decrypting\n", sinkName, nReturnCode);
        return nReturnCode;
    }

    printf ("final_cleartext_size = %d\n", final_cleartext_size);
    printf ("final_cleartext_data = %s\n", final_cleartext_data);
        
    printf ("HTTP Decryption Test complete\n");

	sleep (5);

    nReturnCode = pSink->dtcpip_snk_close(session_handle);
    if (nReturnCode != DTCP_ERROR_SUCCESS)
    {
        printf ("%s: Error %d closing\n", sinkName, nReturnCode);
    }

    delete[] encrypted_data;
    return nReturnCode;
} // httpTest()

int httpRequest()
{
    CURL *curl_handle;
    CURLcode res;
    curl_handle = curl_easy_init();

    static FILE *outfile;
    static FILE *headerfile;

	printf("initiating http request\n");
    outfile = fopen(httpFilename,"w");
    if (outfile == NULL) 
	{
        printf("Error: failed to open file %s\n", httpFilename);
    	return DTCP_ERROR_FILE_NOT_AVAILABLE;
    }
    headerfile = fopen(httpHeaderFilename,"w");
    if (headerfile == NULL) 
	{
        printf("Error: failed to open file %s\n", httpHeaderFilename);
   		return DTCP_ERROR_FILE_NOT_AVAILABLE;
    }

    curl_easy_setopt(curl_handle, CURLOPT_URL, "http://localhost/text.html");
    curl_easy_setopt(curl_handle, CURLOPT_WRITEDATA, outfile);
    curl_easy_setopt(curl_handle, CURLOPT_WRITEHEADER, headerfile);
    res = curl_easy_perform(curl_handle);
    fclose(outfile);
    fclose(headerfile);
    if (res != CURLE_OK)
    {
        printf("Error: %s\n", curl_easy_strerror(res));
        return DTCP_ERROR_FILE_NOT_AVAILABLE;
    }
    curl_easy_cleanup(curl_handle);
	printf("http request was successful!\n");
    return DTCP_ERROR_SUCCESS;

} // httpRequest()

// Local Cert from Mfr1; Verify from Mfr2
int authTest1()
{
    int nReturnCode;
	unsigned char pLocalCert[DTCP_CERT_SZ];
    unsigned int  nLocalCertSz = DTCP_CERT_SZ;
    unsigned char pSignature[DTCP_HASH_SIG_SZ];
    unsigned int  nSignatureSz = DTCP_HASH_SIG_SZ;

    char pTestString[] = "This is a test";
    unsigned int nTestStringSz = strlen(pTestString) + 1;

    printf ("Starting auth test 1...\n");

    printf ("Initializing Mfr1...\n");
    CDTCPTest *pMfr1 = new CDTCPTest();
    nReturnCode = pMfr1->initDTCP(dllPathMfr1, configStrMfr1);
    if (nReturnCode != DTCP_ERROR_SUCCESS)
    {
        printf ("Error %d initializing Mfr1\n", nReturnCode);
        return nReturnCode;
    }
    printf ("Initialized Mfr1!\n");

    printf ("Initializing Mfr2...\n");
    CDTCPTest *pMfr2 = new CDTCPTest();
    nReturnCode = pMfr2->initDTCP(dllPathMfr2, configStrMfr2);
    if (nReturnCode != DTCP_ERROR_SUCCESS)
    {
        printf ("Error %d initializing Mfr2\n", nReturnCode);
        return nReturnCode;
    }
    printf ("Initialized Mfr2!\n");

    printf ("Mfr1: GetLocalCert...\n");
    nReturnCode = pMfr1->DTCPIPAuth_GetLocalCert(pLocalCert, &nLocalCertSz);
    if (nReturnCode != DTCP_ERROR_SUCCESS)
    {
        printf ("Mfr1: Error %d getting local cert\n", nReturnCode);
        return nReturnCode;
    }

    printf ("Mfr1: SignData...\n");
    nReturnCode = pMfr1->DTCPIPAuth_SignData ((unsigned char*)pTestString, nTestStringSz, pSignature, &nSignatureSz);
    if (nReturnCode != DTCP_ERROR_SUCCESS)
    {
        printf ("Mfr1: Error %d getting signature\n", nReturnCode);
        return nReturnCode;
    }

    printf ("Mfr2: VerifyRemoteCert...\n");
    nReturnCode = pMfr2->DTCPIPAuth_VerifyRemoteCert(pLocalCert, DTCP_CERT_SZ);
    if (nReturnCode != DTCP_ERROR_SUCCESS)
    {
        printf ("Mfr2: Error %d verifying cert\n", nReturnCode);
        return nReturnCode;
    }

   printf ("Mfr2: VerifyData...\n");
    nReturnCode = pMfr2->DTCPIPAuth_VerifyData((unsigned char*)pTestString, nTestStringSz, pSignature, pLocalCert);
    if (nReturnCode != DTCP_ERROR_SUCCESS)
    {
        printf ("Mfr2: Error %d verifying signature\n", nReturnCode);
        return nReturnCode;
    }

    printf ("Auth test 1 complete\n");
    return nReturnCode;
} // authTest1()

// Local Cert from Mfr2; Verify from Mfr1
int authTest2()
{
    int nReturnCode;

	unsigned char pLocalCert[DTCP_CERT_SZ];
    unsigned int  nLocalCertSz = DTCP_CERT_SZ;
    unsigned char pSignature[DTCP_HASH_SIG_SZ];
    unsigned int  nSignatureSz = DTCP_HASH_SIG_SZ;

    char pTestString[] = "This is a test";
    unsigned int nTestStringSz = strlen(pTestString) + 1;

    printf ("Starting auth test 2...\n");

    printf ("Initializing Mfr1...\n");
    CDTCPTest *pMfr1 = new CDTCPTest();
    nReturnCode = pMfr1->initDTCP(dllPathMfr1, configStrMfr1);
    if (nReturnCode != DTCP_ERROR_SUCCESS)
    {
        printf ("Error %d initializing Mfr1\n", nReturnCode);
        return nReturnCode;
    }
    printf ("Initialized Mfr1!\n");

    printf ("Initializing Mfr2...\n");
    CDTCPTest *pMfr2 = new CDTCPTest();
    nReturnCode = pMfr2->initDTCP(dllPathMfr2, configStrMfr2);
    if (nReturnCode != DTCP_ERROR_SUCCESS)
    {
        printf ("Error %d initializing Mfr2\n", nReturnCode);
        return nReturnCode;
    }
    printf ("Initialized Mfr2!\n");

    printf ("Mfr2: GetLocalCert...\n");
    nReturnCode = pMfr2->DTCPIPAuth_GetLocalCert(pLocalCert, &nLocalCertSz);
    if (nReturnCode != DTCP_ERROR_SUCCESS)
    {
        printf ("Mfr2: Error %d getting local cert\n", nReturnCode);
        return nReturnCode;
    }

    printf ("Mfr2: SignData...\n");
    nReturnCode = pMfr2->DTCPIPAuth_SignData ((unsigned char*)pTestString, nTestStringSz, pSignature, &nSignatureSz);
    if (nReturnCode != DTCP_ERROR_SUCCESS)
    {
        printf ("Mfr2: Error %d getting signature\n", nReturnCode);
        return nReturnCode;
    }

    printf ("Mfr1: VerifyRemoteCert...\n");
    nReturnCode = pMfr1->DTCPIPAuth_VerifyRemoteCert(pLocalCert, DTCP_CERT_SZ);
    if (nReturnCode != DTCP_ERROR_SUCCESS)
    {
        printf ("Mfr1: Error %d verifying cert\n", nReturnCode);
        return nReturnCode;
    }

	printf ("Mfr1: VerifyData...\n");
    nReturnCode = pMfr1->DTCPIPAuth_VerifyData((unsigned char*)pTestString, nTestStringSz, pSignature, pLocalCert);
    if (nReturnCode != DTCP_ERROR_SUCCESS)
    {
        printf ("Mfr1: Error %d verifying signature\n", nReturnCode);
        return nReturnCode;
    }

    printf ("Auth test 2 complete\n");
    return nReturnCode;
} // authTest2()

/* Encrypts using Mfr1 source - Decrypts using specified sink */
int decryptionTestMfr1Src(const char *sinkName, int useMultiplePCPPackets)
{
    int nReturnCode;
	char *dllPath = NULL;
    char *configStr = NULL;
	char *akeSrcIP = akeSrcIPMfr1;

    if (strcmp(sinkName, "Mfr2") == 0)
    {
        dllPath = dllPathMfr2;
        configStr = configStrMfr2;
    }
    else if (strcmp(sinkName, "Mfr1") == 0)
    {
        dllPath = dllPathMfr1;
        configStr = configStrMfr1;
    }
    else
    {
        printf("Unrecognized DTCP library name %s\n", sinkName);
        return DTCP_ERROR_UNKNOWN_DTCP_LIBRARY;
    }

    printf ("Starting Decryption Test using Mfr1 src and %s snk...\n", sinkName);

    printf ("Initializing Mfr1 source...\n");
	printf ("Mfr1 config str %s\n", configStrMfr1);
    CDTCPTest *pSource = new CDTCPTest();
    nReturnCode = pSource->initDTCP(dllPathMfr1, configStrMfr1);
    if (nReturnCode != DTCP_ERROR_SUCCESS)
    {
        printf ("Error %d initializing Mfr1 src\n", nReturnCode);
        return nReturnCode;
    }
    printf ("Initialized Mfr1 source!\n");

    printf ("Initalizing %s sink...\n", sinkName);
    CDTCPTest *pSink = new CDTCPTest();
    nReturnCode = pSink->initDTCP(dllPath, configStr);
    if (nReturnCode != DTCP_ERROR_SUCCESS)
    {
        printf ("Error %d initializing %s\n", nReturnCode, sinkName);
        return nReturnCode;
    }
    printf ("Initialized %s sink!\n", sinkName);

    printf ("Mfr1: dtcpip_src_init...\n");
    nReturnCode = pSource->dtcpip_src_init(akeSrcPort);
    if (nReturnCode != DTCP_ERROR_SUCCESS)
    {
        printf ("Mfr1: Error %d initializing encryption session\n", nReturnCode);
        return nReturnCode;
    }

	sleep(1);

    printf ("Mfr1: dtcpip_src_open...\n");
    int source_session_handle;
    nReturnCode = pSource->dtcpip_src_open(&source_session_handle, 0 /* audio_only */);
    if (nReturnCode != DTCP_ERROR_SUCCESS)
    {
        printf ("Mfr1: Error %d opening encryption session\n", nReturnCode);
        return nReturnCode;
    }
    printf ("Mfr1: dtcpip_src_open: %d\n", source_session_handle);

    sleep (5);

    int sink_session_handle;
    printf ("%s: dtcpip_snk_open...\n", sinkName);
    nReturnCode = pSink->dtcpip_snk_open (akeSrcIP, akeSrcPort, &sink_session_handle);
    if (nReturnCode != DTCP_ERROR_SUCCESS)
    {
        printf ("%s: Error %d opening sink\n", sinkName, nReturnCode);
        return nReturnCode;
    }
    printf ("%s: dtcpip_snk_open returned sink_session_handle = %d\n", 
		sinkName, sink_session_handle);

	sleep (5);

    unsigned char cci = 0x02;
    char* encrypted_data;
    unsigned int encrypted_size;
    char* final_cleartext_data;
    unsigned int final_cleartext_size;
	if (useMultiplePCPPackets > 0)
    {
        nReturnCode = getMultPCPPktExample(pSource, source_session_handle,
            cci, &encrypted_data, &encrypted_size);
        if (nReturnCode != DTCP_ERROR_SUCCESS)
        {
            printf ("Mfr1: Error %d encrypting\n", nReturnCode);
            return nReturnCode;
        }

        printf ("%s: dtcpip_snk_alloc_decrypt first 10 bytes...\n", sinkName);
        nReturnCode = pSink->dtcpip_snk_alloc_decrypt(sink_session_handle,
            encrypted_data, 10,
            &final_cleartext_data, &final_cleartext_size);
        if (nReturnCode != DTCP_ERROR_SUCCESS)
        {
            printf ("%s: Error %d decrypting\n", sinkName, nReturnCode);
            return nReturnCode;
        }

        printf ("final_cleartext_size = %d\n", final_cleartext_size);
        printf ("final_cleartext_data = ");
        for (unsigned int i=0; i<final_cleartext_size; i++)
        {
            printf ("%c", final_cleartext_data[i]);
        }
        printf ("\n\n");

 		nReturnCode = pSink->dtcpip_snk_free(final_cleartext_data);
    	if (nReturnCode != DTCP_ERROR_SUCCESS)
    	{
        	printf ("%s: Error %d snk_free\n", sinkName, nReturnCode);
            return nReturnCode;
    	}

        printf ("%s: dtcpip_snk_alloc_decrypt second 10 bytes...\n", sinkName);
        nReturnCode = pSink->dtcpip_snk_alloc_decrypt(sink_session_handle,
            encrypted_data + 10, encrypted_size - 10,
            &final_cleartext_data, &final_cleartext_size);
        if (nReturnCode != DTCP_ERROR_SUCCESS)
        {
            printf ("%s: Error %d decrypting\n", sinkName, nReturnCode);
            return nReturnCode;
        }

        printf ("final_cleartext_size = %d\n", final_cleartext_size);
        printf ("final_cleartext_data = ");
        for (unsigned int i=0; i<final_cleartext_size; i++)
        {
            printf ("%c", final_cleartext_data[i]);
        }
        printf ("\n\n");

 		nReturnCode = pSink->dtcpip_snk_free(final_cleartext_data);
    	if (nReturnCode != DTCP_ERROR_SUCCESS)
    	{
        	printf ("%s: Error %d snk_free\n", sinkName, nReturnCode);
            return nReturnCode;
    	}
	}
	else // single PCP packet
	{
    	char initial_cleartext_data[] = "This is the encryption string for decryptionTestMfr1Src";
    	unsigned int initial_cleartext_size = strlen(initial_cleartext_data) + 1;

    	printf ("Mfr1: dtcpip_src_alloc_encrypt...\n");
    	nReturnCode = pSource->dtcpip_src_alloc_encrypt(source_session_handle, 
			cci, initial_cleartext_data, initial_cleartext_size,
        	&encrypted_data, &encrypted_size);
    	if (nReturnCode != DTCP_ERROR_SUCCESS)
    	{
        	printf ("Mfr1: Error %d encrypting\n", nReturnCode);
        	return nReturnCode;
    	}

    	printf ("Mfr1: encrypted data: encrypted_size = %d\n", encrypted_size);
    	for (unsigned int i=0; i<encrypted_size; i++)
    	{
        	printf  ("0x%x ", encrypted_data[i]);
        	if (i%8 == 7)
        	{
            	printf ("\n");
        	}
    	}

    	printf ("%s: dtcpip_snk_alloc_decrypt...sink_session_handle = %d\n", 
			sinkName, sink_session_handle);
    	nReturnCode = pSink->dtcpip_snk_alloc_decrypt(sink_session_handle, 
			encrypted_data, encrypted_size,
        	&final_cleartext_data, &final_cleartext_size);
    	if (nReturnCode != DTCP_ERROR_SUCCESS)
    	{
       		printf ("%s: Error %d decrypting\n", sinkName, nReturnCode);
        	return nReturnCode;
    	}

    	printf ("final_cleartext_size = %d\n", final_cleartext_size);
    	printf ("final_cleartext_data = %s\n", final_cleartext_data);
      
 		nReturnCode = pSink->dtcpip_snk_free(final_cleartext_data);
    	if (nReturnCode != DTCP_ERROR_SUCCESS)
    	{
        	printf ("%s: Error %d snk_free\n", sinkName, nReturnCode);
            return nReturnCode;
    	}
	} // single PCP packet

	sleep(5);
	printf("Closing sink session...\n");
    nReturnCode = pSink->dtcpip_snk_close(sink_session_handle);
    if (nReturnCode != DTCP_ERROR_SUCCESS)
    {
        printf ("%s: Error %d closing snk session\n", sinkName, nReturnCode);
        return nReturnCode;
    }

	sleep (5);
	printf("Closing source session...\n");
    nReturnCode = pSource->dtcpip_src_close(source_session_handle);
    if (nReturnCode != DTCP_ERROR_SUCCESS)
    {
        printf ("Mfr1: Error %d closing src session\n", nReturnCode);
        return nReturnCode;
    }

    printf ("Decryption Test complete\n");
    return nReturnCode;
} // decryptionTestMfr1Src()

/* Encrypts using Mfr2 source - Decrypts using specified sink */
int decryptionTestMfr2Src(const char *sinkName, int useMultiplePCPPackets)
{
   	int nReturnCode; 
    char *dllPath = NULL;
	char *configStr = NULL;
	char *akeSrcIP = akeSrcIPMfr2;

	if (strcmp(sinkName, "Mfr2") == 0)
	{
		dllPath = dllPathMfr2;
		configStr = configStrMfr2;
	}
	else if (strcmp(sinkName, "Mfr1") == 0)
	{
		dllPath = dllPathMfr1;
		configStr = configStrMfr1;
	}
	else
	{
    	printf("Unrecognized DTCP library name %s\n", sinkName);
		return DTCP_ERROR_UNKNOWN_DTCP_LIBRARY;
	}

    printf ("Starting Decryption Test using Mfr2 src and %s snk...\n", sinkName);

    printf ("Initializing Mfr2 source...\n");
    printf ("Mfr2 config str %s\n", configStrMfr2);
    CDTCPTest *pSource = new CDTCPTest();
    nReturnCode = pSource->initDTCP(dllPathMfr2, configStrMfr2);
    if (nReturnCode != DTCP_ERROR_SUCCESS)
    {
        printf ("Error %d initializing Mfr2 src\n", nReturnCode);
        return nReturnCode;
    }
    printf ("Initialized Mfr2 source!\n");

    // Mfr2 source blocks until AKE completes, so need it in a different thread
#if defined ( _WIN32) || defined (__CYGWIN__)
    HANDLE WINAPI hThread = CreateThread(NULL /* LPSECURITY_ATTRIBUTES lpThreadAttributes */,
        0 /* SIZE_T dwStackSize */,
        DecryptionThreadProc, pSource, 0, NULL);
#else
    pthread_t akeThread;
    pthread_create (&akeThread, NULL, &DecryptionThreadProc, (void*)pSource);
#endif

	// wait for new thread to get going
    sleep (5);

    printf ("Initializing %s sink...\n", sinkName);
    CDTCPTest *pSink = new CDTCPTest();
    nReturnCode = pSink->initDTCP(dllPath, configStr);
    if (nReturnCode != DTCP_ERROR_SUCCESS)
    {
        printf ("Error %d initializing %s snk\n", nReturnCode, sinkName);
        return nReturnCode;
    }
    printf ("Initialized %s sink!\n", sinkName);

    printf ("%s: dtcpip_snk_open...\n", sinkName);
    int sink_session_handle;
    nReturnCode = pSink->dtcpip_snk_open (akeSrcIP, akeSrcPort, &sink_session_handle);
    if (nReturnCode != DTCP_ERROR_SUCCESS)
    {
        sleep (15);
        printf ("%s: Error %d opening sink\n", sinkName, nReturnCode);
        return nReturnCode;
    }
    printf ("%s: dtcpip_snk_open returned sink_session_handle = %d\n", 
		sinkName, sink_session_handle);

    // wait until AKE complete
    for (int i=0; i<60; i++)
    {
        if (g_bAKEComplete)
        {
            printf ("g_bAKEComplete is true\n");
            break;
        }
        sleep (1);
    }
	sleep (10);

	// should be OK to start Mfr2 encryption now
	unsigned char cci = 0x02;
    char* encrypted_data;
    unsigned int encrypted_size;
    char* final_cleartext_data;
    unsigned int final_cleartext_size;
	if (useMultiplePCPPackets > 0)
	{
    	nReturnCode = getMultPCPPktExample(pSource, g_session_handle,
			cci, &encrypted_data, &encrypted_size);
    	if (nReturnCode != DTCP_ERROR_SUCCESS)
    	{
        	printf ("Mfr2: Error %d encrypting\n", nReturnCode);
        	return nReturnCode;
    	}

    	printf ("%s: dtcpip_snk_alloc_decrypt first 10 bytes...\n", sinkName);
    	nReturnCode = pSink->dtcpip_snk_alloc_decrypt(sink_session_handle, 
			encrypted_data, 10,
       	 	&final_cleartext_data, &final_cleartext_size);
    	if (nReturnCode != DTCP_ERROR_SUCCESS)
    	{
        	printf ("%s: Error %d decrypting\n", sinkName, nReturnCode);
        	return nReturnCode;
    	}

    	printf ("final_cleartext_size = %d\n", final_cleartext_size);
    	printf ("final_cleartext_data = ");
    	for (unsigned int i=0; i<final_cleartext_size; i++)
    	{
        	printf ("%c", final_cleartext_data[i]);
    	}
    	printf ("\n\n");

 		nReturnCode = pSink->dtcpip_snk_free(final_cleartext_data);
    	if (nReturnCode != DTCP_ERROR_SUCCESS)
    	{
        	printf ("%s: Error %d snk_free\n", sinkName, nReturnCode);
        	return nReturnCode;
    	}

    	printf ("%s: dtcpip_snk_alloc_decrypt second 10 bytes...\n", sinkName);
    	nReturnCode = pSink->dtcpip_snk_alloc_decrypt(sink_session_handle, 
			encrypted_data+ 10, encrypted_size - 10,
        	&final_cleartext_data, &final_cleartext_size);
    	if (nReturnCode != DTCP_ERROR_SUCCESS)
    	{
        	printf ("%s: Error %d decrypting\n", sinkName, nReturnCode);
        	return nReturnCode;
    	}

    	printf ("final_cleartext_size = %d\n", final_cleartext_size);
    	printf ("final_cleartext_data = ");
    	for (unsigned int i=0; i<final_cleartext_size; i++)
    	{
        	printf ("%c", final_cleartext_data[i]);
    	}
    	printf ("\n\n");

 		nReturnCode = pSink->dtcpip_snk_free(final_cleartext_data);
    	if (nReturnCode != DTCP_ERROR_SUCCESS)
    	{
        	printf ("%s: Error %d snk_free\n", sinkName, nReturnCode);
        	return nReturnCode;
    	}
	} 
	else // single PCP packet
	{
    	char initial_cleartext_data[] = "This is the encryption string for decryptionTestMfr2Src";
    	unsigned int initial_cleartext_size = strlen(initial_cleartext_data) + 1;
    	printf ("Mfr2: dtcpip_src_alloc_encrypt...\n");
    	nReturnCode = pSource->dtcpip_src_alloc_encrypt(g_session_handle, cci, 
          initial_cleartext_data, initial_cleartext_size,
          &encrypted_data, &encrypted_size);
    	if (nReturnCode != DTCP_ERROR_SUCCESS)
    	{
        	printf ("Mfr2: Error %d encrypting\n", nReturnCode);
        	return nReturnCode;
    	}

    	printf ("Mfr2: encrypted data: encrypted_size = %d\n", encrypted_size);
    	for (unsigned int i=0; i<encrypted_size; i++)
    	{
       		printf  ("0x%x ", encrypted_data[i]);
       	 	if (i%8 == 7)
       	 	{
            	printf ("\n");
         	}
    	}

    	printf ("%s: dtcpip_snk_alloc_decrypt...\n", sinkName);
    	nReturnCode = pSink->dtcpip_snk_alloc_decrypt(sink_session_handle, 
			encrypted_data, encrypted_size,
        	&final_cleartext_data, &final_cleartext_size);
    	if (nReturnCode != DTCP_ERROR_SUCCESS)
    	{
        	printf ("%s: Error %d decrypting\n", sinkName, nReturnCode);
        	return nReturnCode;
    	}

	    printf ("final_cleartext_size = %d\n", final_cleartext_size);
    	printf ("final_cleartext_data = %s\n", final_cleartext_data);

 		nReturnCode = pSink->dtcpip_snk_free(final_cleartext_data);
    	if (nReturnCode != DTCP_ERROR_SUCCESS)
    	{
        	printf ("%s: Error %d snk_free\n", sinkName, nReturnCode);
        	return nReturnCode;
    	}
	} // single PCP packet

    sleep (5);
    printf ("Closing sink session...\n");
    nReturnCode = pSink->dtcpip_snk_close(sink_session_handle);
    if (nReturnCode != DTCP_ERROR_SUCCESS)
    {
        printf ("%s: Error %d closing snk session\n", sinkName, nReturnCode);
        return nReturnCode;
    }

    sleep (5);
    printf ("Closing source session...\n");
    nReturnCode = pSource->dtcpip_src_close(g_session_handle);
    if (nReturnCode != DTCP_ERROR_SUCCESS)
    {
        printf ("Mfr2: Error %d closing src session\n", nReturnCode);
        return nReturnCode;
    }

    printf ("Decryption Test complete\n");
    return nReturnCode;
} // decryptionTestMfr2Src()

// This test tests the behavior of the Mfr2 DTCP lib when WaitForAKE is
// called with an infinite timeout.
int WaitForAKETest()
{
    int nReturnCode;
    g_session_handle = 0;
    g_bAKEComplete = 0;

    printf ("Starting WaitForAKETest...\n");

    // use Mfr2 source
    printf ("Initializing Mfr2 source...\n");
    printf ("Mfr2 config str %s\n", configStrMfr2);
    CDTCPTest *pSource = new CDTCPTest();
    nReturnCode = pSource->initDTCP(dllPathMfr2, configStrMfr2);
    if (nReturnCode != DTCP_ERROR_SUCCESS)
    {
        printf ("Error %d initializing Mfr2\n", nReturnCode);
        return nReturnCode;
    }
    printf ("Initialized Mfr2 source!\n");

    // the following blocks until AKE completes, so need it in a different thread
#if defined ( _WIN32) || defined (__CYGWIN__)
    HANDLE WINAPI hThread = CreateThread(NULL /* LPSECURITY_ATTRIBUTES lpThreadAttributes */,
        0 /* SIZE_T dwStackSize */,
        DecryptionThreadProc, pSource, 0, NULL);
#else
    pthread_t akeThread;
    pthread_create (&akeThread, NULL, &DecryptionThreadProc, (void*)pSource);
#endif

    // wait until AKE complete
    printf ("Entering AKE wait loop...\n");
    for (int i=0; i<60; i++)
    {
        if (g_bAKEComplete)
        {
            printf ("g_bAKEComplete is true\n");
            break;
        }
        sleep (1);
    }

    if (!g_bAKEComplete)
    {
        printf ("AKE never completed\n");
    }

    printf ("Closing source session (this will deregister)...\n");
    nReturnCode = pSource->dtcpip_src_close(g_session_handle);
    if (nReturnCode != DTCP_ERROR_SUCCESS)
    {
        printf ("Source: Error %d closing session\n", nReturnCode);
        sleep (5);
        return nReturnCode;
    }

    sleep (10);

    printf ("WaitForAKETest complete\n");
    return nReturnCode;
} // WaitForAKETest()

int getMultPCPPktExample (CDTCPTest *pSource, int source_session_handle, 
	unsigned char cci, char **ppEncryptedData, unsigned int *pEncryptedDataSz)
{
	int nReturnCode;
    char initial_cleartext_data_1[] = "This is a really long encryption test string";
    unsigned int initial_cleartext_size_1 = strlen(initial_cleartext_data_1) + 1;
    char initial_cleartext_data_2[] = "This is another really long encryption test string";
    unsigned int initial_cleartext_size_2 = strlen(initial_cleartext_data_2) + 1;
    char initial_cleartext_data_3[] = "This is still another really long encryption test string";
    unsigned int initial_cleartext_size_3 = strlen(initial_cleartext_data_3) + 1;

    char* encrypted_data_1;
    unsigned int encrypted_size_1;
    printf ("getMultPCPPktExample #1: dtcpip_src_alloc_encrypt...\n");
	nReturnCode = pSource->dtcpip_src_alloc_encrypt(source_session_handle, cci,
		initial_cleartext_data_1, initial_cleartext_size_1,
        &encrypted_data_1, &encrypted_size_1);
    if (nReturnCode != DTCP_ERROR_SUCCESS)
    {
        printf ("Error %d encrypting #1\n", nReturnCode);
        return nReturnCode;
    }

    char* encrypted_data_2;
    unsigned int encrypted_size_2;
    printf ("getMultPCPPktExample #2: dtcpip_src_alloc_encrypt...\n");
    nReturnCode = pSource->dtcpip_src_alloc_encrypt(source_session_handle, cci, 
        initial_cleartext_data_2, initial_cleartext_size_2,
        &encrypted_data_2, &encrypted_size_2);
    if (nReturnCode != DTCP_ERROR_SUCCESS)
    {
        printf ("Error %d encrypting #2\n", nReturnCode);
        return nReturnCode;
    }

    char* encrypted_data_3;
    unsigned int encrypted_size_3;
    printf ("getMultPCPPktExample #3: dtcpip_src_alloc_encrypt...\n");
    nReturnCode = pSource->dtcpip_src_alloc_encrypt(source_session_handle, cci, 
        initial_cleartext_data_3, initial_cleartext_size_3,
        &encrypted_data_3, &encrypted_size_3);
    if (nReturnCode != DTCP_ERROR_SUCCESS)
    {
        printf ("Error %d encrypting #3\n", nReturnCode);
        return nReturnCode;
    }

    *ppEncryptedData = (char *) malloc (encrypted_size_1 + encrypted_size_2 + encrypted_size_3);
    memcpy (*ppEncryptedData, encrypted_data_1, encrypted_size_1);
    memcpy (*ppEncryptedData + encrypted_size_1, encrypted_data_2, encrypted_size_2);
    memcpy (*ppEncryptedData + encrypted_size_1 + encrypted_size_2, encrypted_data_3, encrypted_size_3);

    *pEncryptedDataSz = encrypted_size_1 + encrypted_size_2 + encrypted_size_3;

    return nReturnCode;
} // getMultPCPPktExample()

CDTCPTest::CDTCPTest()
{
    m_hDTCPGetLocalCert       = NULL;
    m_hDTCPVerifyRemoteCert   = NULL;
    m_hDTCPSignData           = NULL;
    m_hDTCPVerifyData         = NULL;
    m_hDTCPInit               = NULL;

    m_h_dtcpip_cmn_init = NULL;

    m_h_dtcpip_snk_init = NULL;
    m_h_dtcpip_snk_open = NULL;
    m_h_dtcpip_snk_alloc_decrypt = NULL;
    m_h_dtcpip_snk_free = NULL;
    m_h_dtcpip_snk_close = NULL;

    m_h_dtcpip_src_init = NULL;
    m_h_dtcpip_src_open = NULL;
    m_h_dtcpip_src_alloc_encrypt = NULL;
    m_h_dtcpip_src_free = NULL;
    m_h_dtcpip_src_close = NULL;

    m_inited = 0;
}


#ifdef __linux__
int CDTCPTest::initDTCP(char *dllPath, char* keyStorageDir)
{
    int nReturnCode = 0;
//    void * hModule = NULL;
    char *checkRet = (char *) 0;

    fprintf (stderr, "initDTCP: dllPath = %s\n", dllPath);
    fprintf (stderr, "initDTCP: keyStorageDir = %s\n", keyStorageDir);
    fflush(stderr);

    hModule = dlopen(dllPath, RTLD_LAZY);
    if (NULL == hModule)
    {
        fprintf (stderr, "initDTCP returning %d\n", DTCP_ERROR_LOADING_LIBRARY);
        fprintf (stderr, "dlerror = %s\n", dlerror());
 		fflush(stderr);
        return DTCP_ERROR_LOADING_LIBRARY;
    }

    /*
     * Per Linux Manpage
     * 1. Clear any extant errors
     * 2. Search for the symbol (NULL is legitimate return value)
     * 3. Check for resulting error
     */
    (void) dlerror();
    m_hDTCPGetLocalCert = (DTCPGetLocalCert_PROC) dlsym(hModule, "CVP2_DTCPIP_GetLocalCert");
    fprintf (stderr, "hModule: %p\n", hModule);
    fprintf (stderr, "m_hDTCPGetLocalCert: %p\n", m_hDTCPGetLocalCert);
    checkRet = dlerror();
    if (NULL != checkRet || NULL == m_hDTCPGetLocalCert)
    {
        fprintf (stderr, "initDTCP returning %d\n", DTCP_ERROR_GET_LOCAL_CERT);
        fprintf (stderr, "dlerror = %s\n", dlerror());
		fflush(stderr);
        return DTCP_ERROR_GET_LOCAL_CERT;
    }

    (void) dlerror();
printf ("Getting hDTCPVerifyRemoteCert...\n");

    m_hDTCPVerifyRemoteCert = (DTCPVerifyRemoteCert_PROC) dlsym(hModule, "CVP2_DTCPIP_VerifyRemoteCert");
    checkRet = dlerror();
    if (NULL != checkRet || NULL == m_hDTCPVerifyRemoteCert)
    {
        fprintf (stderr, "initDTCP returning %d\n", DTCP_ERROR_VERIFY_REMOTE_CERT);
		fflush(stderr);
        return DTCP_ERROR_VERIFY_REMOTE_CERT;
    }

 printf ("Getting hDTCPSignData...\n");
   (void) dlerror();
    m_hDTCPSignData =(DTCPSignData_PROC) dlsym(hModule, "CVP2_DTCPIP_SignData");
    checkRet = dlerror();
    if (NULL != checkRet || NULL == m_hDTCPSignData)
    {
        fprintf (stderr, "initDTCP returning %d\n", DTCP_ERROR_SIGN_DATA);
		fflush(stderr);
        return DTCP_ERROR_SIGN_DATA;
    }

    (void) dlerror();
    m_hDTCPVerifyData = (DTCPVerifyData_PROC) dlsym(hModule, "CVP2_DTCPIP_VerifyData");
    checkRet = dlerror();
    if (NULL != checkRet || NULL == m_hDTCPVerifyData)
    {
        fprintf (stderr, "initDTCP returning %d\n", DTCP_ERROR_VERIFY_DATA);
		fflush(stderr);
        return DTCP_ERROR_VERIFY_DATA;
    }

    (void) dlerror();
    m_hDTCPInit = (DTCPInit_PROC) dlsym(hModule, "CVP2_DTCPIP_Init");
    checkRet = dlerror();
    if (NULL != checkRet || NULL == m_hDTCPInit)
    {
        fprintf (stderr, "initDTCP returning %d\n", DTCP_ERROR_INIT);
		fflush(stderr);
        return DTCP_ERROR_INIT;
    }

    m_h_dtcpip_cmn_init = (dtcpip_cmn_init_PROC) dlsym(hModule, "dtcpip_cmn_init");

    m_h_dtcpip_snk_init = (dtcpip_snk_init_PROC) dlsym(hModule, "dtcpip_snk_init");
    m_h_dtcpip_snk_open = (dtcpip_snk_open_PROC) dlsym(hModule, "dtcpip_snk_open");
    m_h_dtcpip_snk_alloc_decrypt = (dtcpip_snk_alloc_decrypt_PROC) dlsym(hModule, "dtcpip_snk_alloc_decrypt");
    m_h_dtcpip_snk_free = (dtcpip_snk_free_PROC) dlsym(hModule, "dtcpip_snk_free");
    m_h_dtcpip_snk_close = (dtcpip_snk_close_PROC) dlsym(hModule, "dtcpip_snk_close");

    m_h_dtcpip_src_init = (dtcpip_src_init_PROC) dlsym(hModule, "dtcpip_src_init");
    m_h_dtcpip_src_open = (dtcpip_src_open_PROC) dlsym(hModule, "dtcpip_src_open");
    m_h_dtcpip_src_alloc_encrypt = (dtcpip_src_alloc_encrypt_PROC) dlsym(hModule, "dtcpip_src_alloc_encrypt");
    m_h_dtcpip_src_free = (dtcpip_src_free_PROC) dlsym(hModule, "dtcpip_src_free");
    m_h_dtcpip_src_close = (dtcpip_src_close_PROC) dlsym(hModule, "dtcpip_src_close");

    if (
        NULL == m_h_dtcpip_cmn_init ||
        NULL == m_h_dtcpip_snk_init ||
        NULL == m_h_dtcpip_snk_open ||
        NULL == m_h_dtcpip_snk_alloc_decrypt ||
        NULL == m_h_dtcpip_snk_free ||
        NULL == m_h_dtcpip_snk_close ||
        NULL == m_h_dtcpip_src_init ||
        NULL == m_h_dtcpip_src_open ||
        NULL == m_h_dtcpip_src_alloc_encrypt ||
        NULL == m_h_dtcpip_src_free ||
        NULL == m_h_dtcpip_src_close 
    )
    {
        return DTCP_ERROR_LOADING_SYMBOL;
    }

printf ("Calling hDTCPInit...\n");

    nReturnCode = m_hDTCPInit (keyStorageDir);
    fprintf (stderr, "hDTCPInit returned: %d\n", nReturnCode);
    fflush(stderr);

printf ("Done calling hDTCPInit...\n");

    if (nReturnCode != 0)
    {
        return nReturnCode;
    }
       
printf ("Calling dtcp_cmn_init with keyStorageDir %s...\n", keyStorageDir);

    nReturnCode = m_h_dtcpip_cmn_init (keyStorageDir);
printf("after m_h_dtcpip_cmn_init\n");
    fprintf (stderr, "h_dtcpip_cmn_init  returned: %d\n", nReturnCode);
    fflush(stderr);
printf ("Done calling dtcp_cmn_init...\n");

    if (nReturnCode != 0)
     {
        return nReturnCode;
    }

    fprintf (stderr, "initDTCP successful\n");
    fflush(stderr);
    m_inited = 1;


    return nReturnCode;
}
#endif


#if defined ( _WIN32) || defined (__CYGWIN__)
int CDTCPTest::initDTCP(char *dllPath, char* configStr)
{
    int nReturnCode = 0;

    wchar_t dllPathWide[1000];

    nReturnCode = mbstowcs(dllPathWide, dllPath, strlen (dllPath) + 1);

    hDll = LoadLibrary(dllPathWide);
    if (NULL == hDll)
    {
        fprintf (stderr, "initDTCP returning %d : %u\n", 
			DTCP_ERROR_LOADING_LIBRARY, GetLastError());
	    fflush(stderr);
        return DTCP_ERROR_LOADING_LIBRARY;
    }

    m_hDTCPGetLocalCert = (DTCPGetLocalCert_PROC) GetProcAddress(hDll, "CVP2_DTCPIP_GetLocalCert");
    if (NULL == m_hDTCPGetLocalCert)
    {
        fprintf (stderr, "initDTCP returning %d : %u\n", 
			DTCP_ERROR_GET_LOCAL_CERT, GetLastError());
	    fflush(stderr);
        return DTCP_ERROR_GET_LOCAL_CERT;
    }

    m_hDTCPVerifyRemoteCert = (DTCPVerifyRemoteCert_PROC) GetProcAddress(hDll, "CVP2_DTCPIP_VerifyRemoteCert");
    if (NULL == m_hDTCPVerifyRemoteCert)
    
        fprintf (stderr, "initDTCP returning %d\n", DTCP_ERROR_VERIFY_REMOTE_CERT);
	    fflush(stderr);
        return DTCP_ERROR_VERIFY_REMOTE_CERT;
    }

    m_hDTCPSignData = (DTCPSignData_PROC) GetProcAddress(hDll, "CVP2_DTCPIP_SignData");
    if (NULL == m_hDTCPSignData)
    {
        fprintf (stderr, "initDTCP returning %d\n", DTCP_ERROR_SIGN_DATA);
    	fflush(stderr);
        return DTCP_ERROR_SIGN_DATA;
    }

    m_hDTCPVerifyData = (DTCPVerifyData_PROC) GetProcAddress(hDll, "CVP2_DTCPIP_VerifyData");
    if (NULL == m_hDTCPVerifyData)
    {
        fprintf (stderr, "initDTCP returning %d\n", DTCP_ERROR_VERIFY_DATA);
	    fflush(stderr);
        return DTCP_ERROR_VERIFY_DATA;
    }

    m_hDTCPInit = (DTCPInit_PROC) GetProcAddress(hDll, "CVP2_DTCPIP_Init");
    if (NULL == m_hDTCPInit)
    {
        fprintf (stderr, "initDTCP returning %d\n", DTCP_ERROR_INIT);
        fflush(stderr);
        return DTCP_ERROR_INIT;
    }
    

    m_h_dtcpip_cmn_init = (dtcpip_cmn_init_PROC) GetProcAddress(hDll, "dtcpip_cmn_init");

    m_h_dtcpip_snk_init = (dtcpip_snk_init_PROC) GetProcAddress(hDll, "dtcpip_snk_init");
    m_h_dtcpip_snk_open = (dtcpip_snk_open_PROC) GetProcAddress(hDll, "dtcpip_snk_open");
    m_h_dtcpip_snk_alloc_decrypt = (dtcpip_snk_alloc_decrypt_PROC) GetProcAddress(hDll, "dtcpip_snk_alloc_decrypt");
    m_h_dtcpip_snk_free = (dtcpip_snk_free_PROC) GetProcAddress(hDll, "dtcpip_snk_free");
    m_h_dtcpip_snk_close = (dtcpip_snk_close_PROC) GetProcAddress(hDll, "dtcpip_snk_close");

    m_h_dtcpip_src_init = (dtcpip_src_init_PROC) GetProcAddress(hDll, "dtcpip_src_init");
    m_h_dtcpip_src_open = (dtcpip_src_open_PROC) GetProcAddress(hDll, "dtcpip_src_open");
    m_h_dtcpip_src_alloc_encrypt = (dtcpip_src_alloc_encrypt_PROC) GetProcAddress(hDll, "dtcpip_src_alloc_encrypt");
    m_h_dtcpip_src_free = (dtcpip_src_free_PROC) GetProcAddress(hDll, "dtcpip_src_free");
    m_h_dtcpip_src_close = (dtcpip_src_close_PROC) GetProcAddress(hDll, "dtcpip_src_close");

    if (
        NULL == m_h_dtcpip_cmn_init ||
        NULL == m_h_dtcpip_snk_init ||
        NULL == m_h_dtcpip_snk_open ||
        NULL == m_h_dtcpip_snk_alloc_decrypt ||
        NULL == m_h_dtcpip_snk_free ||
        NULL == m_h_dtcpip_snk_close ||
        NULL == m_h_dtcpip_src_init ||
        NULL == m_h_dtcpip_src_open ||
        NULL == m_h_dtcpip_src_alloc_encrypt ||
        NULL == m_h_dtcpip_src_free ||
        NULL == m_h_dtcpip_src_close 
    )
    {
        return DTCP_ERROR_LOADING_SYMBOL;
    }

/*
    nReturnCode = m_hDTCPInit (keyStorageDir);
    fprintf (stderr, "hDTCPInit returned: %d\n", nReturnCode);
    fflush(stderr);

    if (nReturnCode != 0)
    {
        return nReturnCode;
    }
       */
    nReturnCode = m_h_dtcpip_cmn_init (configStr);
    fprintf (stderr, "h_dtcpip_cmn_init  returned: %d\n", nReturnCode);
    fflush(stderr);

    if (nReturnCode != 0)
     {
        return nReturnCode;
    }

    fprintf (stderr, "initDTCP successful\n");
    fflush(stderr);
    m_inited = 1;

    return nReturnCode;
}
#endif



int CDTCPTest::DTCPIPAuth_GetLocalCert (
    unsigned char *pLocalCert, 
    unsigned int *pLocalCertSize)
{
    int nReturnCode = 0;
    fprintf (stderr, "Inside DTCPIPAuth_GetLocalCert\n");
    fflush (stderr);

    if (m_inited == 0)
    {
	fprintf (stderr, "DTCPIPAuth_GetLocalCert: DTCP not inited");
	fflush (stderr);
        return DTCP_ERROR_NOT_INITED;
    }

    if (NULL == m_hDTCPGetLocalCert)
    {
        fprintf (stderr, "DTCPIPAuth_GetLocalCert returning %d\n", 
			DTCP_ERROR_GET_LOCAL_CERT);
	fflush (stderr);
        return DTCP_ERROR_GET_LOCAL_CERT;
    }

    nReturnCode = m_hDTCPGetLocalCert (pLocalCert, pLocalCertSize);
    fprintf (stderr, "DTCPIPAuth_GetLocalCert returning %d\n", nReturnCode);
    fflush (stderr);

    return nReturnCode;
}


int CDTCPTest::DTCPIPAuth_VerifyRemoteCert( 
    unsigned char* pRemoteCert, unsigned int nRemoteCertSz )
{
    int nReturnCode = 0;

    fprintf (stderr, "Inside DTCPIPAuth_VerifyRemoteCert\n");
    fflush (stderr);

    if (m_inited == 0)
    {
	fprintf (stderr, "DTCPIPAuth_VerifyRemoteCert: DTCP not inited");
	fflush (stderr);
        return DTCP_ERROR_NOT_INITED;
    }
	fprintf (stderr, "m_inited != 0");
	fflush (stderr);

    if (NULL == m_hDTCPVerifyRemoteCert)
    {
        fprintf (stderr, "DTCPIPAuth_VerifyRemoteCert returning %d\n", 
			DTCP_ERROR_VERIFY_REMOTE_CERT);
		fflush (stderr);
        return DTCP_ERROR_VERIFY_REMOTE_CERT;
    }

    nReturnCode = m_hDTCPVerifyRemoteCert (pRemoteCert, nRemoteCertSz);
    fprintf (stderr, "DTCPIPAuth_VerifyRemoteCert returning %d\n", nReturnCode);
    fflush (stderr);

    return nReturnCode;
}

	
int CDTCPTest::DTCPIPAuth_SignData( 
    unsigned char* pData, 
    unsigned int nDataSz, 
    unsigned char* pSignature,   
    unsigned int *pnSignatureSz)
{
    int nReturnCode = 0;

    fprintf (stderr, "Inside DTCPIPAuth_SignData\n");
    fflush (stderr);

    if (m_inited == 0)
    {
	fprintf (stderr, "DTCPIPAuth_SignData: DTCP not inited");
	fflush (stderr);
        return DTCP_ERROR_NOT_INITED;
    }

    if (NULL == m_hDTCPSignData)
    {
        printf ("DTCPIPAuth_SignData returning %d\n", DTCP_ERROR_SIGN_DATA);
        return DTCP_ERROR_SIGN_DATA;
    }
    nReturnCode = m_hDTCPSignData (pData, nDataSz, pSignature, pnSignatureSz);
    fprintf (stderr, "DTCPIPAuth_SignData returning %d\n", nReturnCode);
    fflush (stderr);

    return nReturnCode;
}


int CDTCPTest::DTCPIPAuth_VerifyData( 
    unsigned char* pData, 
    unsigned int nDataSz, 
    unsigned char* pSignature, 
    unsigned char* pRemoteCert )
{
    int nReturnCode = 0;

    fprintf (stderr, "Inside DTCPIPAuth_VerifyData\n");
    fflush (stderr);

    if (m_inited == 0)
    {
	fprintf (stderr, "DTCPIPAuth_VerifyData: DTCP not inited");
	fflush (stderr);
        return DTCP_ERROR_NOT_INITED;
    }

    if (NULL == m_hDTCPVerifyData)
    {
        printf ("DTCPIPAuth_VerifyData returning %d\n", DTCP_ERROR_VERIFY_DATA);
        return DTCP_ERROR_VERIFY_DATA;
    }
    nReturnCode = m_hDTCPVerifyData (pData, nDataSz, pSignature, pRemoteCert);
    fprintf (stderr, "DTCPIPAuth_VerifyData returning %d\n", nReturnCode);
    fflush (stderr);

    return nReturnCode;
}


int CDTCPTest::dtcpip_snk_init(void)
{
    int nReturnCode = 0;

    printf ("Inside dtcpip_snk_init\n");
    if (NULL == m_h_dtcpip_snk_init)
    {
        printf ("dtcpip_snk_init returning %d\n", DTCP_ERROR_INIT);
        return DTCP_ERROR_INIT;
    }
    nReturnCode = m_h_dtcpip_snk_init ();
    printf ("dtcpip_snk_init returning %d\n", nReturnCode);

    return nReturnCode;
}

int CDTCPTest::dtcpip_snk_open(char* ip_addr, unsigned short ip_port, int *session_handle)
{
    int nReturnCode = 0;

    printf ("Inside dtcpip_snk_open\n");
    if (NULL == m_h_dtcpip_snk_open)
    {
        printf ("dtcpip_snk_open returning %d\n", DTCP_ERROR_INIT);
        return DTCP_ERROR_INIT;
    }
    nReturnCode = m_h_dtcpip_snk_open (ip_addr, ip_port, session_handle);
    printf ("dtcpip_snk_open returning %d\n", nReturnCode);

    return nReturnCode;
}

int CDTCPTest::dtcpip_snk_alloc_decrypt(int session_handle, char* encrypted_data, unsigned int encrypted_size,
    char** cleartext_data, unsigned int* cleartext_size)
{
    int nReturnCode = 0;

    printf ("Inside dtcpip_snk_alloc_decrypt\n");
    if (NULL == m_h_dtcpip_snk_alloc_decrypt)
    {
        printf ("dtcpip_snk_alloc_decrypt returning %d\n", DTCP_ERROR_INIT);
        return DTCP_ERROR_INIT;
    }
    nReturnCode = m_h_dtcpip_snk_alloc_decrypt (session_handle, encrypted_data, encrypted_size,
        cleartext_data, cleartext_size);
    printf ("dtcpip_snk_alloc_decrypt returning %d\n", nReturnCode);

    return nReturnCode;
}

int CDTCPTest::dtcpip_snk_free(char* cleartext_data)
{
    int nReturnCode = 0;

    printf ("Inside dtcpip_snk_free\n");
    if (NULL == m_h_dtcpip_snk_free)
    {
        printf ("dtcpip_snk_free returning %d\n", DTCP_ERROR_INIT);
        return DTCP_ERROR_INIT;
    }
    nReturnCode = m_h_dtcpip_snk_free (cleartext_data);
    printf ("dtcpip_snk_free returning %d\n", nReturnCode);

    return nReturnCode;
}

int CDTCPTest::dtcpip_snk_close(int session_handle)
{
    int nReturnCode = 0;

    printf ("Inside dtcpip_snk_close\n");
    if (NULL == m_h_dtcpip_snk_close)
    {
        printf ("dtcpip_snk_close returning %d\n", DTCP_ERROR_INIT);
        return DTCP_ERROR_INIT;
    }
    nReturnCode = m_h_dtcpip_snk_close (session_handle);
    printf ("dtcpip_snk_close returning %d\n", nReturnCode);

    return nReturnCode;
}


int CDTCPTest::dtcpip_src_init(unsigned short dtcp_port)
{
    int nReturnCode = 0;

    printf ("Inside dtcpip_src_init\n");
    if (NULL == m_h_dtcpip_src_init)
    {
        printf ("dtcpip_src_init returning %d\n", DTCP_ERROR_INIT);
        return DTCP_ERROR_INIT;
    }
    nReturnCode = m_h_dtcpip_src_init (dtcp_port);
    printf ("dtcpip_src_init returning %d\n", nReturnCode);

    return nReturnCode;
}

int CDTCPTest::dtcpip_cmn_init(char *pCertStorageDir)
{
    int nReturnCode = 0;

    printf ("Inside dtcpip_cmn_init\n");
    if (NULL == m_h_dtcpip_cmn_init)
    {
        printf ("dtcpip_cmn_init returning %d\n", DTCP_ERROR_INIT);
        return DTCP_ERROR_INIT;
    }
    nReturnCode = m_h_dtcpip_cmn_init (pCertStorageDir);
    printf ("dtcpip_cmn_init returning %d\n", nReturnCode);

    return nReturnCode;
}

int CDTCPTest::dtcpip_src_open(int* session_handle, int is_audio_only)
{
    int nReturnCode = 0;

    printf ("Inside dtcpip_src_open\n");
    if (NULL == m_h_dtcpip_src_open)
    {
        printf ("dtcpip_src_open returning %d\n", DTCP_ERROR_INIT);
        return DTCP_ERROR_INIT;
    }
    nReturnCode = m_h_dtcpip_src_open (session_handle, is_audio_only);
    printf ("dtcpip_src_open returning %d\n", nReturnCode);

    return nReturnCode;
}

int CDTCPTest::dtcpip_src_alloc_encrypt(int session_handle, unsigned char cci, 
    char* cleartext_data, unsigned int cleartext_size,
    char** encrypted_data, unsigned int* encrypted_size)
{
    int nReturnCode = 0;

    printf ("Inside dtcpip_src_alloc_encrypt\n");
    if (NULL == m_h_dtcpip_src_alloc_encrypt)
    {
        printf ("dtcpip_src_alloc_encrypt returning %d\n", DTCP_ERROR_INIT);
        return DTCP_ERROR_INIT;
    }
    nReturnCode = m_h_dtcpip_src_alloc_encrypt (session_handle, cci, 
        cleartext_data, cleartext_size,
        encrypted_data, encrypted_size);
    printf ("dtcpip_src_alloc_encrypt returning %d\n", nReturnCode);

    return nReturnCode;
}

int CDTCPTest::dtcpip_src_free(char* encrypted_data)
{
    int nReturnCode = 0;

    printf ("Inside dtcpip_src_free\n");
    if (NULL == m_h_dtcpip_src_free)
    {
        printf ("dtcpip_src_free returning %d\n", DTCP_ERROR_INIT);
        return DTCP_ERROR_INIT;
    }
    nReturnCode = m_h_dtcpip_src_free (encrypted_data);
    printf ("dtcpip_src_free returning %d\n", nReturnCode);

    return nReturnCode;
}

int CDTCPTest::dtcpip_src_close(int session_handle)
{
    int nReturnCode = 0;

    printf ("Inside dtcpip_src_close\n");
    if (NULL == m_h_dtcpip_src_close)
    {
        printf ("dtcpip_src_close returning %d\n", DTCP_ERROR_INIT);
        return DTCP_ERROR_INIT;
    }
    nReturnCode = m_h_dtcpip_src_close (session_handle);
    printf ("dtcpip_src_close returning %d\n", nReturnCode);

    return nReturnCode;
}

int CDTCPTest::dtcpip_src_close_socket(int session_handle)
{
    int nReturnCode = 0;

    printf ("Inside dtcpip_src_close_socket\n");
    dtcpip_src_close_socket_PROC h_dtcpip_src_close_socket = NULL;

#if defined ( _WIN32) || defined (__CYGWIN__)

   h_dtcpip_src_close_socket = 
        (dtcpip_src_close_socket_PROC) GetProcAddress (hDll, "dtcpip_src_close_socket");

#elif __linux__

   h_dtcpip_src_close_socket = 
        (dtcpip_src_close_socket_PROC) dlsym(hModule, "dtcpip_src_close_socket");

#endif

    nReturnCode = h_dtcpip_src_close_socket (session_handle);
    printf ("dtcpip_src_close_socket returning %d\n", nReturnCode);

    return nReturnCode;
}

#if defined ( _WIN32) || defined (__CYGWIN__)
DWORD WINAPI DecryptionThreadProc(LPVOID lpParameter)
{
    CDTCPTest *pMfr2 = (CDTCPTest *)lpParameter;

    printf ("Inside DecryptionThreadProc...\n");

    printf ("Mfr2: dtcpip_src_init...\n");
    int nReturnCode = pMfr2->dtcpip_src_init(akeSrcPort);
    if (nReturnCode != DTCP_ERROR_SUCCESS)
    {
        printf ("Mfr2: Error %d initializing encryption session\n", nReturnCode);
        return nReturnCode;
    }

    // the following blocks until AKE completes
    printf ("Mfr2: dtcpip_src_open...\n");
    nReturnCode = pMfr2->dtcpip_src_open(&g_session_handle, 0 /* audio_only */);
    if (nReturnCod

e != DTCP_ERROR_SUCCESS)
    {
        printf ("Mfr2: Error %d opening encryption session\n", nReturnCode);
        return nReturnCode;
    }
    printf ("Mfr2: dtcpip_src_open: %d\n", g_session_handle);

    g_bAKEComplete = 1;

    return nReturnCode;
}
#else
void *DecryptionThreadProc ( void *lpParameter )
{
    CDTCPTest *pMfr2 = (CDTCPTest *)lpParameter;

    printf ("Inside DecryptionThreadProc...\n");

    printf ("Mfr2: dtcpip_src_init...\n");
    int nReturnCode = pMfr2->dtcpip_src_init(akeSrcPort);
    if (nReturnCode != DTCP_ERROR_SUCCESS)
    {
        printf ("Mfr2: Error %d initializing encryption session\n", nReturnCode);
        return NULL;
    }

    // the following blocks until AKE completes
    printf ("Mfr2: dtcpip_src_open...\n");
    nReturnCode = pMfr2->dtcpip_src_open(&g_session_handle, 0 /* audio_only */);
    if (nReturnCode != DTCP_ERROR_SUCCESS)
    {
        printf ("Mfr2: Error %d opening encryption session\n", nReturnCode);
        return NULL;
    }
    printf ("Mfr2: dtcpip_src_open: %d\n", g_session_handle);

    g_bAKEComplete = 1;

    return NULL;
}
#endif

