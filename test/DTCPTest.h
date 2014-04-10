/*
** Copyright (C) 2013  Cable Television Laboratories, Inc.
** Contact: http://www.cablelabs.com/
*/


#ifndef __H_DTCP_TEST
#define __H_DTCP_TEST

#include <stdlib.h>
#include <stdio.h>

#define DTCP_CERT_SZ				88
#define DTCP_HASH_SIG_SZ			40

#if defined ( _WIN32) || defined (__CYGWIN__)

void sleep(unsigned int secs);

#include <windows.h>

typedef int (__cdecl *DTCPGetLocalCert_PROC)(unsigned char *, unsigned int *);
typedef int (__cdecl *DTCPVerifyRemoteCert_PROC)(unsigned char *, unsigned int);
typedef int (__cdecl *DTCPSignData_PROC)(unsigned char *, unsigned int, unsigned char *, unsigned int*);
typedef int (__cdecl *DTCPVerifyData_PROC)(unsigned char *, unsigned int, unsigned char *, unsigned char*);
typedef int (__cdecl *DTCPInit_PROC)(char *);

typedef int (__cdecl *dtcpip_cmn_init_PROC)(char* storage_path);

typedef int (__cdecl *dtcpip_snk_init_PROC)(void);
typedef int (__cdecl *dtcpip_snk_open_PROC)(char*, unsigned short, int *);
typedef int (__cdecl *dtcpip_snk_alloc_decrypt_PROC)(int, char*, unsigned int, char**, unsigned int*);
typedef int (__cdecl *dtcpip_snk_free_PROC)(char*);
typedef int (__cdecl *dtcpip_snk_close_PROC)(int);

typedef int (__cdecl *dtcpip_src_close_socket_PROC)(int);

typedef int (__cdecl *dtcpip_src_init_PROC)(unsigned short);
typedef int (__cdecl *dtcpip_src_open_PROC)(int*, int);
typedef int (__cdecl *dtcpip_src_alloc_encrypt_PROC)(int, unsigned char, 
            char*, unsigned int, char**, unsigned int*);
typedef int (__cdecl *dtcpip_src_free_PROC)(char*);
typedef int (__cdecl *dtcpip_src_close_PROC)(int);

#elif __linux__

#include <dlfcn.h>
#include <unistd.h>

typedef int (*DTCPGetLocalCert_PROC)(unsigned char *, unsigned int *);
typedef int (*DTCPVerifyRemoteCert_PROC)(unsigned char *, unsigned int);
typedef int (*DTCPSignData_PROC)(unsigned char *, unsigned int, unsigned char *, unsigned int*);
typedef int (*DTCPVerifyData_PROC)(unsigned char *, unsigned int, unsigned char *, unsigned char*);
typedef int (*DTCPInit_PROC)(char *);

typedef int (*dtcpip_cmn_init_PROC)(char* storage_path);

typedef int (*dtcpip_snk_init_PROC)(void);
typedef int (*dtcpip_snk_open_PROC)(char*, unsigned short, int *);
typedef int (*dtcpip_snk_alloc_decrypt_PROC)(int, char*, unsigned int, char**, unsigned int*);
typedef int (*dtcpip_snk_free_PROC)(char*);
typedef int (*dtcpip_snk_close_PROC)(int);

typedef int (*dtcpip_src_close_socket_PROC)(int);

typedef int (*dtcpip_src_init_PROC)(unsigned short);
typedef int (*dtcpip_src_open_PROC)(int*, int);
typedef int (*dtcpip_src_alloc_encrypt_PROC)(int, unsigned char, 
            char*, unsigned int, char**, unsigned int*);
typedef int (*dtcpip_src_free_PROC)(char*);
typedef int (*dtcpip_src_close_PROC)(int);

#endif

class CDTCPTest
{

    public:
        CDTCPTest();

        int initDTCP(char *dllPath, char *configStr);

        int DTCPIPAuth_GetLocalCert (unsigned char *pLocalCert, unsigned int *pLocalCertSize);

        int DTCPIPAuth_VerifyRemoteCert(unsigned char* pRemoteCert, unsigned int nRemoteCertSz );

        int DTCPIPAuth_SignData( unsigned char* pData, unsigned int nDataSz, 
            unsigned char* pSignature, unsigned int *pnSignatureSz);

        int DTCPIPAuth_VerifyData( unsigned char* pData, unsigned int nDataSz, 
            unsigned char* pSignature, unsigned char* pRemoteCert );

        int DTCPIPAuth_Init(char * pCertStorageDir);

        int dtcpip_cmn_init(char* storage_path);

        int dtcpip_src_close_socket(int session_handle);

        int dtcpip_snk_init(void);
        int dtcpip_snk_open(char* ip_addr, unsigned short ip_port, int *session_handle);
        int dtcpip_snk_alloc_decrypt(int session_handle, char* encrypted_data, unsigned int encrypted_size,
            char** cleartext_data, unsigned int* cleartext_size);
        int dtcpip_snk_free(char* cleartext_data);
        int dtcpip_snk_close(int session_handle);

        int dtcpip_src_init(unsigned short dtcp_port);
        int dtcpip_src_open(int* session_handle, int is_audio_only);
        int dtcpip_src_alloc_encrypt(int session_handle, unsigned char cci, 
            char* cleartext_data, unsigned int cleartext_size,
            char** encrypted_data, unsigned int* encrypted_size);
        int dtcpip_src_free(char* encrypted_data);
        int dtcpip_src_close(int session_handle);

    private:

#if defined ( _WIN32) || defined (__CYGWIN__)
        HINSTANCE hDll;
#elif __linux__
        void * hModule;
#endif

        DTCPGetLocalCert_PROC       m_hDTCPGetLocalCert;
        DTCPVerifyRemoteCert_PROC   m_hDTCPVerifyRemoteCert;
        DTCPSignData_PROC           m_hDTCPSignData;
        DTCPVerifyData_PROC         m_hDTCPVerifyData;
        DTCPInit_PROC               m_hDTCPInit;

        dtcpip_cmn_init_PROC            m_h_dtcpip_cmn_init;

        dtcpip_snk_init_PROC            m_h_dtcpip_snk_init;
        dtcpip_snk_open_PROC            m_h_dtcpip_snk_open;
        dtcpip_snk_alloc_decrypt_PROC   m_h_dtcpip_snk_alloc_decrypt;
        dtcpip_snk_free_PROC            m_h_dtcpip_snk_free;
        dtcpip_snk_close_PROC           m_h_dtcpip_snk_close;

        dtcpip_src_init_PROC            m_h_dtcpip_src_init;
        dtcpip_src_open_PROC            m_h_dtcpip_src_open;
        dtcpip_src_alloc_encrypt_PROC   m_h_dtcpip_src_alloc_encrypt;
        dtcpip_src_free_PROC            m_h_dtcpip_src_free;
        dtcpip_src_close_PROC           m_h_dtcpip_src_close;

        int m_inited;
};

#endif // __H_DTCP_TEST
