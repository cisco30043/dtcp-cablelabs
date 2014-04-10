/*
** Copyright (C) 2014  Cable Television Laboratories, Inc.
** Contact: http://www.cablelabs.com/
*/

#ifndef __H_DTCP_API
#define __H_DTCP_API

#if defined ( _WIN32) || defined (__CYGWIN__)
#define DLLEXPORT __declspec (dllexport)
#else
#define DLLEXPORT  __attribute__ ((visibility ("default")))    
#endif

// Encrypion/decryption functions used by source and sink applications
DLLEXPORT int dtcpip_cmn_init(char* pIPAndPort);
DLLEXPORT unsigned int dtcpip_get_encrypted_sz(unsigned int cleartextSz, unsigned int basePCPPayload);
DLLEXPORT void dtcpip_cmn_get_version(char *version, unsigned int versionSz);
DLLEXPORT int dtcpip_src_close_socket(int session_handle);
DLLEXPORT int dtcpip_snk_init(void);
DLLEXPORT int dtcpip_snk_open(char* ip_addr, unsigned short ip_port, int *session_handle);
DLLEXPORT int dtcpip_snk_alloc_decrypt(int session_handle, char* encrypted_data, unsigned int encrypted_size,
        char** cleartext_data, unsigned int* cleartext_size);
DLLEXPORT int dtcpip_snk_free(char* cleartext_data);
DLLEXPORT int dtcpip_snk_close(int session_handle);
DLLEXPORT int dtcpip_src_init(unsigned short dtcp_port);
DLLEXPORT int dtcpip_src_open(int* session_handle, int is_audio_only);
DLLEXPORT int dtcpip_src_alloc_encrypt(int session_handle, unsigned char cci, 
       char* cleartext_data, unsigned int cleartext_size,
       char** encrypted_data,unsigned int* encrypted_size);
DLLEXPORT int dtcpip_src_free(char* encrypted_data);
DLLEXPORT int dtcpip_src_close(int session_handle);

// Authorization functions used by Rygel-based CVP2 applications
DLLEXPORT int CVP2_DTCPIP_Init(char *pCertStorageDir);
DLLEXPORT int CVP2_DTCPIP_GetLocalCert (unsigned char *pLocalCert, unsigned int *pLocalCertSize);
DLLEXPORT int CVP2_DTCPIP_VerifyRemoteCert(unsigned char *pRemoteCert,  unsigned int nRemoteCertSz);
DLLEXPORT int CVP2_DTCPIP_SignData( unsigned char *pData, unsigned int nDataSz, 
      unsigned char *pSignature, unsigned int *pnSignatureSz);
DLLEXPORT int CVP2_DTCPIP_VerifyData(unsigned char *pData, unsigned int nDataSz, 
      unsigned char *pSignature, unsigned char *pRemoteCert );

#endif  // __H_DTCP_API
