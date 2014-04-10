/*
** Copyright (C) 2014  Cable Television Laboratories, Inc.
** Contact: http://www.cablelabs.com/
*/

#ifndef __H_DTCP_ERROR
#define __H_DTCP_ERROR

#define DTCP_ERROR_SUCCESS                   	0
#define DTCP_ERROR_FAILURE	                	-1
#define DTCP_ERROR_INSUFFICENT_MEMORY			-2

#define DTCP_ERROR_UNKNOWN_DTCP_LIBRARY			-10
#define DTCP_ERROR_LOADING_LIBRARY				-11
#define DTCP_ERROR_NOT_INITED                	-12
#define DTCP_ERROR_INIT							-13

#define DTCP_ERROR_OPENING_SOCKET            	-20
#define DTCP_ERROR_SOCKET_INIT               	-21
#define DTCP_ERROR_RECV_SELECT               	-22
#define DTCP_ERROR_RECV_TIMEOUT              	-23
#define DTCP_ERROR_RECV                      	-24
#define DTCP_ERROR_RECV_SOCKET_CLOSED        	-25
#define DTCP_ERROR_RECV_UNKNOWN_SOCKET       	-26
#define DTCP_ERROR_SEND                      	-27
#define DTCP_ERROR_INVALID_TAG              	-28
#define DTCP_ERROR_INVALID_PACKET_SZ        	-29
#define DTCP_ERROR_INVALID_PAYLOAD_BUFFER_SZ	-30
#define DTCP_ERROR_STATUS_FIELD_SET          	-31
#define DTCP_ERROR_CREATING_NONCE				-32
#define DTCP_ERROR_INVALID_SESSION_HANDLE		-33
#define DTCP_ERROR_INVALID_IP_PORT_STRING		-34
#define DTCP_ERROR_GET_LOCAL_CERT				-35
#define DTCP_ERROR_VERIFY_REMOTE_CERT			-36
#define DTCP_ERROR_SIGN_DATA					-37
#define DTCP_ERROR_VERIFY_DATA					-38
#define DTCP_ERROR_LOADING_SYMBOL				-39
#define DTCP_ERROR_FILE_NOT_AVAILABLE			-40

#endif  // __H_DTCP_ERROR

