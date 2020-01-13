#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "js_pki.h"
#include "js_http.h"
#include "js_process.h"
#include "js_db.h"

#include "kms_srv.h"
#include "js_ssl.h"
#include "js_kms.h"
#include "js_pkcs11.h"

SSL_CTX     *g_pSSLCTX = NULL;
BIN         g_binPri = {0,0};
BIN         g_binCert = {0,0};
BIN         g_binCACert = {0,0};
JP11_CTX   *g_pP11CTX = NULL;
CK_SESSION_HANDLE   g_hSession = -1;

int KMS_Service( JThreadInfo *pThInfo )
{
    int ret = 0;


    BIN binReq = {0,0};
    BIN binRsp = {0,0};

    ret = procKMS( &binReq, &binRsp );
    if( ret != 0 )
    {
        goto end;
    }


    /* send response body */
end:
    JS_BIN_reset( &binReq );
    JS_BIN_reset( &binRsp );
    return 0;
}

int KMS_SSL_Service( JThreadInfo *pThInfo )
{
    int ret = 0;

    SSL     *pSSL = NULL;

    BIN binReq = {0,0};
    BIN binRsp = {0,0};


    ret = JS_SSL_accept( g_pSSLCTX, pThInfo->nSockFd, &pSSL );
    if( ret != 0 )
    {
        fprintf( stderr, "fail to accept SSL(%d)\n", ret );
        goto end;
    }

    ret = JS_KMS_receive( pSSL, &binReq );

    ret = procKMS( &binReq, &binRsp );
    if( ret != 0 )
    {
        goto end;
    }

    printf( "ReqLen: %d, RspLen: %d\n", binReq.nLen, binRsp.nLen );

    ret = JS_KMS_send( pSSL, &binRsp );

    /* send response body */
end:
    JS_BIN_reset( &binReq );
    JS_BIN_reset( &binRsp );

    if( pSSL ) JS_SSL_clear( pSSL );


    return 0;
}

int Init()
{
    int ret = 0;
    const char *pCACertPath = "/Users/jykim/work/certs/root_cert.der";
    const char *pCertPath = "/Users/jykim/work/certs/server_cert.der";
    const char *pPriPath = "/Users/jykim/work/certs/server_prikey.der";
    const char *pP11Path = "/usr/local/lib/softhsm/libsofthsm2.so";

    JS_BIN_fileRead( pCACertPath, &g_binCACert );
    JS_BIN_fileRead( pCertPath, &g_binCert );
    JS_BIN_fileRead( pPriPath, &g_binPri );

    JS_SSL_initServer( &g_pSSLCTX );
    JS_SSL_setCertAndPriKey( g_pSSLCTX, &g_binPri, &g_binCert );
    JS_SSL_setClientCACert( g_pSSLCTX, &g_binCACert );

    JS_PKCS11_LoadLibrary( &g_pP11CTX, pP11Path );

    ret = loginHSM();

    return ret;
}

int loginHSM()
{
    int ret = 0;
    int nFlags = 0;

    CK_SESSION_HANDLE hSession = NULL;
    CK_ULONG uSlotCnt = 0;
    CK_SLOT_ID  sSlotList[10];

    char *pPin = "1234";
    long uPinLen = 4;
    int nUserType = 0;

    nFlags |= CKF_RW_SESSION;
    nFlags |= CKF_SERIAL_SESSION;
    nUserType = CKU_USER;

    ret = JS_PKCS11_Initialize( g_pP11CTX );
    if( ret != CKR_OK )
    {
        fprintf( stderr, "fail to run initialize(%d)\n", ret );
        return -1;
    }

    ret = JS_PKCS11_GetSlotList2( g_pP11CTX, CK_TRUE, sSlotList, &uSlotCnt );
    if( ret != CKR_OK )
    {
        fprintf( stderr, "fail to run getSlotList fail(%d)\n", ret );
        return -1;
    }

    if( uSlotCnt < 1 )
    {
        fprintf( stderr, "there is no slot(%d)\n", uSlotCnt );
        return -1;
    }

    ret = JS_PKCS11_OpenSession( g_pP11CTX, sSlotList[0], nFlags, &hSession );
    if( ret != CKR_OK )
    {
        fprintf( stderr, "fail to run opensession(%s:%x)\n", JS_PKCS11_GetErrorMsg(ret), ret );
        return -1;
    }

    ret = JS_PKCS11_Login( g_pP11CTX, hSession, nUserType, pPin, uPinLen );
    if( ret != 0 )
    {
        fprintf( stderr, "fail to run login hsm(%d)\n", ret );
        return -1;
    }

    g_hSession = hSession;
    printf( "HSM login ok\n" );

    return 0;
}

int main( int argc, char *argv[] )
{
    Init();

    JS_THD_logInit( "./log", "kms", 2 );
    JS_THD_registerService( "JS_KMS", NULL, 9040, 4, NULL, KMS_Service );
    JS_THD_registerService( "JS_KMS_SSL", NULL, 9140, 4, NULL, KMS_SSL_Service );
    JS_THD_serviceStartAll();

    return 0;
}
