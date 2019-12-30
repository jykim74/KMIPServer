#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "js_pki.h"
#include "js_http.h"
#include "js_process.h"
#include "js_db.h"

#include "kms_srv.h"
#include "js_ssl.h"
#include "js_kmip.h"

SSL_CTX     *g_pSSLCTX = NULL;
BIN         g_binPri = {0,0};
BIN         g_binCert = {0,0};
BIN         g_binCACert = {0,0};


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

    ret = JS_KMIP_receive( pSSL, &binReq );

    ret = procKMS( &binReq, &binRsp );
    if( ret != 0 )
    {
        goto end;
    }

    ret = JS_KMIP_send( pSSL, &binRsp );

    /* send response body */
end:
    JS_BIN_reset( &binReq );
    JS_BIN_reset( &binRsp );

    if( pSSL ) JS_SSL_clear( pSSL );


    return 0;
}

int Init()
{
    const char *pCACertPath = "/Users/jykim/work/certs/root_cert.der";
    const char *pCertPath = "/Users/jykim/work/certs/server_cert.der";
    const char *pPriPath = "/Users/jykim/work/certs/server_prikey.der";

    JS_BIN_fileRead( pCACertPath, &g_binCACert );
    JS_BIN_fileRead( pCertPath, &g_binCert );
    JS_BIN_fileRead( pPriPath, &g_binPri );

    JS_SSL_initServer( &g_pSSLCTX );
    JS_SSL_setCertAndPriKey( g_pSSLCTX, &g_binPri, &g_binCert );
    JS_SSL_setClientCACert( g_pSSLCTX, &g_binCACert );

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
