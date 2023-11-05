#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>

#include "js_log.h"
#include "js_pki.h"
#include "js_http.h"
#include "js_process.h"
#include "js_db.h"
#include "js_cfg.h"

#include "kms_srv.h"
#include "kms_proc.h"
#include "js_ssl.h"
#include "js_kms.h"
#include "js_pkcs11.h"
#include "js_db.h"
#include "js_gen.h"

SSL_CTX     *g_pSSLCTX = NULL;
BIN         g_binPri = {0,0};
BIN         g_binCert = {0,0};
BIN         g_binCACert = {0,0};
JP11_CTX   *g_pP11CTX = NULL;

const char  *g_pDBPath = NULL;
static char g_sConfigPath[1024];
int g_nVerbose = 0;
JEnvList    *g_pEnvList = NULL;
int         g_nPort = 9040;
int         g_nSSLPort = 9140;

int         g_nLogLevel = JS_LOG_LEVEL_INFO;

static char g_sBuildInfo[1024];

const char *getBuildInfo()
{
    sprintf( g_sBuildInfo, "Version: %s Build Date : %s %s",
             JS_KMS_SRV_VERSION, __DATE__, __TIME__ );

    return g_sBuildInfo;
}

int KMS_addAudit( sqlite3 *db, int nOP, const char *pInfo )
{
    int nSeq = 0;
    JDB_Audit   sAudit;
    char *pMAC = NULL;
    char    sData[2048];
    time_t now_t = 0;
    BIN binSrc = {0,0};
    BIN binKey = {0,0};
    BIN binHMAC = {0,0};

    memset( &sAudit, 0x00, sizeof(sAudit));

    binKey.pVal = (unsigned char *)JS_GEN_HMAC_KEY;
    binKey.nLen = strlen( JS_GEN_HMAC_KEY );

    now_t = time(NULL);

//    nSeq = JS_DB_getSeq( db, "TB_AUDIT" );
//    nSeq++;
    nSeq = JS_DB_getNextVal( db, "TB_AUDIT" );

    sprintf( sData, "%d_%d_%d_%s_%d_%s",
             nSeq,
             JS_GEN_KIND_KMS_SRV,
             nOP,
             pInfo ? pInfo:"",
             now_t,
             "kms" );

    binSrc.pVal = (unsigned char *)sData;
    binSrc.nLen = strlen(sData);

    JS_PKI_genHMAC( "SHA256", &binSrc, &binKey, &binHMAC );
    JS_BIN_encodeHex( &binHMAC, &pMAC );

    JS_DB_setAudit( &sAudit, nSeq, now_t, JS_GEN_KIND_KMS_SRV, nOP, "kms", pInfo, pMAC );
    JS_DB_addAudit( db, &sAudit );

    JS_BIN_reset( &binHMAC );
    if( pMAC ) JS_free( pMAC );
    JS_DB_resetAudit( &sAudit );

    return 0;
}

int KMS_Service( JThreadInfo *pThInfo )
{
    int ret = 0;


    BIN binReq = {0,0};
    BIN binRsp = {0,0};

    sqlite3* db = JS_DB_open( g_pDBPath );
    if( db == NULL )
    {
        fprintf( stderr, "fail to open db file(%s)\n", g_pDBPath );
        ret = -1;
        goto end;
    }

    ret = procKMS( db, &binReq, &binRsp );
    if( ret != 0 )
    {
        goto end;
    }


    /* send response body */
end:
    JS_BIN_reset( &binReq );
    JS_BIN_reset( &binRsp );
    JS_DB_close( db );

    return 0;
}

int KMS_SSL_Service( JThreadInfo *pThInfo )
{
    int ret = 0;

    SSL     *pSSL = NULL;

    BIN binReq = {0,0};
    BIN binRsp = {0,0};

    sqlite3* db = JS_DB_open( g_pDBPath );
    if( db == NULL )
    {
        fprintf( stderr, "fail to open db file(%s)\n", g_pDBPath );
        ret = -1;
        goto end;
    }


    ret = JS_SSL_accept( g_pSSLCTX, pThInfo->nSockFd, &pSSL );
    if( ret != 0 )
    {
        fprintf( stderr, "fail to accept SSL(%d)\n", ret );
        goto end;
    }

    ret = JS_KMS_receive( pSSL, &binReq );
    if( ret != 0 )
    {
        fprintf( stderr, "fail to receive request[ret:%d]\n", ret );
        goto end;
    }

    ret = procKMS( db, &binReq, &binRsp );
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
    JS_DB_close( db );


    return 0;
}

int initServer()
{
    int ret = 0;
    const char *value = NULL;

    ret = JS_CFG_readConfig( g_sConfigPath, &g_pEnvList );
    if( ret != 0 )
    {
        fprintf( stderr, "fail to open config file(%s)\n", g_sConfigPath );
        exit(0);
    }

    value = JS_CFG_getValue( g_pEnvList, "LOG_LEVEL" );
    if( value ) g_nLogLevel = atoi( value );

    JS_LOG_setLevel( g_nLogLevel );

    value = JS_CFG_getValue( g_pEnvList, "LOG_PATH" );
    if( value )
        JS_LOG_open( value, "KMS", JS_LOG_TYPE_DAILY );
    else
        JS_LOG_open( "log", "KMS", JS_LOG_TYPE_DAILY );

    value = JS_CFG_getValue( g_pEnvList, "SSL_CA_CERT_PATH" );
    if( value == NULL )
    {
        fprintf( stderr, "You have to set 'SSL_CA_CERT_PATH'\n" );
        exit(0);
    }

    ret = JS_BIN_fileReadBER( value, &g_binCACert );
    if( ret <= 0 )
    {
        fprintf( stderr, "fail to read ssl ca cert(%s)\n", value );
        exit(0);
    }

    value = JS_CFG_getValue( g_pEnvList, "SSL_CERT_PATH" );
    if( value == NULL )
    {
        fprintf( stderr, "You have to set 'SSL_CERT_PATH'\n" );
        exit(0);
    }

    ret = JS_BIN_fileReadBER( value, &g_binCert );
    if( ret <= 0 )
    {
        fprintf( stderr, "fail to read ssl cert(%s)\n", value );
        exit(0);
    }

    value = JS_CFG_getValue( g_pEnvList, "SSL_PRIKEY_PATH" );
    if( value == NULL )
    {
        fprintf( stderr, "You have to set 'SSL_PRIKEY_PATH'\n" );
        exit(0);
    }

    ret = JS_BIN_fileReadBER( value, &g_binPri );
    if( ret <= 0 )
    {
        fprintf( stderr, "fail to read ssl private key(%s)\n", value );
        exit(0);
    }

    value = JS_CFG_getValue( g_pEnvList, "PKCS11_LIB_PATH" );
    if( value == NULL )
    {
        fprintf( stderr, "You have to set 'PKCS11_LIB_PATH'\n" );
        exit(0);
    }

    ret = JS_PKCS11_LoadLibrary( &g_pP11CTX, value );
    if( ret != 0 )
    {
        fprintf( stderr, "fail to load library(%s:%d)\n", value, ret );
        exit(0);
    }

    JS_SSL_initServer( &g_pSSLCTX );
    JS_SSL_setCertAndPriKey( g_pSSLCTX, &g_binPri, &g_binCert );
    JS_SSL_setClientCACert( g_pSSLCTX, &g_binCACert );

    value = JS_CFG_getValue( g_pEnvList, "DB_PATH" );
    if( value == NULL )
    {
        fprintf( stderr, "You have to set 'DB_PATH'\n" );
        exit(0);
    }

    g_pDBPath = JS_strdup( value );

    value = JS_CFG_getValue( g_pEnvList, "KMS_PORT" );
    if( value ) g_nPort = atoi( value );

    value = JS_CFG_getValue( g_pEnvList, "KMS_SSL_PORT" );
    if( value ) g_nSSLPort = atoi( value );

    ret = loginHSM();
    if( ret != 0 )
    {
        fprintf( stderr, "fail to login in HSM(%d)\n", ret );
        exit(0);
    }

    printf( "KMI Server Init OK [Port:%d SSL:%d]\n", g_nPort, g_nSSLPort );
    return 0;
}

int loginHSM()
{
    int ret = 0;
    int nFlags = 0;


    CK_ULONG uSlotCnt = 0;
    CK_SLOT_ID  sSlotList[10];

//    char *pPin = "1234";
    char *pPin = "9999";
    long uPinLen = 4;
    int nUserType = 0;

    nFlags |= CKF_RW_SESSION;
    nFlags |= CKF_SERIAL_SESSION;
    nUserType = CKU_USER;

    ret = JS_PKCS11_Initialize( g_pP11CTX, NULL );
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

    ret = JS_PKCS11_OpenSession( g_pP11CTX, sSlotList[0], nFlags );
    if( ret != CKR_OK )
    {
        fprintf( stderr, "fail to run opensession(%s:%x)\n", JS_PKCS11_GetErrorMsg(ret), ret );
        return -1;
    }

    ret = JS_PKCS11_Login( g_pP11CTX, nUserType, pPin, uPinLen );
    if( ret != 0 )
    {
        fprintf( stderr, "fail to run login hsm(%d)\n", ret );
        return -1;
    }

    printf( "HSM login ok\n" );

    return 0;
}

void printUsage()
{
    printf( "JS KMS Server ( %s )\n", getBuildInfo() );
    printf( "[Options]\n" );
    printf( "-v         : Verbose on(%d)\n", g_nVerbose );
    printf( "-c config : set config file(%s)\n", g_sConfigPath );
    printf( "-h         : Print this message\n" );
}

#if 1
int main( int argc, char *argv[] )
{
    int nOpt = 0;

    sprintf( g_sConfigPath, "%s", "../kms_srv.cfg" );

    while(( nOpt = getopt( argc, argv, "c:vh")) != -1 )
    {
        switch( nOpt ) {
        case 'h':
            printUsage();
            return 0;

        case 'v':
            g_nVerbose = 1;
            break;

        case 'c':
            sprintf( g_sConfigPath, "%s", optarg );
            break;
        }
    }

    initServer();

    JS_THD_logInit( "./log", "kms", 2 );
    JS_THD_registerService( "JS_KMS", NULL, g_nPort, 4, NULL, KMS_Service );
    JS_THD_registerService( "JS_KMS_SSL", NULL, g_nSSLPort, 4, NULL, KMS_SSL_Service );
    JS_THD_serviceStartAll();

    return 0;
}
#endif
