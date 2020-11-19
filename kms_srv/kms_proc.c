#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "kmip.h"
#include "js_bin.h"
#include "js_pkcs11.h"
#include "kms_define.h"
#include "js_db.h"
#include "js_kms.h"
#include "js_pki.h"
#include "js_pki_tools.h"

extern JP11_CTX    *g_pP11CTX;


static void _setErrorResponse( int nErrorCode, ResponseBatchItem *pRspItem )
{
    const char *pError = getErrorMsg( nErrorCode );
    pRspItem->result_status = KMIP_STATUS_OPERATION_FAILED;
    pRspItem->result_reason = KMIP_REASON_GENERAL_FAILURE;
    pRspItem->result_message = (TextString *)JS_malloc(sizeof(TextString));
    pRspItem->result_message->value = JS_strdup( pError );
    pRspItem->result_message->size = strlen( pError );
}

long findObjects( unsigned long uObjClass, const BIN *pID, CK_OBJECT_HANDLE_PTR *pObjects )
{
    int ret = 0;
    CK_ATTRIBUTE sTemplate[2];
    CK_ULONG uCount = 0;
    CK_OBJECT_CLASS objClass = 0;
    CK_ULONG uMaxObjCnt = 20;
    CK_ULONG uObjCnt = -1;

//   objClass = CKO_SECRET_KEY;
    objClass = uObjClass;

    sTemplate[uCount].type = CKA_CLASS;
    sTemplate[uCount].pValue = &objClass;
    sTemplate[uCount].ulValueLen = sizeof(objClass);
    uCount++;

    sTemplate[uCount].type = CKA_ID;
    sTemplate[uCount].pValue = pID->pVal;
    sTemplate[uCount].ulValueLen = pID->nLen;
    uCount++;

    ret = JS_PKCS11_FindObjectsInit( g_pP11CTX,sTemplate, uCount );
    if( ret != CKR_OK )
    {
        fprintf( stderr, "fail to run findObjectsInit(%s:%d)\n", JS_PKCS11_GetErrorMsg(ret), ret );
        return -1;
    }

    ret = JS_PKCS11_FindObjects( g_pP11CTX, pObjects, uMaxObjCnt, &uObjCnt );
    if( ret != CKR_OK )
    {
        fprintf( stderr, "fail to run findObjects(%s:%d)\n", JS_PKCS11_GetErrorMsg(ret), ret );
        return -1;
    }

    ret = JS_PKCS11_FindObjectsFinal( g_pP11CTX );
    if( ret != CKR_OK )
    {
        fprintf( stderr, "fail to run findObjectsFinal(%s:%d)\n", JS_PKCS11_GetErrorMsg(ret), ret );
        return -1;
    }

    return uObjCnt;
}

int getValue( CK_OBJECT_HANDLE hObject, CK_ATTRIBUTE_TYPE nType, BIN *pVal )
{
    int ret = 0;

    ret = JS_PKCS11_GetAtrributeValue2( g_pP11CTX, hObject, nType, pVal );

    return ret;
}

static int _getSecretKey( const BIN *pID, int nKeyType, SymmetricKey **ppSymKey )
{
    int ret = 0;
    BIN binVal = {0,0};

    CK_OBJECT_HANDLE    sObjects[20];
    ret = findObjects( CKO_SECRET_KEY, pID, sObjects );

    if( ret <= 0 )
    {
        ret = JS_KMS_ERROR_NO_OBJECT;
        goto end;
    }

    ret = getValue( sObjects[0], CKA_VALUE, &binVal );
    if( ret != CKR_OK )
    {
        ret = JS_KMS_ERROR_FAIL_GET_VALUE;
        goto end;
    }

    if( ret == CKR_OK )
    {
        ByteString *material = (ByteString *)JS_calloc(1, sizeof(ByteString));
        material->size = binVal.nLen;
        material->value = binVal.pVal;

        KeyValue *key_value = (KeyValue *)JS_calloc(1, sizeof(KeyValue));
        key_value->key_material = material;

        KeyBlock *key_block = (KeyBlock *)JS_calloc(1, sizeof(KeyBlock));
        key_block->key_value = key_value;
        key_block->key_format_type = KMIP_KEYFORMAT_RAW;
        key_block->cryptographic_length = binVal.nLen * 8;
        key_block->cryptographic_algorithm = KMIP_CRYPTOALG_AES;

        SymmetricKey *symmetric_key = (SymmetricKey *)JS_calloc(1, sizeof(SymmetricKey));
        symmetric_key->key_block = key_block;

        *ppSymKey = symmetric_key;
    }

end :
    return ret;
}

static int _getPublicKey( const BIN *pID, int nKeyType, PublicKey **ppPubKey )
{
    int ret = 0;
    BIN binVal = {0,0};
    BIN binPub = {0,0};

    CK_OBJECT_HANDLE    sObjects[20];
    ret = findObjects( CKO_PUBLIC_KEY, pID, sObjects );

    if( nKeyType == JS_PKI_KEY_TYPE_RSA )
    {
        JRSAKeyVal sRSAKeyVal;

        BIN binExponet = {0,0};
        BIN binModulus = {0,0};
        char *pN = NULL;
        char *pE = NULL;


        memset( &sRSAKeyVal, 0x00, sizeof(sRSAKeyVal));

        ret = getValue( sObjects[0], CKA_PUBLIC_EXPONENT, &binExponet );
        ret = getValue( sObjects[0], CKA_MODULUS, &binModulus );

        JS_BIN_encodeHex( &binExponet, &pE );
        JS_BIN_encodeHex( &binModulus, &pN );

        JS_PKI_setRSAKeyVal( &sRSAKeyVal, pN, pE, NULL, NULL, NULL, NULL, NULL, NULL );

        JS_PKI_encodeRSAPublicKey( &sRSAKeyVal, &binPub );

        JS_BIN_reset( &binExponet );
        JS_BIN_reset( &binModulus );
        if( pE ) JS_free( pE );
        if( pN ) JS_free( pN );
        JS_PKI_resetRSAKeyVal( &sRSAKeyVal );
    }
    else if( nKeyType == JS_PKI_KEY_TYPE_ECC )
    {
        ret = getValue( sObjects[0], CKA_EC_POINT, &binPub );
    }
    else
    {
        ret = JS_KMS_ERROR_NOT_SUPPORT_PARAM;
        goto end;
    }

    PublicKey *pPubKey = NULL;
    pPubKey = (PublicKey *)JS_calloc(1, sizeof(PublicKey));

    ByteString *material = (ByteString *)JS_calloc(1, sizeof(ByteString));
    material->size = binPub.nLen;
    material->value = binPub.pVal;

    KeyValue *key_value = (KeyValue *)JS_calloc(1, sizeof(KeyValue));
    key_value->key_material = material;

    KeyBlock *key_block = (KeyBlock *)JS_calloc(1, sizeof(KeyBlock));
    key_block->key_value = key_value;
    key_block->key_format_type = KMIP_KEYFORMAT_RAW;
    key_block->cryptographic_length = binVal.nLen * 8;

    if( nKeyType == JS_PKI_KEY_TYPE_RSA )
        key_block->cryptographic_algorithm = KMIP_CRYPTOALG_RSA;
    else if( nKeyType == JS_PKI_KEY_TYPE_ECC )
        key_block->cryptographic_algorithm = KMIP_CRYPTOALG_ECDSA;

    pPubKey->key_block = key_block;
    *ppPubKey = pPubKey;

 end :


    return ret;
}

static int _getPrivateKey( const BIN *pID, int nKeyType, PrivateKey **ppPriKey )
{
    int ret = 0;
    BIN binVal = {0,0};
    BIN binPri = {0,0};

    CK_OBJECT_HANDLE    sObjects[20];
    ret = findObjects( CKO_PRIVATE_KEY, pID, sObjects );

    if( nKeyType == JS_PKI_KEY_TYPE_RSA )
    {
        JRSAKeyVal sRSAKeyVal;

        BIN binExponet = {0,0};
        BIN binModulus = {0,0};
        BIN binPriExponent = {0,0};

        char *pN = NULL;
        char *pE = NULL;
        char *pD = NULL;

        memset( &sRSAKeyVal, 0x00, sizeof(sRSAKeyVal));

        ret = getValue( sObjects[0], CKA_PUBLIC_EXPONENT, &binExponet );
        ret = getValue( sObjects[0], CKA_MODULUS, &binModulus );
        ret = getValue( sObjects[0], CKA_PRIVATE_EXPONENT, &binPriExponent );

        JS_BIN_encodeHex( &binExponet, &pE );
        JS_BIN_encodeHex( &binModulus, &pN );
        JS_BIN_encodeHex( &binPriExponent, &pD );

        JS_PKI_setRSAKeyVal( &sRSAKeyVal, pN, pE, pD, NULL, NULL, NULL, NULL, NULL );

        JS_PKI_encodeRSAPrivateKey( &sRSAKeyVal, &binPri );

        JS_BIN_reset( &binExponet );
        JS_BIN_reset( &binModulus );
        JS_BIN_reset( &binPriExponent );
        if( pE ) JS_free( pE );
        if( pN ) JS_free( pN );
        if( pD ) JS_free( pD );
        JS_PKI_resetRSAKeyVal( &sRSAKeyVal );
    }
    else if( nKeyType == JS_PKI_KEY_TYPE_ECC )
    {
        JECKeyVal sECKeyVal;

        BIN binPoint = {0,0};
        BIN binGroup = {0,0};
        BIN binPriv = {0,0};

        char *pPoint = NULL;
        char *pGroup = NULL;
        char *pPriv = NULL;

        memset( &sECKeyVal, 0x00, sizeof(sECKeyVal));

        ret = getValue( sObjects[0], CKA_EC_POINT, &binPoint );
        ret = getValue( sObjects[0], CKA_EC_PARAMS, &binGroup );
        ret = getValue( sObjects[0], CKA_VALUE, &binPriv );

        JS_BIN_encodeHex( &binPoint, &pPoint );
        JS_BIN_encodeHex( &binGroup, &pGroup );
        JS_BIN_encodeHex( &binPriv, &pPriv );

        JS_PKI_setECKeyVal( &sECKeyVal, pGroup, pPoint, pPriv );

        JS_PKI_encodeECPrivateKey( &sECKeyVal, &binPri );

        JS_BIN_reset( &binPoint );
        JS_BIN_reset( &binGroup );
        JS_BIN_reset( &binPriv );
        if(pPoint) JS_free( pPoint );
        if( pGroup ) JS_free( pGroup );
        if( pPriv ) JS_free( pPriv );

        JS_PKI_resetECKeyVal( &sECKeyVal );
    }
    else
    {
        ret = JS_KMS_ERROR_NOT_SUPPORT_PARAM;
        goto end;
    }

    PrivateKey *pPriKey = NULL;
    pPriKey = (PrivateKey *)JS_calloc(1, sizeof(PrivateKey));

    ByteString *material = (ByteString *)JS_calloc(1, sizeof(ByteString));
    material->size = binPri.nLen;
    material->value = binPri.pVal;

    KeyValue *key_value = (KeyValue *)JS_calloc(1, sizeof(KeyValue));
    key_value->key_material = material;

    KeyBlock *key_block = (KeyBlock *)JS_calloc(1, sizeof(KeyBlock));
    key_block->key_value = key_value;
    key_block->key_format_type = KMIP_KEYFORMAT_RAW;
    key_block->cryptographic_length = binVal.nLen * 8;

    if( nKeyType == JS_PKI_KEY_TYPE_RSA )
        key_block->cryptographic_algorithm = KMIP_CRYPTOALG_RSA;
    else if( nKeyType == JS_PKI_KEY_TYPE_ECC )
        key_block->cryptographic_algorithm = KMIP_CRYPTOALG_ECDSA;

    pPriKey->key_block = key_block;
    *ppPriKey = pPriKey;

 end :

    return ret;
}

static int _getCert( const BIN *pID, Certificate **ppCert )
{
    int ret = 0;
    BIN binVal = {0,0};

    CK_OBJECT_HANDLE    sObjects[20];
    ret = findObjects( CKO_CERTIFICATE, pID, sObjects );

    if( ret <= 0 )
    {
        ret = JS_KMS_ERROR_NO_OBJECT;
        goto end;
    }

    ret = getValue( sObjects[0], CKA_VALUE, &binVal );
    if( ret != CKR_OK )
    {
        ret = JS_KMS_ERROR_FAIL_GET_VALUE;
        goto end;
    }

    if( ret == CKR_OK )
    {
        Certificate *pCert = NULL;
        pCert = (Certificate *)JS_calloc( 1, sizeof(Certificate));
        pCert->certificate_type = KMIP_CERT_X509;

        ByteString *pCertVal = NULL;
        pCertVal = (ByteString *)JS_calloc(1, sizeof(ByteString));

        pCertVal->value = binVal.pVal;
        pCertVal->size = binVal.nLen;

        pCert->certificate_value = pCertVal;

        *ppCert = pCert;
    }


end :

    return ret;
}

int runGet( sqlite3 *db, const GetRequestPayload *pReqPayload, GetResponsePayload **ppRspPayload )
{
    int ret = 0;
    BIN binID = {0,0};

    JDB_KMS sKMS;
    char    sSeq[32];
    int     nSeq = 0;

    memset( &sKMS, 0x00, sizeof(sKMS));
    memset( sSeq, 0x00, sizeof(sSeq));

    memcpy( sSeq, pReqPayload->unique_identifier->value, pReqPayload->unique_identifier->size );
    nSeq = atoi( sSeq );

    JS_BIN_set( &binID, pReqPayload->unique_identifier->value, pReqPayload->unique_identifier->size );

    ret = JS_DB_getKMS( db, nSeq, &sKMS );
    if( ret < 1 )
    {
        ret = JS_KMS_ERROR_NO_OBJECT;
        goto end;
    }

    if( sKMS.nStatus == 0 )
    {
        ret = JS_KMS_ERROR_NOT_ACTIVATE;
        goto end;
    }

    GetResponsePayload *gsp = (GetResponsePayload *)JS_calloc( 1, sizeof(GetResponsePayload));


    if( sKMS.nType == JS_KMS_OBJECT_TYPE_CERT )
    {
        Certificate *pCert = NULL;
        ret = _getCert( &binID, &pCert );
        if( ret != 0 )
        {
            fprintf( stderr, "fail to get certificate(%d)\n", ret );
            goto end;
        }

        gsp->object_type = KMIP_OBJTYPE_CERTIFICATE;
        gsp->object = pCert;
    }
    else if( sKMS.nType == JS_KMS_OBJECT_TYPE_PRIKEY )
    {
        PrivateKey *pPriKey = NULL;
        ret = _getPrivateKey( &binID, sKMS.nAlgorithm, &pPriKey );
        if( ret != 0 )
        {
            fprintf( stderr, "fail to get private key(%d)\n", ret );
            goto end;
        }

        gsp->object_type = KMIP_OBJTYPE_PRIVATE_KEY;
        gsp->object = pPriKey;

    }
    else if( sKMS.nType == JS_KMS_OBJECT_TYPE_PUBKEY )
    {
        PublicKey *pPubKey = NULL;
        ret = _getPublicKey( &binID, sKMS.nAlgorithm, &pPubKey );

        if( ret != 0 )
        {
            fprintf( stderr, "fail to get public key(%d)\n", ret );
            goto end;
        }

        gsp->object_type = KMIP_OBJTYPE_PUBLIC_KEY;
        gsp->object = pPubKey;
    }
    else if( sKMS.nType == JS_KMS_OBJECT_TYPE_SECRET )
    {
        SymmetricKey *pSymKey = NULL;
        ret = _getSecretKey( &binID, sKMS.nAlgorithm, &pSymKey );

        if( ret != 0 )
        {
            fprintf( stderr, "fail to get secret key(%d)\n", ret );
            goto end;
        }

        gsp->object_type = KMIP_OBJTYPE_SYMMETRIC_KEY;
        gsp->object = pSymKey;
    }
    else
    {
        ret = JS_KMS_ERROR_NOT_SUPPORT_PARAM;
        goto end;
    }

    gsp->unique_identifier = (TextString *)JS_malloc( sizeof(TextString));
    gsp->unique_identifier->size = binID.nLen;
    gsp->unique_identifier->value = (unsigned char *)JS_calloc( 1, binID.nLen );
    memcpy( gsp->unique_identifier->value, binID.pVal, binID.nLen );

    *ppRspPayload = gsp;
    ret = JS_KMS_OK;

end :
    JS_DB_resetKMS( &sKMS );
    JS_BIN_reset( &binID );
    return ret;
}

int runCreate( sqlite3 *db, const CreateRequestPayload *pReqPayload, CreateResponsePayload **ppRspPayload  )
{
    int ret = 0;

    CK_ATTRIBUTE        sTemplate[20];
    CK_ULONG            uCount = 0;
    CK_OBJECT_HANDLE hObject = 0;
    CK_MECHANISM    sMech;

    int             *pnAlg = NULL;
    int             *pnLen = NULL;
    int             *pnMask = NULL;
    long             uLen = 0;
    int             nType = 0;
    int             nKeyAlg = 0;

    CK_BBOOL bTrue = CK_TRUE;
    CK_BBOOL bFalse = CK_FALSE;
    int             nSeq = -1;
    char            sID[16];
    JDB_KMS         sKMS;

    memset( sID, 0x00, sizeof(sID));
    memset( &sKMS, 0x00, sizeof(sKMS));
    memset( &sMech, 0x00, sizeof(sMech));

    nSeq = JS_DB_getSeq( db, "TB_KMS" );
    if( nSeq < 0 )
    {
        fprintf( stderr, "fail to get seq(%d)\n", nSeq );
        ret = JS_KMS_ERROR_SYSTEM;
        goto end;
    }

    nSeq++;
    printf( "Seq : %d\n", nSeq );

    sprintf( sID, "%d", nSeq );


    if( pReqPayload->object_type == KMIP_OBJTYPE_SYMMETRIC_KEY )
    {
        nType = JS_KMS_OBJECT_TYPE_SECRET;
        nKeyAlg = JS_PKI_KEY_TYPE_AES;

        CK_OBJECT_CLASS keyClass = CKO_SECRET_KEY;
        sTemplate[uCount].type = CKA_CLASS;
        sTemplate[uCount].pValue = &keyClass;
        sTemplate[uCount].ulValueLen = sizeof(keyClass);
        uCount++;

        sTemplate[uCount].type = CKA_PRIVATE;
        sTemplate[uCount].pValue = &bTrue;
        sTemplate[uCount].ulValueLen = sizeof(CK_BBOOL);
        uCount++;

        sTemplate[uCount].type = CKA_ID;
        sTemplate[uCount].pValue = sID;
        sTemplate[uCount].ulValueLen = strlen( sID );
        uCount++;

        sTemplate[uCount].type = CKA_TOKEN;
        sTemplate[uCount].pValue = &bTrue;
        sTemplate[uCount].ulValueLen = sizeof(CK_BBOOL);
        uCount++;

        sTemplate[uCount].type = CKA_EXTRACTABLE;
        sTemplate[uCount].pValue = &bTrue;
        sTemplate[uCount].ulValueLen = sizeof(CK_BBOOL);
        uCount++;

        sTemplate[uCount].type = CKA_LABEL;
        sTemplate[uCount].pValue = strdup( "KMS Label" );
        sTemplate[uCount].ulValueLen = strlen( "KMS Label" );
        uCount++;

        TemplateAttribute *ta = pReqPayload->template_attribute;
        for( int i = 0; i < ta->attribute_count; i++ )
        {
            if( ta->attributes[i].type == KMIP_ATTR_CRYPTOGRAPHIC_ALGORITHM )
            {
                pnAlg = ta->attributes[i].value;

                if( *pnAlg == KMIP_CRYPTOALG_AES )
                {
                    sMech.mechanism = JS_PKCS11_GetCKMType( "CKM_AES_KEY_GEN" );
                }
            }
            else if( ta->attributes[i].type == KMIP_ATTR_CRYPTOGRAPHIC_LENGTH )
            {
                pnLen = ta->attributes[i].value;

                uLen = *pnLen;
                uLen = uLen / 8;

                sTemplate[uCount].type = CKA_VALUE_LEN;
                sTemplate[uCount].pValue = &uLen;
                sTemplate[uCount].ulValueLen = sizeof(uLen);
                uCount++;
            }
            else if( ta->attributes[i].type == KMIP_ATTR_CRYPTOGRAPHIC_USAGE_MASK )
            {
                pnMask = ta->attributes[i].value;

                if( *pnMask | KMIP_CRYPTOMASK_ENCRYPT )
                {
                    sTemplate[uCount].type = CKA_ENCRYPT;
                    sTemplate[uCount].pValue = &bTrue;
                    sTemplate[uCount].ulValueLen = sizeof(CK_BBOOL);
                    uCount++;
                }

                if( *pnMask | KMIP_CRYPTOMASK_DECRYPT )
                {
                    sTemplate[uCount].type = CKA_DECRYPT;
                    sTemplate[uCount].pValue = &bTrue;
                    sTemplate[uCount].ulValueLen = sizeof(CK_BBOOL);
                    uCount++;
                }
            }
        }

        ret = JS_PKCS11_GenerateKey( g_pP11CTX, &sMech, sTemplate, uCount, &hObject );
        if( ret != CKR_OK )
        {
            fprintf( stderr, "fail to run generate key(%s:%d)\n", JS_PKCS11_GetErrorMsg(ret), ret );
            ret = JS_KMS_ERROR_FAIL_GEN_KEY;
            goto end;
        }
        else
        {
            printf( "GenerateKey success(%d)\n", hObject );
        }
    }

    CreateResponsePayload   *pld = (CreateRequestPayload *)JS_calloc( 1, sizeof(CreateResponsePayload ) );
    pld->object_type = KMIP_OBJTYPE_SYMMETRIC_KEY;


    if( ret == 0 )
    {
        pld->unique_identifier = (TextString *)JS_malloc(sizeof(TextString));
        pld->unique_identifier->size = strlen( sID );
        pld->unique_identifier->value = JS_strdup( sID );
        *ppRspPayload = pld;
    }

    JS_DB_setKMS( &sKMS, nSeq, time(NULL), 0, nType, nKeyAlg, sID, "SymKey" );
    JS_DB_addKMS( db, &sKMS );
    ret = JS_KMS_OK;

end :
    JS_DB_resetKMS( &sKMS );
    return 0;
}

int runDestroy( sqlite3 *db, const DestroyRequestPayload *pReqPayload, DestroyResponsePayload **ppRspPayload )
{
    int ret = 0;
    BIN binID = {0,0};
    CK_OBJECT_HANDLE    sObjects[20];
    char sSeq[16];
    int nSeq = -1;
    JDB_KMS     sKMS;
    long        uObjClass = -1;

    memset( sSeq, 0x00, sizeof(sSeq));
    memset( &sKMS, 0x00, sizeof(sKMS));


    JS_BIN_set( &binID, pReqPayload->unique_identifier->value, pReqPayload->unique_identifier->size );
    memcpy( sSeq, pReqPayload->unique_identifier->value, pReqPayload->unique_identifier->size );

    nSeq = atoi( sSeq );
    ret = JS_DB_getKMS( db, nSeq, &sKMS );
    if( ret != 1 )
    {
        fprintf( stderr, "fail to get seq(%d)\n", nSeq );
        ret = JS_KMS_ERROR_SYSTEM;
        goto end;
    }

    if( sKMS.nType == JS_KMS_OBJECT_TYPE_CERT )
        uObjClass = CKO_CERTIFICATE;
    else if( sKMS.nType == JS_KMS_OBJECT_TYPE_PRIKEY )
        uObjClass = CKO_PRIVATE_KEY;
    else if( sKMS.nType == JS_KMS_OBJECT_TYPE_PUBKEY )
        uObjClass = CKO_PUBLIC_KEY;
    else if( sKMS.nType == JS_KMS_OBJECT_TYPE_SECRET )
        uObjClass = CKO_SECRET_KEY;
    else if( sKMS.nType == JS_KMS_OBJECT_TYPE_DATA )
        uObjClass = CKO_DATA;
    else
    {
        ret = JS_KMS_ERROR_INVALID_VALUE;
        goto end;
    }

    ret = findObjects( uObjClass, &binID, sObjects );

    if( ret <= 0 )
    {
        fprintf(stderr, "fail to find objects(%d)\n", ret );
        ret = JS_KMS_ERROR_NO_OBJECT;

        goto end;
    }

    ret = JS_PKCS11_DestroyObject( g_pP11CTX, sObjects[0] );
    if( ret != CKR_OK )
    {
        fprintf( stderr, "fail to destroy object(%s:%d)\n", JS_PKCS11_GetErrorMsg(ret), ret );
        ret = JS_KMS_ERROR_FAIL_DESTROY_OBJECT;

        goto end;
    }

    DestroyResponsePayload *dsp = (DestroyResponsePayload *)JS_calloc(1, sizeof(DestroyResponsePayload));

    dsp->unique_identifier = (TextString *)JS_malloc( sizeof(TextString));
    dsp->unique_identifier->size = binID.nLen;
    dsp->unique_identifier->value = (unsigned char *)JS_calloc( 1, binID.nLen );

    memcpy( dsp->unique_identifier->value, binID.pVal, binID.nLen );
    *ppRspPayload = dsp;

    ret = JS_KMS_OK;
    JS_DB_delKMS( db, atoi(sSeq));

end :
    JS_BIN_reset( &binID );
    return ret;
}

int runActivate( sqlite3 *db, const ActivateRequestPayload *pReqPayload, ActivateResponsePayload **ppRspPayload )
{
    int ret = 0;
    BIN binID = {0,0};
    CK_OBJECT_HANDLE    sObjects[20];
    char sSeq[16];
    JDB_KMS sKMS;

    memset( sSeq, 0x00, sizeof(sSeq));
    memset( &sKMS, 0x00, sizeof(sKMS));


    JS_BIN_set( &binID, pReqPayload->unique_identifier->value, pReqPayload->unique_identifier->size );
    memcpy( sSeq, pReqPayload->unique_identifier->value, pReqPayload->unique_identifier->size );

    ret = JS_DB_getKMS( db, atoi(sSeq), &sKMS );
    if( ret != 1 )
    {
        ret = JS_KMS_ERROR_SYSTEM;
        goto end;
    }

    sKMS.nStatus = 1;

    ret = JS_DB_modKMS( db, atoi(sSeq), &sKMS );
    if( ret != 0 )
    {
        ret = JS_KMS_ERROR_SYSTEM;
        goto end;
    }


    ActivateResponsePayload *asp = (ActivateResponsePayload *)JS_calloc(1, sizeof(ActivateResponsePayload));

    asp->unique_identifier = (TextString *)JS_malloc( sizeof(TextString));
    asp->unique_identifier->size = binID.nLen;
    asp->unique_identifier->value = (unsigned char *)JS_calloc( 1, binID.nLen );

    memcpy( asp->unique_identifier->value, binID.pVal, binID.nLen );
    *ppRspPayload = asp;

    ret = JS_KMS_OK;

end :
    JS_BIN_reset( &binID );
    JS_DB_resetKMS( &sKMS );

    return ret;
}

int runEncrypt( sqlite3 *db, const EncryptRequestPayload *pReqPayload, EncryptResponsePayload **ppRspPayload )
{
    int ret = 0;
    BIN binIV = {0};
    BIN binPlain = {0};
    BIN binID = {0};
    CK_OBJECT_HANDLE    sObjects[20];
    CK_MECHANISM stMech = {0};
    unsigned char *pEncData = NULL;
    long uEncDataLen = 0;
    int nMech = 0;
    int nSeq = -1;
    char sSeq[64];

    JDB_KMS sKMS;
    memset( &sKMS, 0x00, sizeof(sKMS));
    memset( sSeq, 0x00, sizeof(sSeq));

    memcpy( sSeq, pReqPayload->unique_identifier->value, pReqPayload->unique_identifier->size );
    nSeq = atoi( sSeq );

    ret = JS_DB_getKMS( db, nSeq, &sKMS );
    if( ret < 1 )
    {
        ret = JS_KMS_ERROR_NO_OBJECT;
        goto end;
    }

    if( sKMS.nStatus == 0 )
    {
        ret = JS_KMS_ERROR_NOT_ACTIVATE;
        goto end;
    }

    JS_BIN_set( &binID, pReqPayload->unique_identifier->value, pReqPayload->unique_identifier->size );
    ret = findObjects( CKO_SECRET_KEY, &binID, sObjects );
    if( ret < 1 )
    {
        ret = JS_KMS_ERROR_NO_OBJECT;
        goto end;
    }

    ret = JS_KMS_setMechParam( pReqPayload->cryptographic_parameters, &nMech );
    if( ret < 0 )
    {
        ret = JS_KMS_ERROR_NOT_SUPPORT_PARAM;
        goto end;
    }

    stMech.mechanism = nMech;

    JS_BIN_set( &binPlain, pReqPayload->data->value, pReqPayload->data->size );
    JS_BIN_set( &binIV, pReqPayload->iv_counter_nonce->value, pReqPayload->iv_counter_nonce->size );

    stMech.pParameter = binIV.pVal;
    stMech.ulParameterLen = binIV.nLen;

    ret = JS_PKCS11_EncryptInit( g_pP11CTX, &stMech, sObjects[0] );
    if( ret != 0 )
    {
        ret = JS_KMS_ERROR_SYSTEM;
        goto end;
    }

    pEncData = (unsigned char *)JS_malloc( binPlain.nLen + 64 );
    uEncDataLen = binPlain.nLen + 64;

    ret = JS_PKCS11_Encrypt( g_pP11CTX, binPlain.pVal, binPlain.nLen, pEncData, &uEncDataLen );
    if( ret != 0 )
    {
        ret = JS_KMS_ERROR_SYSTEM;
        goto end;
    }

    EncryptResponsePayload *pESP = (EncryptResponsePayload *)JS_calloc( 1, sizeof(EncryptResponsePayload));
    pESP->data = (ByteString *)JS_malloc(sizeof(ByteString));
    pESP->data->value = pEncData;
    pESP->data->size = uEncDataLen;

    pESP->unique_identifier = (TextString *)JS_malloc(sizeof(TextString));
    pESP->unique_identifier->value = binID.pVal;
    pESP->unique_identifier->size = binID.nLen;

    *ppRspPayload = pESP;

end :
    if( ret != JS_KMS_OK )
    {
        if( pEncData ) JS_free( pEncData );
        JS_BIN_reset( &binID );
    }

    JS_BIN_reset( &binIV );
    JS_BIN_reset( &binPlain );
    JS_DB_resetKMS( &sKMS );

    return ret;
}

int runDecrypt( sqlite3 *db, const DecryptRequestPayload *pReqPayload, DecryptResponsePayload **ppRspPayload )
{
    int ret = 0;
    BIN binIV = {0};
    BIN binEncrypt = {0};
    BIN binID = {0};
    CK_OBJECT_HANDLE    sObjects[20];
    CK_MECHANISM stMech = {0};
    unsigned char *pDecData = NULL;
    long uDecDataLen = 0;
    int nMech = 0;
    int nSeq = -1;
    char sSeq[64];
    JDB_KMS sKMS;


    memset( &sKMS, 0x00, sizeof(sKMS));
    memset( sSeq, 0x00, sizeof(sSeq));

    memcpy( sSeq, pReqPayload->unique_identifier->value, pReqPayload->unique_identifier->size );
    nSeq = atoi( sSeq );

    ret = JS_DB_getKMS( db, nSeq, &sKMS );
    if( ret < 1 )
    {
        ret = JS_KMS_ERROR_NO_OBJECT;
        goto end;
    }

    if( sKMS.nStatus == 0 )
    {
        ret = JS_KMS_ERROR_NOT_ACTIVATE;
        goto end;
    }

    JS_BIN_set( &binID, pReqPayload->unique_identifier->value, pReqPayload->unique_identifier->size );
    ret = findObjects( CKO_SECRET_KEY, &binID, sObjects );
    if( ret < 1 )
    {
        ret = JS_KMS_ERROR_NO_OBJECT;
        goto end;
    }

    ret = JS_KMS_setMechParam( pReqPayload->cryptographic_parameters, &nMech );
    if( ret < 0 )
    {
        ret = JS_KMS_ERROR_NOT_SUPPORT_PARAM;
        goto end;
    }

    stMech.mechanism = nMech;

    JS_BIN_set( &binEncrypt, pReqPayload->data->value, pReqPayload->data->size );
    JS_BIN_set( &binIV, pReqPayload->iv_counter_nonce->value, pReqPayload->iv_counter_nonce->size );

    stMech.pParameter = binIV.pVal;
    stMech.ulParameterLen = binIV.nLen;

    ret = JS_PKCS11_DecryptInit( g_pP11CTX, &stMech, sObjects[0] );
    if( ret != 0 )
    {
        ret = JS_KMS_ERROR_SYSTEM;
        goto end;
    }

    pDecData = (unsigned char *)JS_malloc( binEncrypt.nLen + 64 );
    uDecDataLen = binEncrypt.nLen + 64;

    ret = JS_PKCS11_Decrypt( g_pP11CTX, binEncrypt.pVal, binEncrypt.nLen, pDecData, &uDecDataLen );
    if( ret != 0 )
    {
        ret = JS_KMS_ERROR_SYSTEM;
        goto end;
    }

    DecryptResponsePayload *pDSP = (DecryptResponsePayload *)JS_calloc( 1, sizeof(DecryptResponsePayload));
    pDSP->data = (ByteString *)JS_malloc(sizeof(ByteString));
    pDSP->data->value = pDecData;
    pDSP->data->size = uDecDataLen;

    pDSP->unique_identifier = (TextString *)JS_malloc(sizeof(TextString));
    pDSP->unique_identifier->value = binID.pVal;
    pDSP->unique_identifier->size = binID.nLen;

    *ppRspPayload = pDSP;

end :
    if( ret != JS_KMS_OK )
    {
        if( pDecData ) JS_free( pDecData );
        JS_BIN_reset( &binID );
    }

    JS_BIN_reset( &binIV );
    JS_BIN_reset( &binEncrypt );
    JS_DB_resetKMS( &sKMS );

    return ret;
}

int runSign( sqlite3 *db, const SignRequestPayload *pReqPayload, SignResponsePayload **ppRspPayload )
{
    int ret = 0;
    BIN binID = {0};
    BIN binSign = {0};
    BIN binData = {0};
    CK_OBJECT_HANDLE    sObjects[20];

    CK_MECHANISM stMech = {0};
    unsigned char sSign[1024];
    long uSignLen = 0;
    int nMech = 0;
    int nSeq = -1;
    char sSeq[64];
    JDB_KMS sKMS;

    memset( &sKMS, 0x00, sizeof(sKMS));
    memset( &sSeq, 0x00, sizeof(sSeq));

    memcpy( sSeq, pReqPayload->unique_identifier->value, pReqPayload->unique_identifier->size );
    nSeq = atoi( sSeq );

    ret = JS_DB_getKMS( db, nSeq, &sKMS );
    if( ret < 1 )
    {
        ret = JS_KMS_ERROR_NO_OBJECT;
        goto end;
    }

    if( sKMS.nStatus == 0 )
    {
        ret = JS_KMS_ERROR_NOT_ACTIVATE;
        goto end;
    }

    JS_BIN_set( &binID, pReqPayload->unique_identifier->value, pReqPayload->unique_identifier->size );
    ret = findObjects( CKO_PRIVATE_KEY, &binID, sObjects );
    if( ret < 1 )
    {
        ret = JS_KMS_ERROR_NO_OBJECT;
        goto end;
    }

    ret = JS_KMS_setMechParam( pReqPayload->cryptographic_parameters, &nMech );
    if( ret < 0 )
    {
        ret = JS_KMS_ERROR_NOT_SUPPORT_PARAM;
        goto end;
    }

    stMech.mechanism = nMech;

    JS_BIN_set( &binData, pReqPayload->data->value, pReqPayload->data->size );

    ret = JS_PKCS11_SignInit( g_pP11CTX, &stMech, sObjects[0] );
    if( ret != CKR_OK )
    {
        ret = JS_KMS_ERROR_SYSTEM;
        goto end;
    }

    uSignLen = sizeof(sSign);

    ret = JS_PKCS11_Sign( g_pP11CTX, binData.pVal, binData.nLen, sSign, &uSignLen );
    if( ret != CKR_OK )
    {
        ret = JS_KMS_ERROR_SYSTEM;
        goto end;
    }

    SignResponsePayload *pSSP = (SignResponsePayload *)JS_calloc( 1, sizeof(SignResponsePayload));

    pSSP->signature_data = (ByteString *)JS_malloc(sizeof(ByteString));
    pSSP->signature_data->value = JS_malloc( uSignLen );
    memcpy( pSSP->signature_data->value, sSign, uSignLen );
    pSSP->signature_data->size = uSignLen;

    pSSP->unique_identifier = (TextString *)JS_malloc(sizeof(TextString));
    pSSP->unique_identifier->value = binID.pVal;
    pSSP->unique_identifier->size = binID.nLen;

    *ppRspPayload = pSSP;

end :
    if( ret != JS_KMS_OK )
    {
        JS_BIN_reset( &binID );
    }

    JS_DB_resetKMS( &sKMS );
    return ret;
}

int runVerify( sqlite3 *db, const SignatureVerifyRequestPayload *pReqPayload, SignatureVerifyResponsePayload **ppRspPayload )
{
    int ret = 0;
    BIN binID = {0};
    BIN binSign = {0};
    BIN binData = {0};
    CK_OBJECT_HANDLE    sObjects[20];
    int nMech = 0;
    int nSeq = -1;
    char sSeq[64];

    JDB_KMS sKMS;

    CK_MECHANISM stMech = {0};

    memset( &sKMS, 0x00, sizeof(sKMS));
    memset( &sSeq, 0x00, sizeof(sSeq));

    memcpy( sSeq, pReqPayload->unique_identifier->value, pReqPayload->unique_identifier->size );
    nSeq = atoi( sSeq );

    ret = JS_DB_getKMS( db, nSeq, &sKMS );
    if( ret < 1 )
    {
        ret = JS_KMS_ERROR_NO_OBJECT;
        goto end;
    }

    if( sKMS.nStatus == 0 )
    {
        ret = JS_KMS_ERROR_NOT_ACTIVATE;
        goto end;
    }

    JS_BIN_set( &binID, pReqPayload->unique_identifier->value, pReqPayload->unique_identifier->size );
    ret = findObjects( CKO_PUBLIC_KEY, &binID, sObjects );
    if( ret < 1 )
    {
        ret = JS_KMS_ERROR_NO_OBJECT;
        goto end;
    }

    ret = JS_KMS_setMechParam( pReqPayload->cryptographic_parameters, &nMech );
    if( ret < 0 )
    {
        ret = JS_KMS_ERROR_NOT_SUPPORT_PARAM;
        goto end;
    }

    stMech.mechanism = nMech;

    JS_BIN_set( &binData, pReqPayload->data->value, pReqPayload->data->size );
    JS_BIN_set( &binSign, pReqPayload->signature_data->value, pReqPayload->signature_data->size );

    ret = JS_PKCS11_VerifyInit( g_pP11CTX, &stMech, sObjects[0] );
    if( ret != CKR_OK )
    {
        ret = JS_KMS_ERROR_SYSTEM;
        goto end;
    }

    ret = JS_PKCS11_Verify( g_pP11CTX, binData.pVal, binData.nLen, binSign.pVal, binSign.nLen );
    if( ret != CKR_OK )
    {
        ret = JS_KMS_ERROR_SYSTEM;
        goto end;
    }

    SignatureVerifyResponsePayload *pVSP = (SignatureVerifyResponsePayload *)JS_calloc( 1, sizeof(SignatureVerifyResponsePayload));

    pVSP->validity_indicator = KMIP_VALIDITY_VALID;

    pVSP->unique_identifier = (TextString *)JS_malloc(sizeof(TextString));
    pVSP->unique_identifier->value = binID.pVal;
    pVSP->unique_identifier->size = binID.nLen;

    *ppRspPayload = pVSP;

end :
    if( ret != JS_KMS_OK )
    {
        JS_BIN_reset( &binID );
    }

    JS_DB_resetKMS( &sKMS );
    return ret;
}

int runGetAttributeList( sqlite3 *db, const GetAttributeListRequestPayload *pReqPayload, GetAttributeListResponsePayload **ppRspPayload )
{
    return 0;
}

int runHash( sqlite3 *db, const HashRequestPayload *pReqPayload, HashResponsePayload **ppRspPayload )
{
    int ret = 0;
    int nMech = 0;

    CK_MECHANISM    stMech = {0};
    CK_ULONG        uDigestLen = 64;
    unsigned char   sDigest[64];
    HashResponsePayload *pRspPayload = NULL;

    ret = JS_KMS_setMechParam( pReqPayload->crypt_params, &nMech );
    stMech.mechanism = nMech;

    ret = JS_PKCS11_DigestInit( g_pP11CTX, &stMech );
    if( ret != CKR_OK )
    {
        goto end;
    }

    ret = JS_PKCS11_Digest( g_pP11CTX, pReqPayload->data->value, pReqPayload->data->size, sDigest, &uDigestLen );
    if( ret != CKR_OK )
    {
        goto end;
    }

    pRspPayload = (HashResponsePayload *)JS_calloc( 1, sizeof(HashResponsePayload));
    pRspPayload->data = (ByteString *)JS_malloc(sizeof(ByteString));
    pRspPayload->data->value = JS_malloc( uDigestLen );
    memcpy( pRspPayload->data->value, sDigest, uDigestLen );
    pRspPayload->data->size = uDigestLen;

    *ppRspPayload = pRspPayload;

end :


    return ret;
}

int runRNGRetrieve( sqlite3 *db, const RNGRetrieveRequestPayload *pReqPayload, const RNGRetrieveResponsePayload **ppRspPayload )
{
    int ret = 0;
    int nDataLen = 0;
    RNGRetrieveResponsePayload  *pRspPayload = NULL;

    nDataLen = pReqPayload->data_length;
    unsigned char *pRand = NULL;

    pRand = (unsigned char *)JS_calloc( 1, nDataLen );

    ret = JS_PKCS11_GenerateRandom( g_pP11CTX, pRand, nDataLen );
    if( ret != CKR_OK )
    {
        goto end;
    }

    pRspPayload = (RNGRetrieveResponsePayload *)JS_calloc( 1, sizeof(RNGRetrieveResponsePayload));
    pRspPayload->data = (ByteString *)JS_malloc(sizeof(ByteString));
    pRspPayload->data->value = JS_malloc( nDataLen );
    memcpy( pRspPayload->data->value, pRand, nDataLen );
    pRspPayload->data->size = nDataLen;

    *ppRspPayload = pRspPayload;

end :
    if( pRand ) JS_free( pRand );

    return ret;
}

int runRNGSeed( sqlite3 *db, const RNGSeedRequestPayload *pReqPayload, const RNGSeedResponsePayload **ppRspPayload )
{
    int ret = 0;
    RNGSeedResponsePayload  *pRspPayload = NULL;

    ret = JS_PKCS11_SeedRandom( g_pP11CTX, pReqPayload->data->value, pReqPayload->data->size );
    if( ret != 0 )
    {
        goto end;
    }

    pRspPayload = (RNGSeedResponsePayload *)JS_calloc( 1, sizeof(RNGSeedResponsePayload));
    pRspPayload->data_length = pReqPayload->data->size;

    *ppRspPayload = pRspPayload;

end :

    return ret;
}


static int registerCert( const BIN *pID, const RegisterRequestPayload *pRRP )
{
    int ret = 0;

    CK_ATTRIBUTE sTemplate[20];
    CK_ULONG    uCount = 0;
    CK_OBJECT_HANDLE    hObject = 0;
    CK_OBJECT_CLASS objClass = CKO_CERTIFICATE;
    CK_CERTIFICATE_TYPE certType = CKC_X_509;
    CK_BBOOL bTrue = CK_TRUE;
    CK_BBOOL bFalse = CK_FALSE;


    if( pRRP == NULL )
        return JS_KMS_ERROR_NO_PAYLOAD;

    TemplateAttribute *pta = pRRP->template_attribute;
    Certificate *pcert = pRRP->object;

    sTemplate[uCount].type = CKA_CLASS;
    sTemplate[uCount].pValue = &objClass;
    sTemplate[uCount].ulValueLen = sizeof(objClass);
    uCount++;

    sTemplate[uCount].type = CKA_CERTIFICATE_TYPE;
    sTemplate[uCount].pValue = &certType;
    sTemplate[uCount].ulValueLen = sizeof(certType);
    uCount++;

    sTemplate[uCount].type = CKA_ID;
    sTemplate[uCount].pValue = pID->pVal;
    sTemplate[uCount].ulValueLen = pID->nLen;
    uCount++;

    sTemplate[uCount].type = CKA_VALUE;
    sTemplate[uCount].pValue = pcert->certificate_value->value;
    sTemplate[uCount].ulValueLen = pcert->certificate_value->size;
    uCount++;

    for( int i = 0; i < pta->attribute_count; i++ )
    {
        if( pta->attributes[i].type == KMIP_ATTR_NAME )
        {
            Name *pname = pta->attributes[i].value;

            sTemplate[uCount].type = CKA_LABEL;
            sTemplate[uCount].pValue = pname->value->value;
            sTemplate[uCount].ulValueLen = pname->value->size;
            uCount++;

            sTemplate[uCount].type = CKA_SUBJECT;
            sTemplate[uCount].pValue = pname->value->value;
            sTemplate[uCount].ulValueLen = pname->value->size;
            uCount++;
        }
    }

    sTemplate[uCount].type = CKA_TOKEN;
    sTemplate[uCount].pValue = &bTrue;
    sTemplate[uCount].ulValueLen = sizeof(bTrue);
    uCount++;

    ret = JS_PKCS11_CreateObject( g_pP11CTX, sTemplate, uCount, &hObject );
    if( ret != CKR_OK )
    {
        sprintf( g_pP11CTX->sLastLog, "%s:%d", JS_PKCS11_GetErrorMsg(ret), ret );
        return JS_KMS_ERROR_SYSTEM;
    }

    return 0;
}

static int registerPriKey( const BIN *pID, const RegisterRequestPayload *pRRP, int *pnKeyAlg )
{
    int ret = 0;

    CK_ATTRIBUTE sTemplate[20];
    CK_ULONG    uCount = 0;
    CK_OBJECT_HANDLE    hObject = 0;
    CK_OBJECT_CLASS objClass = CKO_PRIVATE_KEY;
    CK_KEY_TYPE keyType = CKK_RSA;
    CK_BBOOL bTrue = CK_TRUE;
    CK_BBOOL bFalse = CK_FALSE;
    PrivateKey *pPriKey = NULL;
    KeyValue *pKeyValue = NULL;
    ByteString *pMaterial = NULL;
    int nLen = 0;
    JRSAKeyVal      sRSAKeyVal;
    JECKeyVal       sECKeyVal;

    BIN     binN = {0};
    BIN     binE = {0};
    BIN     binD = {0};
    BIN     binP = {0};
    BIN     binQ = {0};
    BIN     binDMP1 = {0};
    BIN     binDMQ1 = {0};
    BIN     binIQMP = {0};

    BIN     binECParam = {0};
    BIN     binECPrivate = {0};

    BIN     binPri = {0};

    if( pRRP == NULL )
        return JS_KMS_ERROR_NO_PAYLOAD;

    memset( &sRSAKeyVal, 0x00, sizeof(sRSAKeyVal));
    memset( &sECKeyVal, 0x00, sizeof(sECKeyVal));

    sTemplate[uCount].type = CKA_CLASS;
    sTemplate[uCount].pValue = &objClass;
    sTemplate[uCount].ulValueLen = sizeof(objClass);
    uCount++;

    pPriKey = pRRP->object;

    if( pPriKey->key_block->cryptographic_algorithm == KMIP_CRYPTOALG_RSA )
    {
        keyType = CKK_RSA;
        sTemplate[uCount].type = CKA_KEY_TYPE;
        sTemplate[uCount].pValue = &keyType;
        sTemplate[uCount].ulValueLen = sizeof(keyType);
        uCount++;

        *pnKeyAlg = JS_PKI_KEY_TYPE_RSA;
    }
    else if( pPriKey->key_block->cryptographic_algorithm == KMIP_CRYPTOALG_ECDSA )
    {
        keyType = CKK_ECDSA;
        sTemplate[uCount].type = CKA_KEY_TYPE;
        sTemplate[uCount].pValue = &keyType;
        sTemplate[uCount].ulValueLen = sizeof(keyType);
        uCount++;

        *pnKeyAlg = JS_PKI_KEY_TYPE_ECC;
    }
    else
    {
        ret = JS_KMS_ERROR_NOT_SUPPORT_PARAM;
        return ret;
    }

    sTemplate[uCount].type = CKA_ID;
    sTemplate[uCount].pValue = pID->pVal;
    sTemplate[uCount].ulValueLen = pID->nLen;
    uCount++;

    pKeyValue = pPriKey->key_block->key_value;

    if( pKeyValue == NULL )
    {
        ret = JS_KMS_ERROR_NO_PAYLOAD;
        return ret;
    }

    pMaterial = pKeyValue->key_material;
    JS_BIN_set( &binPri, pMaterial->value, pMaterial->size );

    TemplateAttribute *pta = pRRP->template_attribute;

    for( int i = 0; i < pta->attribute_count; i++ )
    {
        if( pta->attributes[i].type == KMIP_ATTR_CRYPTOGRAPHIC_USAGE_MASK )
        {

        }
        else if( pta->attributes[i].type == KMIP_ATTR_NAME )
        {
            Name *pname = pta->attributes[i].value;

            sTemplate[uCount].type = CKA_LABEL;
            sTemplate[uCount].pValue = pname->value->value;
            sTemplate[uCount].ulValueLen = pname->value->size;
            uCount++;
        }
        else if( pta->attributes[i].type == KMIP_ATTR_RECOMMENDED_CURVE )
        {
            enum recommended_curve *curve = pta->attributes[i].value;

            ret = JS_KMS_getECParam( *curve, &binECParam );
            if( ret != 0 )
            {
                ret = JS_KMS_ERROR_NOT_SUPPORT_PARAM;
                goto end;
            }

            sTemplate[uCount].type = CKA_EC_PARAMS;
            sTemplate[uCount].pValue = binECParam.pVal;
            sTemplate[uCount].ulValueLen = binECParam.nLen;
            uCount++;
        }
    }

    if( keyType == CKK_RSA )
    {
        ret = JS_PKI_getRSAKeyVal( &binPri, &sRSAKeyVal );
        if( ret != 0 )
        {
            ret = JS_KMS_ERROR_INVALID_VALUE;
            goto end;
        }

        JS_BIN_decodeHex( sRSAKeyVal.pN, &binN );
        JS_BIN_decodeHex( sRSAKeyVal.pE, &binE );
        JS_BIN_decodeHex( sRSAKeyVal.pD, &binD );
        JS_BIN_decodeHex( sRSAKeyVal.pP, &binP );
        JS_BIN_decodeHex( sRSAKeyVal.pQ, &binQ );
        JS_BIN_decodeHex( sRSAKeyVal.pDMP1, &binDMP1 );
        JS_BIN_decodeHex( sRSAKeyVal.pDMQ1, &binDMQ1 );
        JS_BIN_decodeHex( sRSAKeyVal.pIQMP, &binIQMP );

        sTemplate[uCount].type = CKA_MODULUS;
        sTemplate[uCount].pValue = binN.pVal;
        sTemplate[uCount].ulValueLen = binN.nLen;
        uCount++;

        sTemplate[uCount].type = CKA_PUBLIC_EXPONENT;
        sTemplate[uCount].pValue = binE.pVal;
        sTemplate[uCount].ulValueLen = binE.nLen;
        uCount++;

        sTemplate[uCount].type = CKA_PRIVATE_EXPONENT;
        sTemplate[uCount].pValue = binD.pVal;
        sTemplate[uCount].pValue = binD.nLen;
        uCount++;

        sTemplate[uCount].type = CKA_PRIME_1;
        sTemplate[uCount].pValue = binP.pVal;
        sTemplate[uCount].ulValueLen = binP.nLen;
        uCount++;

        sTemplate[uCount].type = CKA_PRIME_2;
        sTemplate[uCount].pValue = binQ.pVal;
        sTemplate[uCount].ulValueLen = binQ.nLen;
        uCount++;

        sTemplate[uCount].type = CKA_EXPONENT_1;
        sTemplate[uCount].pValue = binDMP1.pVal;
        sTemplate[uCount].ulValueLen = binDMP1.nLen;
        uCount++;

        sTemplate[uCount].type = CKA_EXPONENT_2;
        sTemplate[uCount].pValue = binDMQ1.pVal;
        sTemplate[uCount].ulValueLen = binDMQ1.nLen;
        uCount++;

        sTemplate[uCount].type = CKA_COEFFICIENT;
        sTemplate[uCount].pValue = binIQMP.pVal;
        sTemplate[uCount].ulValueLen = binIQMP.nLen;
        uCount++;
    }
    else if( keyType == CKK_ECDSA )
    {
        ret = JS_PKI_getECKeyVal( &binPri, &sECKeyVal );
        if( ret != 0 )
        {
            ret = JS_KMS_ERROR_INVALID_VALUE;
            goto end;
        }

        JS_BIN_decodeHex( sECKeyVal.pPrivate, &binECPrivate );

        sTemplate[uCount].type = CKA_VALUE;
        sTemplate[uCount].pValue = binECPrivate.pVal;
        sTemplate[uCount].ulValueLen = binECPrivate.nLen;
        uCount++;
    }


    sTemplate[uCount].type = CKA_DECRYPT;
    sTemplate[uCount].pValue = &bTrue;
    sTemplate[uCount].ulValueLen = sizeof(bTrue);
    uCount++;

    sTemplate[uCount].type = CKA_EXTRACTABLE;
    sTemplate[uCount].pValue = &bTrue;
    sTemplate[uCount].ulValueLen = sizeof(bTrue);
    uCount++;

    sTemplate[uCount].type = CKA_PRIVATE;
    sTemplate[uCount].pValue = &bTrue;
    sTemplate[uCount].ulValueLen = sizeof(bTrue);
    uCount++;

    sTemplate[uCount].type = CKA_SIGN;
    sTemplate[uCount].pValue = &bTrue;
    sTemplate[uCount].ulValueLen = sizeof(bTrue);
    uCount++;

    sTemplate[uCount].type = CKA_TOKEN;
    sTemplate[uCount].pValue = &bTrue;
    sTemplate[uCount].ulValueLen = sizeof(bTrue);
    uCount++;

    ret = JS_PKCS11_CreateObject( g_pP11CTX, sTemplate, uCount, &hObject );
    if( ret != 0 )
    {
        sprintf( g_pP11CTX->sLastLog, "%s:%d", JS_PKCS11_GetErrorMsg(ret), ret );
        ret = JS_KMS_ERROR_SYSTEM;
        goto end;
    }

end :
    JS_PKI_resetRSAKeyVal( &sRSAKeyVal );
    JS_PKI_resetECKeyVal( &sECKeyVal );
    JS_BIN_reset( &binPri );
    JS_BIN_reset( &binN );
    JS_BIN_reset( &binE );
    JS_BIN_reset( &binD );
    JS_BIN_reset( &binP );
    JS_BIN_reset( &binQ );
    JS_BIN_reset( &binDMP1 );
    JS_BIN_reset( &binDMQ1 );
    JS_BIN_reset( &binIQMP );

    JS_BIN_reset( &binECParam );
    JS_BIN_reset( &binECPrivate );

    return ret;
}

static int registerPubKey( const BIN *pID, const RegisterRequestPayload *pRRP, int *pnKeyAlg )
{
    int ret = 0;

    CK_ATTRIBUTE sTemplate[20];
    CK_ULONG    uCount = 0;
    CK_OBJECT_HANDLE    hObject = 0;
    CK_OBJECT_CLASS objClass = CKO_PUBLIC_KEY;
    CK_KEY_TYPE keyType = CKK_RSA;
    CK_BBOOL bTrue = CK_TRUE;
    CK_BBOOL bFalse = CK_FALSE;
    PublicKey *pPubKey = NULL;
    KeyValue *pKeyValue = NULL;
    ByteString *pMaterial = NULL;
    int nLen = 0;

    BIN     binN = {0};
    BIN     binE = {0};
    BIN     binPub = {0};
    char    *pHexN = NULL;
    char    *pHexE = NULL;

    BIN     binECParam = {0};


    if( pRRP == NULL )
        return JS_KMS_ERROR_NO_PAYLOAD;

    sTemplate[uCount].type = CKA_CLASS;
    sTemplate[uCount].pValue = &objClass;
    sTemplate[uCount].ulValueLen = sizeof(objClass);
    uCount++;

    pPubKey = pRRP->object;

    if( pPubKey->key_block->cryptographic_algorithm == KMIP_CRYPTOALG_RSA )
    {
        keyType = CKK_RSA;
        sTemplate[uCount].type = CKA_KEY_TYPE;
        sTemplate[uCount].pValue = &keyType;
        sTemplate[uCount].ulValueLen = sizeof(keyType);
        uCount++;

        *pnKeyAlg = JS_PKI_KEY_TYPE_RSA;
    }
    else if( pPubKey->key_block->cryptographic_algorithm == KMIP_CRYPTOALG_ECDSA )
    {
        keyType = CKK_ECDSA;
        sTemplate[uCount].type = CKA_KEY_TYPE;
        sTemplate[uCount].pValue = &keyType;
        sTemplate[uCount].ulValueLen = sizeof(keyType);
        uCount++;

        *pnKeyAlg = JS_PKI_KEY_TYPE_ECC;
    }
    else
    {
        ret = JS_KMS_ERROR_NOT_SUPPORT_PARAM;
        return ret;
    }

    sTemplate[uCount].type = CKA_ID;
    sTemplate[uCount].pValue = pID->pVal;
    sTemplate[uCount].ulValueLen = pID->nLen;
    uCount++;

    pKeyValue = pPubKey->key_block->key_value;

    if( pKeyValue == NULL )
    {
        ret = JS_KMS_ERROR_NO_PAYLOAD;
        return ret;
    }

    pMaterial = pKeyValue->key_material;

    JS_BIN_set( &binPub, pMaterial->value, pMaterial->size );


    TemplateAttribute *pta = pRRP->template_attribute;

    for( int i = 0; i < pta->attribute_count; i++ )
    {
        if( pta->attributes[i].type == KMIP_ATTR_CRYPTOGRAPHIC_USAGE_MASK )
        {

        }
        else if( pta->attributes[i].type == KMIP_ATTR_NAME )
        {
            Name *pname = pta->attributes[i].value;

            sTemplate[uCount].type = CKA_LABEL;
            sTemplate[uCount].pValue = pname->value->value;
            sTemplate[uCount].ulValueLen = pname->value->size;
            uCount++;
        }
        else if( pta->attributes[i].type == KMIP_ATTR_RECOMMENDED_CURVE )
        {
            enum recommended_curve *curve = pta->attributes[i].value;

            ret = JS_KMS_getECParam( *curve, &binECParam );
            if( ret != 0 )
            {
                ret = JS_KMS_ERROR_NOT_SUPPORT_PARAM;
                goto end;
            }

            sTemplate[uCount].type = CKA_EC_PARAMS;
            sTemplate[uCount].pValue = binECParam.pVal;
            sTemplate[uCount].ulValueLen = binECParam.nLen;
            uCount++;
        }
    }

    if( keyType == CKK_RSA )
    {
        ret = JS_PKI_getRSAPublicKeyVal( &binPub, &pHexE, &pHexN );
        if( ret != 0 )
        {
            ret = JS_KMS_ERROR_INVALID_VALUE;
            goto end;
        }

        JS_BIN_decodeHex( pHexE, &binE );
        JS_BIN_decodeHex( pHexN, &binN );

        sTemplate[uCount].type = CKA_MODULUS;
        sTemplate[uCount].pValue = binN.pVal;
        sTemplate[uCount].ulValueLen = binN.nLen;
        uCount++;

        sTemplate[uCount].type = CKA_PUBLIC_EXPONENT;
        sTemplate[uCount].pValue = binE.pVal;
        sTemplate[uCount].ulValueLen = binE.nLen;
        uCount++;
    }
    else if( keyType == CKK_ECDSA )
    {
        sTemplate[uCount].type = CKA_EC_POINT;
        sTemplate[uCount].pValue = binPub.pVal;
        sTemplate[uCount].ulValueLen = binPub.nLen;
        uCount++;
    }

    sTemplate[uCount].type = CKA_ENCRYPT;
    sTemplate[uCount].pValue = &bTrue;
    sTemplate[uCount].ulValueLen = sizeof(bTrue);
    uCount++;

    sTemplate[uCount].type = CKA_TOKEN;
    sTemplate[uCount].pValue = &bTrue;
    sTemplate[uCount].ulValueLen = sizeof(bTrue);
    uCount++;

    sTemplate[uCount].type = CKA_VERIFY;
    sTemplate[uCount].pValue = &bTrue;
    sTemplate[uCount].ulValueLen = sizeof(bTrue);
    uCount++;

    ret = JS_PKCS11_CreateObject( g_pP11CTX, sTemplate, uCount, &hObject );
    if( ret != 0 )
    {
        sprintf( g_pP11CTX->sLastLog, "%s:%d", JS_PKCS11_GetErrorMsg(ret), ret );
        ret = JS_KMS_ERROR_SYSTEM;
        goto end;
    }


end :
    if( pHexE ) JS_free( pHexE );
    if( pHexN ) JS_free( pHexN );
    JS_BIN_reset( &binPub );
    JS_BIN_reset( &binE );
    JS_BIN_reset( &binN );
    JS_BIN_reset( &binECParam );

    return ret;
}

static int registerSecretKey( const BIN *pID, const RegisterRequestPayload *pRRP, int *pnKeyAlg )
{
    int ret = 0;

    CK_ATTRIBUTE sTemplate[20];
    CK_ULONG    uCount = 0;
    CK_OBJECT_HANDLE    hObject = 0;
    CK_OBJECT_CLASS objClass = CKO_SECRET_KEY;
    CK_KEY_TYPE keyType = CKK_AES;
    CK_BBOOL bTrue = CK_TRUE;
    CK_BBOOL bFalse = CK_FALSE;
    SymmetricKey *pSymKey = NULL;
    KeyValue *pKeyValue = NULL;
    ByteString *pMaterial = NULL;
    int nLen = 0;


    if( pRRP == NULL )
        return JS_KMS_ERROR_NO_PAYLOAD;

    sTemplate[uCount].type = CKA_CLASS;
    sTemplate[uCount].pValue = &objClass;
    sTemplate[uCount].ulValueLen = sizeof(objClass);
    uCount++;

    pSymKey = pRRP->object;

    if( pSymKey->key_block->cryptographic_algorithm == KMIP_CRYPTOALG_AES )
    {
        keyType = CKK_AES;
        sTemplate[uCount].type = CKA_KEY_TYPE;
        sTemplate[uCount].pValue = &keyType;
        sTemplate[uCount].ulValueLen = sizeof(keyType);
        uCount++;

        *pnKeyAlg = JS_PKI_KEY_TYPE_AES;
    }
    else
    {
        ret = JS_KMS_ERROR_NOT_SUPPORT_PARAM;
        return ret;
    }
/*
    if( pSymKey->key_block->cryptographic_length > 0 )
    {
        nLen = pSymKey->key_block->cryptographic_length;
        nLen = nLen / 8;

        sTemplate[uCount].type = CKA_VALUE_LEN;
        sTemplate[uCount].pValue = &nLen;
        sTemplate[uCount].ulValueLen = sizeof(nLen);
        uCount++;
    }
*/
    pKeyValue = pSymKey->key_block->key_value;

    if( pKeyValue == NULL )
    {
        ret = JS_KMS_ERROR_NO_PAYLOAD;
        return ret;
    }

    pMaterial = pKeyValue->key_material;

    sTemplate[uCount].type = CKA_VALUE;
    sTemplate[uCount].pValue = pMaterial->value;
    sTemplate[uCount].ulValueLen  = pMaterial->size;
    uCount++;

    TemplateAttribute *pta = pRRP->template_attribute;

    for( int i = 0; i < pta->attribute_count; i++ )
    {
        if( pta->attributes[i].type == KMIP_ATTR_CRYPTOGRAPHIC_USAGE_MASK )
        {

        }
        else if( pta->attributes[i].type == KMIP_ATTR_NAME )
        {
            Name *pname = pta->attributes[i].value;
            TextString *pText = pname->value;

            sTemplate[uCount].type = CKA_LABEL;
            sTemplate[uCount].pValue = pText->value;
            sTemplate[uCount].ulValueLen = pText->size;
            uCount++;
        }
    }

    sTemplate[uCount].type = CKA_TOKEN;
    sTemplate[uCount].pValue = &bTrue;
    sTemplate[uCount].ulValueLen = sizeof(bTrue);
    uCount++;

    sTemplate[uCount].type = CKA_ENCRYPT;
    sTemplate[uCount].pValue = &bTrue;
    sTemplate[uCount].ulValueLen = sizeof(bTrue);
    uCount++;

    sTemplate[uCount].type = CKA_DECRYPT;
    sTemplate[uCount].pValue = &bTrue;
    sTemplate[uCount].ulValueLen = sizeof(bTrue);
    uCount++;

    sTemplate[uCount].type = CKA_PRIVATE;
    sTemplate[uCount].pValue = &bTrue;
    sTemplate[uCount].ulValueLen = sizeof(bTrue);
    uCount++;

    sTemplate[uCount].type = CKA_EXTRACTABLE;
    sTemplate[uCount].pValue = &bTrue;
    sTemplate[uCount].ulValueLen = sizeof(bTrue);
    uCount++;

    ret = JS_PKCS11_CreateObject( g_pP11CTX, sTemplate, uCount, &hObject );
    if( ret != CKR_OK )
    {
        sprintf( g_pP11CTX->sLastLog, "%s:%d", JS_PKCS11_GetErrorMsg(ret), ret );
        ret = JS_KMS_ERROR_SYSTEM;
        return ret;
    }

    return 0;
}

int runRegister( sqlite3 *db, const RegisterRequestPayload *pReqPayload, RegisterResponsePayload **ppRspPayload )
{
    int ret = 0;
    int nSeq = 0;
    char sSeq[16];
    int nType = 0;
    int nKeyAlg = 0;
    BIN binID = {0};

    JDB_KMS sKMS;
    char    sInfo[128];

    memset( sSeq, 0x00, sizeof(sSeq));
    memset( &sKMS, 0x00, sizeof(sKMS));

    nSeq = JS_DB_getSeq( db, "TB_KMS" );
    if( nSeq < 0 )
    {
        ret = JS_KMS_ERROR_SYSTEM;
        goto end;
    }

    nSeq++;
    sprintf( sSeq, "%d", nSeq );
    JS_BIN_set( &binID, sSeq, strlen(sSeq));

    if( pReqPayload->object_type == KMIP_OBJTYPE_CERTIFICATE )
    {
        nType = JS_KMS_OBJECT_TYPE_CERT;
        nKeyAlg = JS_PKI_KEY_TYPE_NONE;
        sprintf( sInfo, "%s", "Certificate" );

        ret = registerCert( &binID, pReqPayload );
    }
    else if( pReqPayload->object_type == KMIP_OBJTYPE_PRIVATE_KEY )
    {
        nType = JS_KMS_OBJECT_TYPE_PRIKEY;
        sprintf( sInfo, "%s", "PrivateKey" );
        ret = registerPriKey( &binID, pReqPayload, &nKeyAlg );
    }
    else if( pReqPayload->object_type == KMIP_OBJTYPE_PUBLIC_KEY )
    {
        nType = JS_KMS_OBJECT_TYPE_PUBKEY;
        sprintf( sInfo, "%s", "PublicKey" );
        ret = registerPubKey( &binID, pReqPayload, &nKeyAlg );
    }
    else if( pReqPayload->object_type == KMIP_OBJTYPE_SYMMETRIC_KEY )
    {
        nType = JS_KMS_OBJECT_TYPE_SECRET;
        sprintf( sInfo, "%s", "SecretKey" );
        ret = registerSecretKey( &binID, pReqPayload, &nKeyAlg );
    }
    else
    {
        ret = JS_KMS_ERROR_NOT_SUPPORT_PARAM;
        goto end;
    }

    if( ret != 0 ) goto end;

    RegisterResponsePayload *pRSP = (RegisterResponsePayload *)JS_calloc( 1, sizeof(RegisterResponsePayload));
    pRSP->unique_identifier = (TextString *)JS_malloc(sizeof(TextString));
    pRSP->unique_identifier->value = binID.pVal;
    pRSP->unique_identifier->size = binID.nLen;

    *ppRspPayload = pRSP;

    JS_DB_setKMS( &sKMS, nSeq, time(NULL), 0, nType, nKeyAlg, sSeq, sInfo );
    JS_DB_addKMS( db, &sKMS );

end :
    if( ret != JS_KMS_OK )
    {
        JS_BIN_reset( &binID );
    }

    JS_DB_resetKMS( &sKMS );
    return ret;
}

int runCreateKeyPair( sqlite3 *db, const CreateKeyPairRequestPayload *pReqPayload, CreateKeyPairResponsePayload **ppRspPayload )
{
    int ret = 0;

    int nLength = 2048;
    int nCurve = 0;
    int nPriSeq = 0;
    int nPubSeq = 0;
    int nKeyAlg = 0;

    char sPriSeq[16];
    char sPubSeq[16];

    CK_MECHANISM stMech;
    CK_ULONG uPubCount = 0;
    CK_ATTRIBUTE sPubTemplate[20];
    CK_ULONG uPriCount = 0;
    CK_ATTRIBUTE sPriTemplate[20];

    CK_OBJECT_CLASS pubClass = CKO_PUBLIC_KEY;
    CK_OBJECT_CLASS priClass = CKO_PRIVATE_KEY;

    CK_KEY_TYPE keyType;

    CK_BBOOL bTrue = CK_TRUE;
    CK_BBOOL bFalse = CK_FALSE;

    CK_ULONG uModulusBits = 0;

    CK_OBJECT_HANDLE uPubHandle = -1;
    CK_OBJECT_HANDLE uPriHandle = -1;

    BIN binExponent = {0};
    BIN binECParam = {0};

    const char *pLabel = "KMS KeyPair";
    const char *pSubject = "KMS Subject";

    JDB_KMS sPriKMS;
    JDB_KMS sPubKMS;

    time_t now_t = time(NULL);

    memset( &stMech, 0x00, sizeof(stMech));
    memset( sPriSeq, 0x00, sizeof(sPriSeq));
    memset( sPubSeq, 0x00, sizeof(sPubSeq));
    memset( &sPriKMS, 0x00, sizeof(sPriKMS));
    memset( &sPubKMS, 0x00, sizeof(sPubKMS));

    if( pReqPayload->common_template_attribute )
    {
        TemplateAttribute *tca = pReqPayload->common_template_attribute;

        for( int i = 0; i < tca->attribute_count; i++ )
        {
            if( tca->attributes[i].type == KMIP_ATTR_CRYPTOGRAPHIC_ALGORITHM )
            {
                enum cryptographic_algorithm *alg;
                alg = tca->attributes[i].value;

                if( *alg == KMIP_CRYPTOALG_EC || *alg == KMIP_CRYPTOALG_ECDSA )
                    keyType = CKK_ECDSA;
                else
                    keyType = CKK_RSA;
            }
            else if( tca->attributes[i].type == KMIP_ATTR_CRYPTOGRAPHIC_LENGTH )
            {
                int32 *length = tca->attributes[i].value;
                nLength = *length;
            }
            else if( tca->attributes[i].type == KMIP_ATTR_RECOMMENDED_CURVE )
            {
                enum recommended_curve *curve;
                curve = tca->attributes[i].value;
                nCurve = *curve;
            }
        }
    }

    if( pReqPayload->public_key_template_attribute )
    {
        TemplateAttribute *pua = pReqPayload->public_key_template_attribute;

        for( int i = 0; i < pua->attribute_count; i++ )
        {
            if( pua->attributes[i].type == KMIP_ATTR_CRYPTOGRAPHIC_USAGE_MASK )
            {

            }
        }
    }

    if( pReqPayload->private_key_template_attribute )
    {
        TemplateAttribute *pra = pReqPayload->private_key_template_attribute;

        for( int i = 0; i < pra->attribute_count; i++ )
        {
            if( pra->attributes[i].type == KMIP_ATTR_CRYPTOGRAPHIC_USAGE_MASK )
            {

            }
        }
    }

    nPriSeq = JS_DB_getSeq( db, "TB_KMS" );
    nPriSeq++;
    nPubSeq = nPriSeq + 1;
    sprintf( sPriSeq, "%d", nPriSeq );
    sprintf( sPubSeq, "%d", nPubSeq );

    if( keyType == CKK_RSA )
    {
        stMech.mechanism = CKM_RSA_PKCS_KEY_PAIR_GEN;
        uModulusBits = nLength;
        JS_BIN_decodeHex( "010001", &binExponent );
        nKeyAlg = JS_PKI_KEY_TYPE_RSA;
    }
    else if( keyType == CKK_ECDSA )
    {
        stMech.mechanism = CKM_ECDSA_KEY_PAIR_GEN;
        nKeyAlg = JS_PKI_KEY_TYPE_ECC;
    }

    sPubTemplate[uPubCount].type = CKA_CLASS;
    sPubTemplate[uPubCount].pValue = &pubClass;
    sPubTemplate[uPubCount].ulValueLen = sizeof(pubClass);
    uPubCount++;

    sPubTemplate[uPubCount].type = CKA_KEY_TYPE;
    sPubTemplate[uPubCount].pValue = &keyType;
    sPubTemplate[uPubCount].ulValueLen = sizeof(keyType);
    uPubCount++;

    if( keyType == CKK_RSA )
    {
        sPubTemplate[uPubCount].type = CKA_MODULUS_BITS;
        sPubTemplate[uPubCount].pValue = &uModulusBits;
        sPubTemplate[uPubCount].ulValueLen = sizeof(uModulusBits);
        uPubCount++;

        sPubTemplate[uPubCount].type = CKA_PUBLIC_EXPONENT;
        sPubTemplate[uPubCount].pValue = binExponent.pVal;
        sPubTemplate[uPubCount].ulValueLen = binExponent.nLen;
        uPubCount++;
    }
    else if( keyType == CKK_ECDSA )
    {   
        ret = JS_KMS_getECParam( nCurve, &binECParam );
        if( ret != 0 )
        {
            ret = JS_KMS_ERROR_NOT_SUPPORT_PARAM;
            goto end;
        }

        sPubTemplate[uPubCount].type = CKA_EC_PARAMS;
        sPubTemplate[uPubCount].pValue = binECParam.pVal;
        sPubTemplate[uPubCount].ulValueLen = binECParam.nLen;
        uPubCount++;
    }

    sPubTemplate[uPubCount].type = CKA_LABEL;
    sPubTemplate[uPubCount].pValue = pLabel;
    sPubTemplate[uPubCount].ulValueLen = strlen( pLabel );
    uPubCount++;

    sPubTemplate[uPubCount].type = CKA_ID;
    sPubTemplate[uPubCount].pValue = sPubSeq;
    sPubTemplate[uPubCount].ulValueLen = strlen( sPubSeq );
    uPubCount++;

    sPubTemplate[uPubCount].type = CKA_TOKEN;
    sPubTemplate[uPubCount].pValue = &bTrue;
    sPubTemplate[uPubCount].ulValueLen = sizeof(bTrue);
    uPubCount++;

    sPubTemplate[uPubCount].type = CKA_ENCRYPT;
    sPubTemplate[uPubCount].pValue = &bTrue;
    sPubTemplate[uPubCount].ulValueLen = sizeof(bTrue);
    uPubCount++;

    sPubTemplate[uPubCount].type = CKA_VERIFY;
    sPubTemplate[uPubCount].pValue = &bTrue;
    sPubTemplate[uPubCount].ulValueLen = sizeof(bTrue);
    uPubCount++;

    // Private Template
    sPriTemplate[uPriCount].type = CKA_CLASS;
    sPriTemplate[uPriCount].pValue = &priClass;
    sPriTemplate[uPriCount].ulValueLen = sizeof(priClass);
    uPriCount++;

    sPriTemplate[uPriCount].type = CKA_KEY_TYPE;
    sPriTemplate[uPriCount].pValue = &keyType;
    sPriTemplate[uPriCount].ulValueLen = sizeof(keyType);
    uPriCount++;

    sPriTemplate[uPriCount].type = CKA_LABEL;
    sPriTemplate[uPriCount].pValue = pLabel;
    sPriTemplate[uPriCount].ulValueLen = strlen(pLabel);
    uPriCount++;

    sPriTemplate[uPriCount].type = CKA_SUBJECT;
    sPriTemplate[uPriCount].pValue = pSubject;
    sPriTemplate[uPriCount].ulValueLen = strlen( pSubject );
    uPriCount++;

    sPriTemplate[uPriCount].type = CKA_ID;
    sPriTemplate[uPriCount].pValue = sPriSeq;
    sPriTemplate[uPriCount].ulValueLen = strlen( sPriSeq );
    uPriCount++;

    sPriTemplate[uPriCount].type = CKA_PRIVATE;
    sPriTemplate[uPriCount].pValue = &bTrue;
    sPriTemplate[uPriCount].ulValueLen = sizeof(bTrue);
    uPriCount++;

    sPriTemplate[uPriCount].type = CKA_TOKEN;
    sPriTemplate[uPriCount].pValue = &bTrue;
    sPriTemplate[uPriCount].ulValueLen = sizeof(bTrue);
    uPriCount++;

    sPriTemplate[uPriCount].type = CKA_DECRYPT;
    sPriTemplate[uPriCount].pValue = &bTrue;
    sPriTemplate[uPriCount].ulValueLen = sizeof(bTrue);
    uPriCount++;

    sPriTemplate[uPriCount].type = CKA_SIGN;
    sPriTemplate[uPriCount].pValue = &bTrue;
    sPriTemplate[uPriCount].ulValueLen = sizeof(bTrue);
    uPriCount++;

    ret = JS_PKCS11_GenerateKeyPair( g_pP11CTX, &stMech, sPubTemplate, uPubCount, sPriTemplate, uPriCount, &uPubHandle, &uPriHandle );
    if( ret != CKR_OK )
    {
        ret = JS_KMS_ERROR_SYSTEM;
        goto end;
    }

    CreateKeyPairResponsePayload *csp = (CreateKeyPairResponsePayload *)JS_calloc(1, sizeof(CreateKeyPairResponsePayload));
    csp->public_key_unique_identifier = (TextString *)JS_malloc( sizeof(TextString) );
    csp->public_key_unique_identifier->size = strlen( sPubSeq );
    csp->public_key_unique_identifier->value = JS_strdup( sPubSeq );

    csp->private_key_unique_identifier = (TextString *)JS_malloc( sizeof(TextString) );
    csp->private_key_unique_identifier->size = strlen( sPriSeq );
    csp->private_key_unique_identifier->value = JS_strdup( sPriSeq );

    *ppRspPayload = csp;

    JS_DB_setKMS( &sPriKMS, nPriSeq, now_t, 0, JS_KMS_OBJECT_TYPE_PRIKEY, nKeyAlg, sPriSeq, "PrivateKey" );
    JS_DB_setKMS( &sPubKMS, nPubSeq, now_t, 0, JS_KMS_OBJECT_TYPE_PUBKEY, nKeyAlg, sPubSeq, "PublicKey" );

    JS_DB_addKMS( db, &sPriKMS );
    JS_DB_addKMS( db, &sPubKMS );

end :

    JS_BIN_reset( &binECParam );
    JS_BIN_reset( &binExponent );
    JS_DB_resetKMS( &sPriKMS );
    JS_DB_resetKMS( &sPubKMS );

    return ret;
}


int procBatchItem( sqlite3 *db, const RequestBatchItem *pReqItem, ResponseBatchItem *pRspItem )
{
    int ret = 0;

    pRspItem->operation = pReqItem->operation;

    if( pReqItem->operation == KMIP_OP_GET )
    {
        ret = runGet( db, pReqItem->request_payload, &pRspItem->response_payload );
    }
    else if( pReqItem->operation == KMIP_OP_CREATE )
    {
        ret = runCreate( db, pReqItem->request_payload, &pRspItem->response_payload );
    }
    else if( pReqItem->operation == KMIP_OP_DESTROY )
    {
        ret = runDestroy( db, pReqItem->request_payload, &pRspItem->response_payload );
    }
    else if( pReqItem->operation == KMIP_OP_ACTIVATE )
    {
        ret = runActivate( db, pReqItem->request_payload, &pRspItem->response_payload );
    }
    else if( pReqItem->operation == KMIP_OP_SIGN )
    {
        ret = runSign( db, pReqItem->request_payload, &pRspItem->response_payload );
    }
    else if( pReqItem->operation == KMIP_OP_DECRYPT )
    {
        ret = runDecrypt( db, pReqItem->request_payload, &pRspItem->response_payload );
    }
    else if( pReqItem->operation == KMIP_OP_ENCRYPT )
    {
        ret = runEncrypt( db, pReqItem->request_payload, &pRspItem->response_payload );
    }
    else if( pReqItem->operation == KMIP_OP_REGISTER )
    {
        ret = runRegister( db, pReqItem->request_payload, &pRspItem->response_payload );
    }
    else if( pReqItem->operation == KMIP_OP_CREATE_KEY_PAIR )
    {
        ret = runCreateKeyPair( db, pReqItem->request_payload, &pRspItem->response_payload );
    }
    else if( pReqItem->operation == KMIP_OP_SIGNATURE_VERIFY )
    {
        ret = runVerify( db, pReqItem->request_payload, &pRspItem->response_payload );
    }
    else if( pReqItem->operation == KMIP_OP_GET_ATTRIBUTE_LIST )
    {
        ret = runGetAttributeList( db, pReqItem->request_payload, &pRspItem->response_payload );
    }
    else if( pReqItem->operation == KMIP_OP_HASH )
    {
        ret = runHash( db, pReqItem->request_payload, &pRspItem->response_payload );
    }
    else if( pReqItem->operation == KMIP_OP_RNG_RETRIEVE )
    {
        ret = runRNGRetrieve( db, pReqItem->request_payload, &pRspItem->response_payload );
    }
    else if( pReqItem->operation == KMIP_OP_RNG_SEED )
    {
        ret = runRNGSeed( db, pReqItem->request_payload, &pRspItem->response_payload );
    }
    else
    {
        fprintf( stderr, "not support operation(%d)\n", pReqItem->operation );
        return -1;
    }

    if( ret == JS_KMS_OK )
    {
        pRspItem->result_status = KMIP_STATUS_SUCCESS;
    }
    else
    {
        _setErrorResponse( ret, pRspItem );
    }

    return ret;
}

int isAuthentication( const Authentication *pAuth )
{
    Credential *credential = pAuth->credential;

    if( credential == NULL ) return 0;

    if( credential->credential_type == KMIP_CRED_USERNAME_AND_PASSWORD )
    {
        UsernamePasswordCredential *pUPC = credential->credential_value;

        char *pUserName = (char *)JS_calloc(1, pUPC->username->size + 1 );
        memcpy( pUserName, pUPC->username->value, pUPC->username->size );

        char *pPasswd = (char *)JS_calloc(1, pUPC->password->size + 1 );
        memcpy( pPasswd, pUPC->password->value, pUPC->password->size );

        printf( "UserName:%s Passwd:%s\n", pUserName, pPasswd );

        if( pUserName ) JS_free( pUserName );
        if( pPasswd ) JS_free( pPasswd );
    }
    else
    {
        return 0;
    }


    return 1;
}

int procKMS( sqlite3 *db, const BIN *pReq, BIN *pRsp )
{
    int ret = 0;
    KMIP ctx = {0};
    RequestMessage  reqm = {0};
    ResponseMessage rspm = {0};
    ResponseBatchItem rspBatch = {0};
    Authentication *pAuth = NULL;
    kmip_init(&ctx, NULL, 0, KMIP_1_2);
    memset( &reqm, 0x00, sizeof(reqm));


    kmip_set_buffer( &ctx, pReq->pVal, pReq->nLen );
    kmip_decode_request_message( &ctx, &reqm );

    pAuth = reqm.request_header->authentication;

    if( pAuth )
    {
        ret = isAuthentication( pAuth );
        if( ret != 1 )
        {
            fprintf( stderr, "fail authentication\n" );
            goto end;
        }
    }
    else
    {
        fprintf( stderr, "need to authorization\n" );
        goto end;
    }

    kmip_print_request_message( &reqm );

    for( int i = 0; i < reqm.batch_count; i++ )
    {
        ret = procBatchItem( db, reqm.batch_items, &rspBatch );
    }

//    kmip_set_buffer( &ctx, NULL, 0 );
    kmip_reset( &ctx );
    size_t buffer_blocks = 1;
    size_t buffer_block_size = 1024 * 2;
    size_t buffer_total_size = buffer_blocks * buffer_block_size;

    uint8 * encoding = ctx.calloc_func( ctx.state, buffer_blocks, buffer_block_size);
    if( encoding == NULL )
    {
        ret = -1;
        goto end;
    }

    kmip_set_buffer( &ctx, encoding, buffer_total_size );

    ResponseHeader  rsph = {0};
    ProtocolVersion pv = {0};

    rsph.time_stamp = time(NULL);
    kmip_init_protocol_version( &pv, KMIP_1_0 );

    rspm.response_header = &rsph;
    rsph.protocol_version = &pv;
    rsph.batch_count = 1;

    rspm.batch_count = 1;
    rspm.batch_items = &rspBatch;


    ret = kmip_encode_response_message( &ctx, &rspm );
    if( ret != 0 )
    {
        fprintf( stderr, "fail to encode response(%d)\n", ret );
        goto end;
    }

    kmip_print_response_message( &rspm );

//    JS_BIN_set( pRsp, ctx.buffer, ctx.size );
    JS_BIN_set( pRsp, ctx.buffer, ctx.index - ctx.buffer );
    JS_BIN_print( stdout, "KMIP_RESPONSE", pRsp );

end :
    kmip_free_request_message( &ctx, &reqm );
//    kmip_free_response_message( &ctx, &rspm );
    kmip_free_response_batch_item( &ctx, &rspBatch );

    kmip_destroy( &ctx );
    return ret;
}


