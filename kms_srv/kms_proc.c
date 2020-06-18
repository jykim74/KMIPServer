#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "kmip.h"
#include "js_bin.h"
#include "js_pkcs11.h"
#include "kms_define.h"
#include "js_db.h"

extern JP11_CTX    *g_pP11CTX;
extern CK_SESSION_HANDLE    g_hSession;

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

    ret = JS_PKCS11_FindObjectsInit( g_pP11CTX, g_hSession, sTemplate, uCount );
    if( ret != CKR_OK )
    {
        fprintf( stderr, "fail to run findObjectsInit(%s:%d)\n", JS_PKCS11_GetErrorMsg(ret), ret );
        return -1;
    }

    ret = JS_PKCS11_FindObjects( g_pP11CTX, g_hSession, pObjects, uMaxObjCnt, &uObjCnt );
    if( ret != CKR_OK )
    {
        fprintf( stderr, "fail to run findObjects(%s:%d)\n", JS_PKCS11_GetErrorMsg(ret), ret );
        return -1;
    }

    ret = JS_PKCS11_FindObjectsFinal( g_pP11CTX, g_hSession );
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

    ret = JS_PKCS11_GetAtrributeValue2( g_pP11CTX, g_hSession, hObject, nType, pVal );

    return ret;
}

int runGet( sqlite3 *db, const RequestBatchItem *pReqItem, ResponseBatchItem *pRspItem )
{
    int ret = 0;
    BIN binID = {0,0};
    BIN binVal = {0,0};
    CK_OBJECT_HANDLE    sObjects[20];


    GetRequestPayload *grp = (GetRequestPayload *)pReqItem->request_payload;

    JS_BIN_set( &binID, grp->unique_identifier->value, grp->unique_identifier->size );

    ret = findObjects( CKO_SECRET_KEY, &binID, sObjects );

    pRspItem->operation = pReqItem->operation;

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

    GetResponsePayload *gsp = (GetResponsePayload *)JS_calloc( 1, sizeof(GetResponsePayload));
    gsp->object_type = KMIP_OBJTYPE_SYMMETRIC_KEY;

    gsp->unique_identifier = (TextString *)JS_malloc( sizeof(TextString));
    gsp->unique_identifier->size = binID.nLen;
    gsp->unique_identifier->value = (unsigned char *)JS_calloc( 1, binID.nLen );
    memcpy( gsp->unique_identifier->value, binID.pVal, binID.nLen );

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

        gsp->object = symmetric_key;
    }

    pRspItem->response_payload = gsp;
    ret = JS_KMS_OK;

end :
    if( ret == JS_KMS_OK )
    {
        pRspItem->result_status = KMIP_STATUS_SUCCESS;
    }
    else
    {
        const char *pError = getErrorMsg( ret );
        pRspItem->result_status = KMIP_STATUS_OPERATION_FAILED;
        pRspItem->result_reason = KMIP_REASON_GENERAL_FAILURE;
        pRspItem->result_message = JS_strdup( pError );
        pRspItem->result_message->size = strlen( pError );

        JS_BIN_reset( &binVal );
    }

    JS_BIN_reset( &binID );
    return ret;
}

int runCreate( sqlite3 *db, const RequestBatchItem *pReqItem, ResponseBatchItem *pRspItem)
{
    int ret = 0;
    CreateRequestPayload *crp = (CreateRequestPayload *)pReqItem->request_payload;

    CK_ATTRIBUTE        sTemplate[20];
    CK_ULONG            uCount = 0;
    CK_OBJECT_HANDLE hObject = 0;
    CK_MECHANISM    sMech;

    int             *pnAlg = NULL;
    int             *pnLen = NULL;
    int             *pnMask = NULL;
    long             uLen = 0;

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

    printf( "Seq : %d\n", nSeq );
    JS_DB_setKMS( &sKMS, nSeq, 0, 0, "SymKey" );
    sprintf( sID, "%d", nSeq );

    if( crp->object_type == KMIP_OBJTYPE_SYMMETRIC_KEY )
    {
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

        TemplateAttribute *ta = crp->template_attribute;
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

        ret = JS_PKCS11_GenerateKey( g_pP11CTX, g_hSession, &sMech, sTemplate, uCount, &hObject );
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
    pRspItem->operation = pReqItem->operation;


    if( ret == 0 )
    {
        pld->unique_identifier = (TextString *)JS_malloc(sizeof(TextString));
        pld->unique_identifier->size = strlen( sID );
        pld->unique_identifier->value = JS_strdup( sID );
        pRspItem->response_payload = pld;
    }

    JS_DB_addKMS( db, &sKMS );
    ret = JS_KMS_OK;

end :
    if( ret == JS_KMS_OK )
    {
        pRspItem->result_status = KMIP_STATUS_SUCCESS;
    }
    else
    {
        const char *pError = getErrorMsg( ret );
        pRspItem->result_status = KMIP_STATUS_OPERATION_FAILED;
        pRspItem->result_reason = KMIP_REASON_GENERAL_FAILURE;
        pRspItem->result_message = JS_strdup( pError );
        pRspItem->result_message->size = strlen( pError );
    }

    JS_DB_resetKMS( &sKMS );
    return 0;
}

int runDestroy( sqlite3 *db, const RequestBatchItem *pReqItem, ResponseBatchItem *pRspItem)
{
    int ret = 0;
    BIN binID = {0,0};
    CK_OBJECT_HANDLE    sObjects[20];
    char sSeq[16];

    memset( sSeq, 0x00, sizeof(sSeq));

    DestroyRequestPayload *drp = (DestroyRequestPayload *)pReqItem->request_payload;


    JS_BIN_set( &binID, drp->unique_identifier->value, drp->unique_identifier->size );
    memcpy( sSeq, drp->unique_identifier->value, drp->unique_identifier->size );

    ret = findObjects( CKO_SECRET_KEY, &binID, sObjects );

    pRspItem->operation = pReqItem->operation;

    if( ret <= 0 )
    {
        fprintf(stderr, "fail to find objects(%d)\n", ret );
        ret = JS_KMS_ERROR_NO_OBJECT;

        goto end;
    }

    ret = JS_PKCS11_DestroyObject( g_pP11CTX, g_hSession, sObjects[0] );
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
    pRspItem->response_payload = dsp;

    ret = JS_KMS_OK;
    JS_DB_delKMS( db, atoi(sSeq));

end :
    if( ret == JS_KMS_OK )
    {
        pRspItem->result_status = KMIP_STATUS_SUCCESS;
    }
    else
    {
        const char *pError = getErrorMsg( ret );
        pRspItem->result_status = KMIP_STATUS_OPERATION_FAILED;
        pRspItem->result_reason = KMIP_REASON_GENERAL_FAILURE;
        pRspItem->result_message = JS_strdup( pError );
        pRspItem->result_message->size = strlen( pError );
    }

    JS_BIN_reset( &binID );
    return ret;
}

int runActivate( sqlite3 *db, const RequestBatchItem *pReqItem, ResponseBatchItem *pRspItem)
{
    int ret = 0;
    BIN binID = {0,0};
    CK_OBJECT_HANDLE    sObjects[20];
    char sSeq[16];
    JDB_KMS sKMS;

    memset( sSeq, 0x00, sizeof(sSeq));
    memset( &sKMS, 0x00, sizeof(sKMS));

    ActivateRequestPayload *arp = (ActivateRequestPayload *)pReqItem->request_payload;


    JS_BIN_set( &binID, arp->unique_identifier->value, arp->unique_identifier->size );
    memcpy( sSeq, arp->unique_identifier->value, arp->unique_identifier->size );

    pRspItem->operation = pReqItem->operation;

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
    pRspItem->response_payload = asp;

    ret = JS_KMS_OK;
    JS_DB_delKMS( db, atoi(sSeq));

end :
    if( ret == JS_KMS_OK )
    {
        pRspItem->result_status = KMIP_STATUS_SUCCESS;
    }
    else
    {
        const char *pError = getErrorMsg( ret );
        pRspItem->result_status = KMIP_STATUS_OPERATION_FAILED;
        pRspItem->result_reason = KMIP_REASON_GENERAL_FAILURE;
        pRspItem->result_message = JS_strdup( pError );
        pRspItem->result_message->size = strlen( pError );
    }

    JS_BIN_reset( &binID );
    JS_DB_resetKMS( &sKMS );

    return ret;
}

int runEncrypt( sqlite3 *db, const RequestBatchItem *pReqItem, ResponseBatchItem *pRspItem)
{
    int ret = 0;
    BIN binIV = {0};
    BIN binPlain = {0};
    BIN binID = {0};
    CK_OBJECT_HANDLE    sObjects[20];
    CK_MECHANISM stMech = {0};
    unsigned char *pEncData = NULL;
    long uEncDataLen = 0;

    EncryptRequestPayload *pERP = (EncryptRequestPayload *)pReqItem->request_payload;
    if( pERP == NULL )
    {
        ret = JS_KMS_ERROR_NO_PAYLOAD;
        goto end;
    }

    JS_BIN_set( &binID, pERP->unique_identifier->value, pERP->unique_identifier->size );
    ret = findObjects( CKO_SECRET_KEY, &binID, sObjects );
    if( ret < 1 )
    {
        ret = JS_KMS_ERROR_NO_OBJECT;
        goto end;
    }

    if( pERP->cryptographic_parameters->block_cipher_mode == KMIP_BLOCK_CBC &&
            pERP->cryptographic_parameters->padding_method == KMIP_PAD_PKCS5 &&
            pERP->cryptographic_parameters->cryptographic_algorithm == KMIP_CRYPTOALG_AES )
    {
        stMech.mechanism = CKM_AES_CBC_PAD;
    }
    else
    {
        fprintf( stderr, "need to work\n" );
        ret = JS_KMS_ERROR_NOT_SUPPORT_PARAM;
        goto end;
    }

    JS_BIN_set( &binPlain, pERP->data->value, pERP->data->size );
    JS_BIN_set( &binID, pERP->iv_counter_nonce->value, pERP->iv_counter_nonce->size );

    stMech.pParameter = binIV.pVal;
    stMech.ulParameterLen = binIV.nLen;

    ret = JS_PKCS11_EncryptInit( g_pP11CTX, g_hSession, &stMech, sObjects[0] );
    if( ret != 0 )
    {
        ret = JS_KMS_ERROR_SYSTEM;
        goto end;
    }

    pEncData = (unsigned char *)JS_malloc( binPlain.nLen + 64 );

    ret = JS_PKCS11_Encrypt( g_pP11CTX, g_hSession, binPlain.pVal, binPlain.nLen, pEncData, &uEncDataLen );
    if( ret != 0 )
    {
        ret = JS_KMS_ERROR_SYSTEM;
        goto end;
    }

    EncryptResponsePayload *pESP = (EncryptResponsePayload *)JS_calloc( 1, sizeof(EncryptResponsePayload));
    pESP->data->value = pEncData;
    pESP->data->size = uEncDataLen;

    pESP->unique_identifier->value = binID.pVal;
    pESP->unique_identifier->size = binID.nLen;

    pRspItem->response_payload = pESP;

end :
    if( ret == JS_KMS_OK )
    {
        pRspItem->result_status = KMIP_STATUS_SUCCESS;
    }
    else
    {
        const char *pError = getErrorMsg( ret );
        pRspItem->result_status = KMIP_STATUS_OPERATION_FAILED;
        pRspItem->result_reason = KMIP_REASON_GENERAL_FAILURE;
        pRspItem->result_message = JS_strdup( pError );
        pRspItem->result_message->size = strlen( pError );

        if( pEncData ) JS_free( pEncData );
        JS_BIN_reset( &binID );
    }

    JS_BIN_reset( &binIV );
    JS_BIN_reset( &binPlain );

    return ret;
}

int runDecrypt( sqlite3 *db, const RequestBatchItem *pReqItem, ResponseBatchItem *pRspItem)
{
    int ret = 0;
    BIN binIV = {0};
    BIN binEncrypt = {0};
    BIN binID = {0};
    CK_OBJECT_HANDLE    sObjects[20];
    CK_MECHANISM stMech = {0};
    unsigned char *pDecData = NULL;
    long uDecDataLen = 0;

    DecryptRequestPayload *pDRP = (DecryptRequestPayload *)pReqItem->request_payload;
    if( pDRP == NULL )
    {
        ret = JS_KMS_ERROR_NO_PAYLOAD;
        goto end;
    }

    JS_BIN_set( &binID, pDRP->unique_identifier->value, pDRP->unique_identifier->size );
    ret = findObjects( CKO_SECRET_KEY, &binID, sObjects );
    if( ret < 1 )
    {
        ret = JS_KMS_ERROR_NO_OBJECT;
        goto end;
    }

    if( pDRP->cryptographic_parameters->block_cipher_mode == KMIP_BLOCK_CBC &&
            pDRP->cryptographic_parameters->padding_method == KMIP_PAD_PKCS5 &&
            pDRP->cryptographic_parameters->cryptographic_algorithm == KMIP_CRYPTOALG_AES )
    {
        stMech.mechanism = CKM_AES_CBC_PAD;
    }
    else
    {
        fprintf( stderr, "need to work\n" );
        ret = JS_KMS_ERROR_NOT_SUPPORT_PARAM;
        goto end;
    }

    JS_BIN_set( &binEncrypt, pDRP->data->value, pDRP->data->size );
    JS_BIN_set( &binID, pDRP->iv_counter_nonce->value, pDRP->iv_counter_nonce->size );

    stMech.pParameter = binIV.pVal;
    stMech.ulParameterLen = binIV.nLen;

    ret = JS_PKCS11_DecryptInit( g_pP11CTX, g_hSession, &stMech, sObjects[0] );
    if( ret != 0 )
    {
        ret = JS_KMS_ERROR_SYSTEM;
        goto end;
    }

    pDecData = (unsigned char *)JS_malloc( binEncrypt.nLen + 64 );

    ret = JS_PKCS11_Decrypt( g_pP11CTX, g_hSession, binEncrypt.pVal, binEncrypt.nLen, pDecData, &uDecDataLen );
    if( ret != 0 )
    {
        ret = JS_KMS_ERROR_SYSTEM;
        goto end;
    }

    DecryptResponsePayload *pDSP = (DecryptResponsePayload *)JS_calloc( 1, sizeof(DecryptResponsePayload));
    pDSP->data->value = pDecData;
    pDSP->data->size = uDecDataLen;

    pDSP->unique_identifier->value = binID.pVal;
    pDSP->unique_identifier->size = binID.nLen;

    pRspItem->response_payload = pDSP;

end :
    if( ret == JS_KMS_OK )
    {
        pRspItem->result_status = KMIP_STATUS_SUCCESS;
    }
    else
    {
        const char *pError = getErrorMsg( ret );
        pRspItem->result_status = KMIP_STATUS_OPERATION_FAILED;
        pRspItem->result_reason = KMIP_REASON_GENERAL_FAILURE;
        pRspItem->result_message = JS_strdup( pError );
        pRspItem->result_message->size = strlen( pError );

        if( pDecData ) JS_free( pDecData );
        JS_BIN_reset( &binID );
    }

    JS_BIN_reset( &binIV );
    JS_BIN_reset( &binEncrypt );

    return ret;
}

int runSign( sqlite3 *db, const RequestBatchItem *pReqItem, ResponseBatchItem *pRspItem)
{
    int ret = 0;
    BIN binID = {0};
    BIN binSign = {0};
    BIN binData = {0};
    CK_OBJECT_HANDLE    sObjects[20];

    CK_MECHANISM stMech = {0};
    unsigned char sSign[1024];
    long uSignLen = 0;

    SignRequestPayload *pSRP = (SignRequestPayload *)pReqItem->request_payload;

    pRspItem->operation = pReqItem->operation;

    JS_BIN_set( &binID, pSRP->unique_identifier->value, pSRP->unique_identifier->size );
    ret = findObjects( CKO_PRIVATE_KEY, &binID, sObjects );
    if( ret < 1 )
    {
        ret = JS_KMS_ERROR_NO_OBJECT;
        goto end;
    }


    if( pSRP->cryptographic_parameters->hashing_algorithm == KMIP_HASH_SHA256 &&
            pSRP->cryptographic_parameters->padding_method == KMIP_PAD_PKCS5 &&
            pSRP->cryptographic_parameters->cryptographic_algorithm == KMIP_CRYPTOALG_RSA )
    {
        stMech.mechanism = CKM_SHA256_RSA_PKCS;
    }
    else
    {
        fprintf( stderr, "need to work\n" );
        ret = JS_KMS_ERROR_NOT_SUPPORT_PARAM;
        goto end;
    }

    JS_BIN_set( &binData, pSRP->data->value, pSRP->data->size );

    ret = JS_PKCS11_SignInit( g_pP11CTX, g_hSession, &stMech, sObjects[0] );
    if( ret != CKR_OK )
    {
        ret = JS_KMS_ERROR_SYSTEM;
        goto end;
    }

    ret = JS_PKCS11_Sign( g_pP11CTX, g_hSession, binData.pVal, binData.nLen, sSign, &uSignLen );
    if( ret != CKR_OK )
    {
        ret = JS_KMS_ERROR_SYSTEM;
        goto end;
    }

    SignResponsePayload *pSSP = (SignResponsePayload *)JS_calloc( 1, sizeof(SignResponsePayload));

    pSSP->signature_data->value = JS_malloc( uSignLen );
    memcpy( pSSP->signature_data->value, sSign, uSignLen );
    pSSP->signature_data->size = uSignLen;

    pSSP->unique_identifier->value = binID.pVal;
    pSSP->unique_identifier->size = binID.nLen;

    pRspItem->response_payload = pSSP;

end :
    if( ret == JS_KMS_OK )
    {
        pRspItem->result_status = KMIP_STATUS_SUCCESS;
    }
    else
    {
        const char *pError = getErrorMsg( ret );
        pRspItem->result_status = KMIP_STATUS_OPERATION_FAILED;
        pRspItem->result_reason = KMIP_REASON_GENERAL_FAILURE;
        pRspItem->result_message = JS_strdup( pError );
        pRspItem->result_message->size = strlen( pError );

        JS_BIN_reset( &binID );
    }

    return ret;
}

int runVerify( sqlite3 *db, const RequestBatchItem *pReqItem, ResponseBatchItem *pRspItem)
{
    int ret = 0;
    BIN binID = {0};
    BIN binSign = {0};
    BIN binData = {0};
    CK_OBJECT_HANDLE    sObjects[20];

    CK_MECHANISM stMech = {0};

    SignatureVerifyRequestPayload *pVRP = (SignatureVerifyRequestPayload *)pReqItem->request_payload;

    pRspItem->operation = pReqItem->operation;

    JS_BIN_set( &binID, pVRP->unique_identifier->value, pVRP->unique_identifier->size );
    ret = findObjects( CKO_PRIVATE_KEY, &binID, sObjects );
    if( ret < 1 )
    {
        ret = JS_KMS_ERROR_NO_OBJECT;
        goto end;
    }


    if( pVRP->cryptographic_parameters->hashing_algorithm == KMIP_HASH_SHA256 &&
            pVRP->cryptographic_parameters->padding_method == KMIP_PAD_PKCS5 &&
            pVRP->cryptographic_parameters->cryptographic_algorithm == KMIP_CRYPTOALG_RSA )
    {
        stMech.mechanism = CKM_SHA256_RSA_PKCS;
    }
    else
    {
        fprintf( stderr, "need to work\n" );
        ret = JS_KMS_ERROR_NOT_SUPPORT_PARAM;
        goto end;
    }

    JS_BIN_set( &binData, pVRP->data->value, pVRP->data->size );
    JS_BIN_set( &binSign, pVRP->signature_data->value, pVRP->signature_data->size );

    ret = JS_PKCS11_VerifyInit( g_pP11CTX, g_hSession, &stMech, sObjects[0] );
    if( ret != CKR_OK )
    {
        ret = JS_KMS_ERROR_SYSTEM;
        goto end;
    }

    ret = JS_PKCS11_Verify( g_pP11CTX, g_hSession, binData.pVal, binData.nLen, binSign.pVal, binSign.nLen );
    if( ret != CKR_OK )
    {
        ret = JS_KMS_ERROR_SYSTEM;
        goto end;
    }

    SignatureVerifyResponsePayload *pVSP = (SignatureVerifyResponsePayload *)JS_calloc( 1, sizeof(SignatureVerifyResponsePayload));

    pVSP->validity_indicator = KMIP_VALIDITY_VALID;

    pVSP->unique_identifier->value = binID.pVal;
    pVSP->unique_identifier->size = binID.nLen;

    pRspItem->response_payload = pVSP;

end :
    if( ret == JS_KMS_OK )
    {
        pRspItem->result_status = KMIP_STATUS_SUCCESS;
    }
    else
    {
        const char *pError = getErrorMsg( ret );
        pRspItem->result_status = KMIP_STATUS_OPERATION_FAILED;
        pRspItem->result_reason = KMIP_REASON_GENERAL_FAILURE;
        pRspItem->result_message = JS_strdup( pError );
        pRspItem->result_message->size = strlen( pError );

        JS_BIN_reset( &binID );
    }

    return ret;
}

int runRegister( sqlite3 *db, const RequestBatchItem *pReqItem, ResponseBatchItem *pRspItem)
{
    int ret = 0;
    RegisterRequestPayload *pRRP = (RegisterRequestPayload *)pReqItem->request_payload;

    pRspItem->operation = pReqItem->operation;

    return 0;
}

int runGenKeyPair( sqlite3 *db, const RequestBatchItem *pReqItem, ResponseBatchItem *pRspItem)
{
    int ret = 0;

    int nLength = 2048;
    int nPriSeq = 0;
    int nPubSeq = 0;

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

    CreateKeyPairRequestPayload *crp = (CreateKeyPairRequestPayload *)pReqItem->request_payload;

    pRspItem->operation = pReqItem->operation;

    memset( &stMech, 0x00, sizeof(stMech));
    memset( sPriSeq, 0x00, sizeof(sPriSeq));
    memset( sPubSeq, 0x00, sizeof(sPubSeq));
    memset( &sPriKMS, 0x00, sizeof(sPriKMS));
    memset( &sPubKMS, 0x00, sizeof(sPubKMS));

    if( crp->common_template_attribute )
    {
        TemplateAttribute *tca = crp->common_template_attribute;

        for( int i = 0; i < tca->attribute_count; i++ )
        {
            if( tca->attributes[i].type == KMIP_ATTR_CRYPTOGRAPHIC_ALGORITHM )
            {
                enum cryptographic_algorithm *alg;
                alg = tca->attributes[i].value;

                if( *alg == KMIP_CRYPTOALG_EC )
                    keyType = CKK_ECDSA;
                else
                    keyType = CKK_RSA;
            }
            else if( tca->attributes[i].type == KMIP_ATTR_CRYPTOGRAPHIC_LENGTH )
            {
                int32 *length = tca->attributes[i].value;
                nLength = *length;
            }
        }
    }

    if( crp->public_key_template_attribute )
    {
        TemplateAttribute *pua = crp->public_key_template_attribute;

        for( int i = 0; i < pua->attribute_count; i++ )
        {
            if( pua->attributes[i].type == KMIP_ATTR_CRYPTOGRAPHIC_USAGE_MASK )
            {

            }
        }
    }

    if( crp->private_key_template_attribute )
    {
        TemplateAttribute *pra = crp->private_key_template_attribute;

        for( int i = 0; i < pra->attribute_count; i++ )
        {
            if( pra->attributes[i].type == KMIP_ATTR_CRYPTOGRAPHIC_USAGE_MASK )
            {

            }
        }
    }

    nPriSeq = JS_DB_getSeq( db, "TB_KMS" );
    nPubSeq = nPriSeq + 1;
    sprintf( sPriSeq, "%d", nPriSeq );
    sprintf( sPubSeq, "%d", nPubSeq );

    if( keyType == CKK_RSA )
    {
        stMech.mechanism = CKM_RSA_PKCS_KEY_PAIR_GEN;
        uModulusBits = nLength;
        JS_BIN_decodeHex( "010001", &binExponent );
    }
    else if( keyType == CKK_ECDSA )
    {
        stMech.mechanism = CKM_ECDSA_KEY_PAIR_GEN;
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

    ret = JS_PKCS11_GenerateKeyPair( g_pP11CTX, g_hSession, &stMech, sPubTemplate, uPubCount, sPriTemplate, uPriCount, &uPubHandle, &uPriHandle );
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

    pRspItem->response_payload = csp;

    JS_DB_setKMS( &sPriKMS, nPriSeq, 0, 1, "privatekey" );
    JS_DB_setKMS( &sPubKMS, nPubSeq, 0, 2, sPriSeq );

    JS_DB_addKMS( db, &sPriKMS );
    JS_DB_addKMS( db, &sPubKMS );

end :
    if( ret == JS_KMS_OK )
    {
        pRspItem->result_status = KMIP_STATUS_SUCCESS;
    }
    else
    {
        const char *pError = getErrorMsg( ret );
        pRspItem->result_status = KMIP_STATUS_OPERATION_FAILED;
        pRspItem->result_reason = KMIP_REASON_GENERAL_FAILURE;
        pRspItem->result_message = JS_strdup( pError );
        pRspItem->result_message->size = strlen( pError );
    }

    JS_BIN_reset( &binECParam );
    JS_BIN_reset( &binExponent );
    JS_DB_resetKMS( &sPriKMS );
    JS_DB_resetKMS( &sPubKMS );

    return ret;
}


int procBatchItem( sqlite3 *db, const RequestBatchItem *pReqItem, ResponseBatchItem *pRspItem )
{
    int ret = 0;

    if( pReqItem->operation == KMIP_OP_GET )
    {
        ret = runGet( db, pReqItem, pRspItem );
    }
    else if( pReqItem->operation == KMIP_OP_CREATE )
    {
        ret = runCreate( db, pReqItem, pRspItem );
    }
    else if( pReqItem->operation == KMIP_OP_DESTROY )
    {
        ret = runDestroy( db, pReqItem, pRspItem );
    }
    else if( pReqItem->operation == KMIP_OP_ACTIVATE )
    {
        ret = runActivate( db, pReqItem, pRspItem );
    }
    else if( pReqItem->operation == KMIP_OP_SIGN )
    {
        ret = runSign( db, pReqItem, pRspItem );
    }
    else if( pReqItem->operation == KMIP_OP_DECRYPT )
    {
        ret = runDecrypt( db, pReqItem, pRspItem );
    }
    else if( pReqItem->operation == KMIP_OP_ENCRYPT )
    {
        ret = runEncrypt( db, pReqItem, pRspItem );
    }
    else if( pReqItem->operation == KMIP_OP_REGISTER )
    {
        ret = runRegister( db, pReqItem, pRspItem );
    }
    else if( pReqItem->operation == KMIP_OP_CREATE_KEY_PAIR )
    {
        ret = runGenKeyPair( db, pReqItem, pRspItem );
    }
    else if( pReqItem->operation == KMIP_OP_SIGNATURE_VERIFY )
    {
        ret = runVerify( db, pReqItem, pRspItem );
    }
    else
    {
        fprintf( stderr, "not support operation(%d)\n", pReqItem->operation );
        return -1;
    }

    return ret;
}


int procKMS( sqlite3 *db, const BIN *pReq, BIN *pRsp )
{
    int ret = 0;
    KMIP ctx = {0};
    RequestMessage  reqm = {0};
    ResponseMessage rspm = {0};
    ResponseBatchItem rspBatch = {0};
    kmip_init(&ctx, NULL, 0, KMIP_1_0);
    memset( &reqm, 0x00, sizeof(reqm));


    kmip_set_buffer( &ctx, pReq->pVal, pReq->nLen );
    kmip_decode_request_message( &ctx, &reqm );

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


