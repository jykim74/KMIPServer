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

long findObjects( const BIN *pID, CK_OBJECT_HANDLE_PTR *pObjects )
{
    int ret = 0;
    CK_ATTRIBUTE sTemplate[2];
    CK_ULONG uCount = 0;
    CK_OBJECT_CLASS objClass = 0;
    CK_ULONG uMaxObjCnt = 20;
    CK_ULONG uObjCnt = -1;

    objClass = CKO_SECRET_KEY;

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

    ret = findObjects( &binID, sObjects );

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

    ret = findObjects( &binID, sObjects );

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
    else if( pReqItem->operation == KMIP_OP_SIGN )
    {

    }
    else if( pReqItem->operation == KMIP_OP_DECRYPT )
    {

    }
    else if( pReqItem->operation == KMIP_OP_ENCRYPT )
    {

    }
    else if( pReqItem->operation == KMIP_OP_REGISTER )
    {

    }
    else if( pReqItem->operation == KMIP_OP_CREATE_KEY_PAIR )
    {

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


