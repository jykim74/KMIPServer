#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "kmip.h"
#include "js_bin.h"
#include "js_pkcs11.h"

extern JSP11_CTX    *g_pP11CTX;
extern CK_SESSION_HANDLE    g_hSession;

int runGet( const RequestBatchItem *pReqItem, ResponseBatchItem *pRspItem )
{
    GetRequestPayload *grp = (GetRequestPayload *)pReqItem->request_payload;



    return 0;
}

int runCreate(const RequestBatchItem *pReqItem, ResponseBatchItem *pRspItem)
{
    int ret = 0;
    CreateRequestPayload *crp = (CreateRequestPayload *)pReqItem->request_payload;

    CK_ATTRIBUTE        sTemplate[20];
    long                uCount = 0;
    CK_OBJECT_HANDLE hObject = 0;
    CK_MECHANISM    sMech;

    int             *pnAlg = NULL;
    int             *pnLen = NULL;
    int             *pnMask = NULL;

    memset( &sMech, 0x00, sizeof(sMech));

    if( crp->object_type == KMIP_OBJTYPE_SYMMETRIC_KEY )
    {
        CK_OBJECT_CLASS keyClass = CKO_SECRET_KEY;
        sTemplate[uCount].type = CKA_CLASS;
        sTemplate[uCount].pValue = &keyClass;
        sTemplate[uCount].ulValueLen = sizeof(keyClass);
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

                sTemplate[uCount].type = CKA_VALUE_LEN;
                sTemplate[uCount].pValue = pnLen;
                sTemplate[uCount].ulValueLen = sizeof(*pnLen);
                uCount++;
            }
            else if( ta->attributes[i].type == KMIP_ATTR_CRYPTOGRAPHIC_USAGE_MASK )
            {
                pnMask = ta->attributes[i].value;

                if( *pnMask | KMIP_CRYPTOMASK_ENCRYPT )
                {
                    sTemplate[uCount].type = CKA_ENCRYPT;
                    sTemplate[uCount].pValue = CK_TRUE;
                    sTemplate[uCount].ulValueLen = sizeof(CK_TRUE);
                    uCount++;
                }
                else if( *pnMask | KMIP_CRYPTOMASK_DECRYPT )
                {
                    sTemplate[uCount].type = CKA_DECRYPT;
                    sTemplate[uCount].pValue = CK_TRUE;
                    sTemplate[uCount].ulValueLen = sizeof(CK_TRUE);
                    uCount++;
                }
            }
        }

        ret = JS_PKCS11_GenerateKey( g_pP11CTX, g_hSession, &sMech, sTemplate, uCount, &hObject );
        if( ret != CKR_OK )
        {
            fprintf( stderr, "fail to run generate key(%d)\n", ret );
        }


    }

    CreateResponsePayload   *pld = (CreateRequestPayload *)JS_calloc( 1, sizeof(CreateResponsePayload ) );
    pld->object_type = KMIP_OBJTYPE_SYMMETRIC_KEY;
    pRspItem->operation = pReqItem->operation;


    if( ret == 0 )
    {
        pRspItem->result_status = KMIP_STATUS_SUCCESS;
        pld->unique_identifier = (TextString *)JS_malloc(sizeof(TextString));
        pld->unique_identifier->size = 4;
        pld->unique_identifier->value = JS_strdup("1111");
        pRspItem->response_payload = pld;
    }
    else
    {
        pRspItem->result_status = KMIP_STATUS_OPERATION_FAILED;
        pRspItem->result_reason = KMIP_REASON_GENERAL_FAILURE;
        pRspItem->result_message = (TextString *)JS_malloc(sizeof(TextString));
        pRspItem->result_message->size = 5;
        pRspItem->result_message->value = JS_strdup( "error" );
    }

    return 0;
}

int runDestroy(const RequestBatchItem *pReqItem, ResponseBatchItem *pRspItem)
{
    DestroyRequestPayload *drp = (DestroyRequestPayload *)pReqItem->request_payload;


    return 0;
}

int procBatchItem( const RequestBatchItem *pReqItem, ResponseBatchItem *pRspItem )
{
    int ret = 0;

    if( pReqItem->operation == KMIP_OP_GET )
    {
        ret = runGet( pReqItem, pRspItem );
    }
    else if( pReqItem->operation == KMIP_OP_CREATE )
    {
        ret = runCreate( pReqItem, pRspItem );
    }
    else if( pReqItem->operation == KMIP_OP_DESTROY )
    {
        ret = runDestroy( pReqItem, pRspItem );
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

#if 1
int procKMS( const BIN *pReq, BIN *pRsp )
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
        ret = procBatchItem( reqm.batch_items, &rspBatch );
    }

//    kmip_set_buffer( &ctx, NULL, 0 );
    kmip_reset( &ctx );

    ResponseHeader  rsph = {0};
    ProtocolVersion pv = {0};

    rsph.time_stamp = time(NULL);
    kmip_init_protocol_version( &pv, KMIP_1_0 );

    rspm.response_header = &rsph;
    rsph.protocol_version = &pv;
    rsph.batch_count = 1;

    rspm.batch_count = 1;
    rspm.batch_items = &rspBatch;


    kmip_encode_response_message( &ctx, &rspm );
    kmip_print_response_message( &rspm );

    JS_BIN_set( pRsp, ctx.buffer, ctx.size );

    kmip_free_request_message( &ctx, &reqm );
//    kmip_free_response_message( &ctx, &rspm );
    kmip_set_buffer( &ctx, NULL, 0 );
    kmip_destroy( &ctx );
    return 0;
}
#else
int procKMS( const BIN *pReq, BIN *pRsp )
{
    int ret = 0;
    KMIP ctx = {0};
    RequestMessage  reqm = {0};

    kmip_init(&ctx, NULL, 0, KMIP_1_0);
    memset( &reqm, 0x00, sizeof(reqm));

    kmip_set_buffer( &ctx, pReq->pVal, pReq->nLen );
    kmip_decode_request_message( &ctx, &reqm );
    kmip_print_request_message( &reqm );


    printf( "----------> Response -------------\n");
    kmip_reset( &ctx );
    ResponseMessage rspm = {0};
    ResponseBatchItem rspBatch = {0};
    ResponseHeader  rsph = {0};
    ProtocolVersion pv = {0};
    CreateResponsePayload crp = {0};

    rsph.time_stamp = time(NULL);
    kmip_init_protocol_version( &pv, KMIP_1_0 );

    rspm.response_header = &rsph;
    rsph.protocol_version = &pv;
    rsph.batch_count = 1;

    crp.object_type = KMIP_OBJTYPE_SYMMETRIC_KEY;

    TextString p = {0};
    p.value = "1111";
    p.size = kmip_strnlen_s("1111", 50);
    crp.unique_identifier = &p;



    rspBatch.operation = KMIP_OP_CREATE;
    rspBatch.result_status = KMIP_STATUS_SUCCESS;
    rspBatch.response_payload = &crp;

    rspm.batch_items = &rspBatch;
    rspm.batch_count = 1;

    kmip_encode_response_message( &ctx, &rspm );
    kmip_print_response_message( &rspm );

    JS_BIN_set( pRsp, ctx.buffer, ctx.size );

    kmip_free_request_message( &ctx, &reqm );
//    kmip_free_response_message( &ctx, &rspm );
    kmip_set_buffer( &ctx, NULL, 0 );
    kmip_destroy( &ctx );
    return 0;
}
#endif

