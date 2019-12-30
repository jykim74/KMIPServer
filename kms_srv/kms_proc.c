#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "kmip.h"
#include "js_bin.h"

int runGet( const RequestBatchItem *pReqItem, ResponseBatchItem *pRspItem )
{
    return 0;
}

int runCreate(const RequestBatchItem *pReqItem, ResponseBatchItem *pRspItem)
{
    return 0;
}

int runDestroy(const RequestBatchItem *pReqItem, ResponseBatchItem *pRspItem)
{
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

    return 0;
}

int procKMS( const BIN *pReq, BIN *pRsp )
{
    KMIP ctx = {0};
    RequestMessage  reqm = {0};
    ResponseMessage rspm = {0};

    kmip_init(&ctx, NULL, 0, KMIP_1_0);
    memset( &reqm, 0x00, sizeof(reqm));

    kmip_set_buffer( &ctx, pReq->pVal, pReq->nLen );
    kmip_decode_request_message( &ctx, &reqm );

    kmip_print_request_message( &reqm );

    for( int i = 0; i < reqm.batch_count; i++ )
    {

    }

    kmip_set_buffer( &ctx, NULL, 0 );
    kmip_print_response_message( &rspm );
    kmip_encode_response_message( &ctx, &reqm );

    JS_BIN_set( pRsp, ctx.buffer, ctx.size );

    kmip_free_request_message( &ctx, &reqm );
    kmip_free_response_message( &ctx, &rspm );
    kmip_set_buffer( &ctx, NULL, 0 );
    kmip_destroy( &ctx );
    return 0;
}


