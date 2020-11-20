#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "js_bin.h"
#include "kmip_data.h"
#include "kms_define.h"
#include "kms_proc.h"
#include "kms_util.h"

int getKMIPAttributeNum( int nType, int nVal, Attribute *pAttribute )
{
    int32 *pnNum = NULL;

    if( pAttribute == NULL ) return -1;

    pnNum = (int32 *)JS_calloc( 1, sizeof(int32));
    *pnNum = nVal;
    pAttribute->value = pnNum;

    pAttribute->type = nType;
    pAttribute->index = 0;
    pAttribute->value = pnNum;

    return 0;
}

int getKMIPAttributeString( int nType, const char *pVal, Attribute *pAttribute )
{
    int32 *pnNum = NULL;
    TextString *pText = NULL;
    int nLen = 0;

    if( pAttribute == NULL ) return -1;

    pAttribute->value = pnNum;

    pAttribute->type = nType;
    pAttribute->index = 0;

    if( pVal == NULL )
    {
        pAttribute->value = NULL;
        return 0;
    }

    nLen = strlen( pVal );
    pText = (TextString *)JS_calloc( 1, sizeof(TextString));
    pText->value = (char *)JS_calloc( 1, nLen + 1 );
    memcpy( pText->value, pVal, nLen );
    pText->size = nLen;
    pAttribute->value = pText;

    return 0;
}

int getKMIPAttribute( const JDB_KMSAttrib *pDBAttribute, Attribute *pAttribute )
{
    TextString *pText = NULL;
    int nLen = 0;
    int32       *pnNum = 0;

    if( pDBAttribute == NULL || pAttribute == NULL ) return -1;

    pAttribute->type = pDBAttribute->nType;
    pAttribute->index = 0;

    if( pDBAttribute == NULL )
    {
        pAttribute->value = NULL;
        return 0;
    }

    switch ( pDBAttribute->nType)
    {
    case KMIP_ATTR_UNIQUE_IDENTIFIER:
    case KMIP_ATTR_OPERATION_POLICY_NAME:
        nLen = strlen( pDBAttribute->pValue );
        pText = (TextString *)JS_calloc( 1, sizeof(TextString));
        pText->value = (char *)JS_calloc( 1, nLen + 1 );
        memcpy( pText->value, pDBAttribute->pValue, nLen );
        pText->size = nLen;
        pAttribute->value = pText;
        break;

    case KMIP_ATTR_CRYPTOGRAPHIC_ALGORITHM:
    case KMIP_ATTR_CRYPTOGRAPHIC_LENGTH:
    case KMIP_ATTR_OBJECT_TYPE:
    case KMIP_ATTR_STATE:
    case KMIP_ATTR_INITIAL_DATE:
    case KMIP_ATTR_CRYPTOGRAPHIC_USAGE_MASK:
        pnNum = (int32 *)JS_calloc( 1, sizeof(int32));
        *pnNum = atoi( pDBAttribute->pValue );
        pAttribute->value = pnNum;
        break;

    default:
        return -1;
    }

    return 0;
}
