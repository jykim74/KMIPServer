#include "kms_define.h"
#include "js_util.h"

static JNumVal      sErrList[] = {
    { JS_KMS_ERROR_SYSTEM, "System fail" },
    { JS_KMS_ERROR_NO_OBJECT, "no object" },
    { JS_KMS_ERROR_FAIL_GET_VALUE, "fail to get value" },
    { JS_KMS_ERROR_FAIL_DESTROY_OBJECT, "fail to destroy object" },
    { JS_KMS_ERROR_FAIL_GEN_KEY, "fail to generate key" },
    { JS_KMS_ERROR_NO_PAYLOAD, "no payload" },
    { JS_KMS_ERROR_NOT_SUPPORT_PARAM, "not support parameter" },
    { JS_KMS_ERROR_INVALID_VALUE, "invalid value" },
};

const char *getErrorMsg( int nNum )
{
    int nCount = sizeof( sErrList ) / sizeof(sErrList[0]);

    for( int i = 0; i < nCount; i++ )
    {
        if( sErrList[i].nNum == nNum )
            return sErrList[i].pValue;
    }

    return sErrList[0].pValue;
}
