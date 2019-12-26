#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "js_pki.h"
#include "js_http.h"
#include "js_process.h"
#include "js_db.h"

#include "kms_srv.h"

int KMS_Service( JThreadInfo *pThInfo )
{
    return 0;
}

int KMS_SSL_Service( JThreadInfo *pThInfo )
{
    return 0;
}

int main( int argc, char *argv[] )
{
    JS_THD_logInit( "./log", "kms", 2 );
    JS_THD_registerService( "JS_KMS", NULL, 9040, 4, NULL, KMS_Service );
    JS_THD_registerService( "JS_KMS_SSL", NULL, 9140, 4, NULL, KMS_SSL_Service );
    JS_THD_serviceStartAll();

    return 0;
}
