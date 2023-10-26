#ifndef KMS_SRV_H
#define KMS_SRV_H

#include "js_bin.h"
#include "js_db.h"
#include "js_kms.h"
#include "kmip.h"
#include "js_thread.h"

#define     JS_KMS_SRV_VERSION          "0.9.1"

int KMS_Service( JThreadInfo *pThInfo );
int KMS_SSL_Service( JThreadInfo *pThInfo );
int KMS_addAudit( sqlite3 *db, int nOP, const char *pInfo );

int loginHSM();


#endif // KMS_SRV_H
