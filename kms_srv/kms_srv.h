#ifndef KMS_SRV_H
#define KMS_SRV_H

#include "js_bin.h"
#include "js_db.h"
#include "js_kms.h"
#include "kmip.h"
#include "js_thread.h"


int KMS_Service( JThreadInfo *pThInfo );
int KMS_SSL_Service( JThreadInfo *pThInfo );


#endif // KMS_SRV_H
