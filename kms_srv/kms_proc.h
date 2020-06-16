#ifndef KMS_PROC_H
#define KMS_PROC_H

#include "js_bin.h"
#include "js_db.h"
#include "js_kms.h"
#include "kmip.h"

int runGet( sqlite3 *db, const RequestBatchItem *pReqItem, ResponseBatchItem *pRspItem );
int runCreate( sqlite3 *db, const RequestBatchItem *pReqItem, ResponseBatchItem *pRspItem);
int runDestroy( sqlite3 *db, const RequestBatchItem *pReqItem, ResponseBatchItem *pRspItem);

int procKMS( sqlite3 *db, const BIN *pReq, BIN *pRsp );

#endif // KMS_PROC_H
