#ifndef KMS_PROC_H
#define KMS_PROC_H

#include "js_bin.h"
#include "js_db.h"
#include "js_kms.h"
#include "kmip.h"

int runGet( sqlite3 *db, const GetRequestPayload *pReqPayload, GetResponsePayload **ppRspPayload );
int runCreate( sqlite3 *db, const CreateRequestPayload *pReqPayload, CreateResponsePayload **ppRspPayload );
int runDestroy( sqlite3 *db, const DestroyRequestPayload *pReqPayload, DestroyResponsePayload **ppRspPayload );
int runActivate( sqlite3 *db, const ActivateRequestPayload *pReqPayload, ActivateResponsePayload **ppRspPayload );
int runEncrypt( sqlite3 *db, const EncryptRequestPayload *pReqPayload, EncryptResponsePayload **ppRspPayload );
int runDecrypt( sqlite3 *db, const DecryptRequestPayload *pReqPayload, DecryptResponsePayload **ppRspPayload );
int runSign( sqlite3 *db, const SignRequestPayload *pReqPayload, SignResponsePayload **ppRspPayload );
int runVerify( sqlite3 *db, const SignatureVerifyRequestPayload *pReqPayload, SignatureVerifyResponsePayload **ppRspPayload );
int runRegister( sqlite3 *db, const RegisterRequestPayload *pReqPayload, RegisterResponsePayload **ppRspPayload );
int runCreateKeyPair( sqlite3 *db, const CreateKeyPairRequestPayload *pReqPayload, CreateKeyPairResponsePayload **ppRspPayload );
int runGetAttributeList( sqlite3 *db, const GetAttributeListRequestPayload *pReqPayload, GetAttributeListResponsePayload **ppRspPayload );
int runHash( sqlite3 *db, const HashRequestPayload *pReqPayload, const HashResponsePayload **ppRspPayload );

int isAuthentication( const Authentication *pAuth );
int procKMS( sqlite3 *db, const BIN *pReq, BIN *pRsp );

#endif // KMS_PROC_H
