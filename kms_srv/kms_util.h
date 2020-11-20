#ifndef KMS_UTIL_H
#define KMS_UTIL_H

#include "js_db.h"
#include "js_kms.h"
#include "kmip.h"

int getKMIPAttributeNum( int nType, int nVal, Attribute *pAttribute );
int getKMIPAttributeString( int nType, const char *pVal, Attribute *pAttribute );
int getKMIPAttribute( const JDB_KMSAttrib *pDBAttribute, Attribute *pAttribute );


#endif // KMS_UTIL_H
