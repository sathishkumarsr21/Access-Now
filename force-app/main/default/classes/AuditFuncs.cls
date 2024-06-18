global with sharing class AuditFuncs {
    // called from process builder + time based
    @InvocableMethod
    public static void auditRecentlyViewed(List<Id> requestIds) {
        // this can ONLY be done in the context of the logged in user since RecentlyViewed is only available for the logged in user
        DateTime dt = System.now();
        List<ACNW_Request__c> reqs = new List<ACNW_Request__c>();
        for (ACNW_Request__c r : [select Id, Actual_Start_Time__c, Actual_End_Time__c, Status__c, OwnerId, Requested_End_Time__c, Manually_Revoked__c, (select Id from Data_Audit_Logs__r where Field__c = 'viewed' limit 1) from ACNW_Request__c where Actual_Start_Time__c <> null and Actual_Start_Time__c < :dt and Id in :requestIds]) {
            if (r.Data_Audit_Logs__r.isEmpty() && ((r.Actual_End_Time__c == null && SiteSwitcherFuncs.needToStop(r)) || (r.Actual_End_Time__c != null && r.Actual_End_Time__c <= dt))) {
            	reqs.add(r);
            }
        }

        Id uid = null;
        DateTime minDate = null;

        for (ACNW_Request__c req : reqs) {
            if (uid != null && uid != req.OwnerId) throw new AuditFuncsException('Received multiple owner ids in audit request');
            uid = req.OwnerId;
            if (minDate == null || minDate > req.Actual_Start_Time__c) minDate = req.Actual_Start_Time__c;
        }

        if (reqs.isEmpty() || UserInfo.getUserId() != uid) return;

        List<ACNW_Data_Audit_Log__c> toInsert = new List<ACNW_Data_Audit_Log__c>();
        for (RecentlyViewed rv : [select Id, Type, LastViewedDate, Name from RecentlyViewed where LastViewedDate >= :minDate]) {
            for (ACNW_Request__c req : reqs) {
                if (rv.LastViewedDate >= req.Actual_Start_Time__c && rv.LastViewedDate <= (req.Actual_End_Time__c == null ? dt : req.Actual_End_Time__c)) {
                    toInsert.add(new ACNW_Data_Audit_Log__c(
                        Logged_In_As__c = uid,
                        Parent_Id__c = rv.Id,
                        Field__c = 'viewed',
                        Date__c = rv.LastViewedDate,
                        Object_Name__c = rv.Type,
                        Parent_Name__c = rv.Name,
                        Request__c = req.Id
                    ));
                }
            }
        }

        if (!toInsert.isEmpty()) insert toInsert;
    }

    // called from real-time triggers deployed in the org
    global static void auditRecords() {
        // if impersonating, we get these afterwards via the history trigger
        Id userId = UserInfo.getUserId();

        Id requestId = null;

        for (ACNW_Request__c req : [select Id from ACNW_Request__c where Status__c = 'In Progress' and OwnerId = :userinfo.getUserId()]) {
            requestId = req.Id;
        }

        if (requestId == null) return;

        list<sobject> recs = trigger.isDelete ? trigger.old : trigger.new;
        map<id, sobject> oldRecs = trigger.isUpdate ? trigger.oldMap : null;

        Schema.DescribeSObjectResult describeRes = recs[0].getsobjecttype().getdescribe();
        String objectName = describeRes.getName();

        Map<String, Schema.SObjectField> fields = describeRes.fields.getMap();

        String nameField = null;
        if (fields.containsKey('name')) {
            nameField = 'Name';
        } else {
            for (Schema.SObjectField fld : fields.values()) {
                if (fld.getDescribe().isNameField()) {
                    nameField = fld.getDescribe().getName();
                }
            }
        }

        list<ACNW_Data_Audit_Log__c> toInsert = new list<ACNW_Data_Audit_Log__c>();

        for (sobject r : recs) {
            String recordName = nameField == null ? null : (String)r.get(nameField);

            if (trigger.isInsert) {
                toInsert.add(new ACNW_Data_Audit_Log__c(
                    Logged_In_As__c = UserInfo.getUserId(),
                    Parent_Id__c = r.Id,
                    Field__c = 'created',
                    Date__c = System.now(),
                    Object_Name__c = objectName,
                    Parent_Name__c = recordName,
                    Request__c = requestId
                ));
            } else if (trigger.isUpdate) {
                SObject oldRec = oldRecs.get(r.Id);
                for (String f : fields.keySet()) {
                    if (f == 'lastmodifieddate' || f == 'lastmodifiedbyid' || f == 'systemmodstamp') continue;

                    if (oldRec.get(f) != r.get(f)) {
                        toInsert.add(new ACNW_Data_Audit_Log__c(
                            Logged_In_As__c = UserInfo.getUserId(),
                            Parent_Id__c = r.Id,
                            Field__c = fields.get(f).getDescribe().getName(),
                            Old_Value__c = oldRec.get(f) == null ? '' : '' + oldRec.get(f),
                            New_Value__c = r.get(f) == null ? '' : '' + r.get(f),
                            Date__c = System.now(),
                            Object_Name__c = objectName,
                            Parent_Name__c = recordName,
                            Request__c = requestId
                        ));
                    }
                }
            } else if (trigger.isDelete) {
                toInsert.add(new ACNW_Data_Audit_Log__c(
                    Logged_In_As__c = UserInfo.getUserId(),
                    Parent_Id__c = r.Id,
                    Field__c = 'deleted',
                    Date__c = System.now(),
                    Object_Name__c = objectName,
                    Parent_Name__c = recordName,
                    Request__c = requestId
                ));
            } else if (trigger.isUndelete) {
                toInsert.add(new ACNW_Data_Audit_Log__c(
                    Logged_In_As__c = UserInfo.getUserId(),
                    Parent_Id__c = r.Id,
                    Field__c = 'undeleted',
                    Date__c = System.now(),
                    Object_Name__c = objectName,
                    Parent_Name__c = recordName,
                    Request__c = requestId
                ));
            }
        }

        if (!toInsert.isEmpty()) insert toInsert;
    }
    class AuditFuncsException extends Exception { }
}