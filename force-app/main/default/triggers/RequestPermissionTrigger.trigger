trigger RequestPermissionTrigger on ACNW_Request_Permission__c (after insert, before insert, before update, before delete) {
    if (trigger.isBefore) {
        // make sure we only allow deletions if the request is Draft or Cancelled
        map<id, ACNW_request__c> parentIds = new map<id, ACNW_request__c>();
        for (ACNW_Request_Permission__c rp : trigger.isDelete ? trigger.old : trigger.new) {
            parentIds.put(rp.Request__c, null);
        }
        parentIds = new Map<Id, ACNW_Request__c>([select Id from ACNW_Request__c where Status__c in ('Draft','Cancelled') and Id in :parentIds.keySet()]);
        for (ACNW_Request_Permission__c rp : trigger.isDelete ? trigger.old : trigger.new) {
            if (!parentIds.containsKey(rp.Request__c)) {
                rp.addError(Label.ERR_RequestCannotBeEditedAfterApproval);
            }
        }
    } else {
        if (trigger.isInsert) {
            // make sure that the user permissions all belong to the owner of the request
            map<id, ACNW_Request__c> reqIds = new map<id, ACNW_Request__c>();
            map<id, ACNW_User_Permission__c> upIds = new map<id, ACNW_User_Permission__c>();
            for (ACNW_Request_Permission__c rp : trigger.new) {
                reqIds.put(rp.Request__c, null);
                upIds.put(rp.User_Permission__c, null);
            }
            reqIds = new map<id, ACNW_request__c>([select Id, OwnerId from ACNW_Request__c where Id in :reqIds.keySet()]);
            upIds = new map<id, ACNW_user_permission__c>([select Id, User__c from ACNW_User_Permission__c where Id in :upIds.keySet()]);
            for (ACNW_Request_Permission__c rp : trigger.new) {
                if (reqIds.get(rp.Request__c).OwnerId != upIds.get(rp.User_Permission__c).User__c) {
                    rp.addError(Label.ERR_UserPermissionCannotBeChanged);
                }
            }
        }
    }
}