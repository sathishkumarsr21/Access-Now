trigger UserPermissionTrigger on ACNW_User_Permission__c (before insert, before update) {
    for (ACNW_User_Permission__c up : trigger.new) {
        up.Unique_Key__c = up.User__c + '_' + up.Permission__c;
    }
}