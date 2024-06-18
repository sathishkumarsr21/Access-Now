trigger PermissionSetTrigger on ACNW_Permission__c (before insert, before update) {
    Set<Id> permissionSetsToLoad = new Set<Id>();
    Set<Id> permissionSetGroupsToLoad = new Set<Id>();
    Set<Id> profilesToLoad = new Set<Id>();
    for (ACNW_Permission__c rp : trigger.new) {
        try {
            rp.SF_Permission_Id__c = (Id)rp.SF_Permission_Id__c;
            if (rp.Type__c == 'Permission Set') {
                permissionSetsToLoad.add(rp.SF_Permission_Id__c);
            } else if (rp.Type__c == 'Permission Set Group') {
                permissionSetGroupsToLoad.add(rp.SF_Permission_Id__c);
            } else if (rp.Type__c == 'Profile') {
                profilesToLoad.add(rp.SF_Permission_Id__c);
            }
        } catch(Exception ex) {
            rp.addError(String.format(Label.ERR_InvalidId, new List<String> { rp.SF_Permission_Id__c } ));
        }
    }
    if (!permissionSetsToLoad.isEmpty()) {
        Set<Id> existing = (new Map<Id, PermissionSet>([select Id from PermissionSet where Id in :permissionSetsToLoad and IsOwnedByProfile = false])).keySet();
        for (Id s : permissionSetsToLoad) {
            if (!existing.contains(s)) {
                for (ACNW_Permission__c rp : trigger.new) {
                    if ((Id)rp.SF_Permission_Id__c == s) rp.addError(Label.ERR_PermissionSetNotFound);
                }
            }
        }
    }
    if (!permissionSetGroupsToLoad.isEmpty()) {
        Set<Id> existing = (new Map<Id, PermissionSetGroup>([select Id from PermissionSetGroup where Id in :permissionSetGroupsToLoad])).keySet();
        for (Id s : permissionSetGroupsToLoad) {
            if (!existing.contains(s)) {
                for (ACNW_Permission__c rp : trigger.new) {
                    if ((Id)rp.SF_Permission_Id__c == s) rp.addError(Label.ERR_PermissionSetGroupNotFound);
                }
            }
        }
    }
    if (!profilesToLoad.isEmpty()) {
        Set<Id> existing = (new Map<Id, Profile>([select Id from Profile where Id in :profilesToLoad])).keySet();
        for (Id s : profilesToLoad) {
            if (!existing.contains(s)) {
                for (ACNW_Permission__c rp : trigger.new) {
                    if ((Id)rp.SF_Permission_Id__c == s) rp.addError(Label.ERR_ProfileNotFound);
                }
            }
        }
    }
}