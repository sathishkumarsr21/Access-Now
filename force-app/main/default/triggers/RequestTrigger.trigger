trigger RequestTrigger on ACNW_Request__c (before insert, before update, after insert, after update, before delete) {
    if (Trigger.isDelete) {
        // make sure it's not in progress
        for (ACNW_Request__c req : trigger.old) {
            if (req.Status__c == 'In Progress') {
                req.addError(Label.ERR_InProgressRequestsCannotBeDeleted);
            }
        }
    } else {
        if (trigger.isBefore) {
            for (ACNW_Request__c req : trigger.new) {
                if (trigger.isInsert) req.TRVP__c = true;

                if (req.Status__c == 'Approved' && (trigger.isInsert || trigger.oldMap.get(req.Id).Status__c != 'Approved')) {
                    if (req.Provision_Immediately__c) {
                        req.Requested_Start_Time__c = System.now();
                    }
                    req.Approved_On__c = System.now();
                }
                if (req.Manually_Revoked__c && (trigger.isInsert || !trigger.oldMap.get(req.Id).Manually_Revoked__c)) {
                    if (req.Actual_Start_Time__c == null) {
                        // not yet started - basically cancel it out
                        req.Status__c = 'Cancelled';
                        req.TRVP__c = false;
                    } else {
                        if (req.Actual_End_Time__c != null) {
                            req.addError(Label.ERR_RequestAlreadyCompleted);
                        } else {
                            // let this go through - user is requesting it be cancelled - in the after trigger we will deal with this
                        }
                    }
                }
            }
        } else {
            list<ACNW_Request__c> okRequests = new list<ACNW_Request__c>();
            list<ACNW_Request__c> dupeCheckRequests = new list<ACNW_Request__c>();
            DateTime minDateTime = null;
            DateTime maxDateTime = null;
            set<Id> ownerIdsToCheck = new set<id>();
            for (ACNW_Request__c att : trigger.new) {
                // if it's existing and owner/datetime hasn't changed, let it go through--otherwise we need to make sure nothing overlaps
                if (att.Status__c == 'Draft' || (trigger.isUpdate && att.OwnerId == trigger.oldMap.get(att.Id).OwnerId && att.Requested_Start_Time__c == trigger.oldMap.get(att.Id).Requested_Start_Time__c && att.accessnow__Requested_End_Time__c == trigger.oldMap.get(att.Id).accessnow__Requested_End_Time__c)) {
                    okRequests.add(att);
                } else {
                    dupeCheckRequests.add(att);
                    minDateTime = minDateTime == null ? att.Requested_Start_Time__c : (minDateTime > att.Requested_Start_Time__c ? att.Requested_Start_Time__c : minDateTime);
                    maxDateTime = maxDateTime == null ? att.Requested_End_Time__c : (maxDateTime < att.Requested_End_Time__c ? att.Requested_End_Time__c : maxDateTime);
                    ownerIdsToCheck.add(att.OwnerId);
                }
            }
            if (!dupeCheckRequests.isEmpty()) {
                // check for duplicates
                list<ACNW_Request__c> existingReqs = [select Id, Status__c, Name, OwnerId, Requested_Start_Time__c, Requested_End_Time__c from accessnow__ACNW_Request__c where accessnow__Status__c not in ('Draft','Cancelled','Completed') and Requested_Start_Time__c <= :maxDateTime and Requested_End_Time__c >= :minDateTime and OwnerId in :ownerIdsToCheck order by Requested_Start_Time__c];
                for (ACNW_Request__c dc : dupeCheckRequests) {
                    List<ACNW_Request__c> dupes = new list<ACNW_Request__c>();
                    for (ACNW_Request__c pc : existingReqs) {
                        if (dc.Id == pc.Id || dc.OwnerId != pc.OwnerId || dc.Requested_Start_Time__c == pc.Requested_End_Time__c || pc.Requested_Start_Time__c == dc.Requested_End_Time__c) continue;
                        if (dc.Requested_Start_Time__c <= pc.Requested_End_Time__c && pc.Requested_Start_Time__c <= dc.Requested_End_Time__c) dupes.add(pc);
                    }
                    if (dupes.isEmpty()) {
                        okRequests.add(dc);
                    } else {
                        List<String> conflictReqs = new List<String>();
                        for (ACNW_Request__c d : dupes) conflictReqs.add(d.Name + ' - ' + d.Requested_Start_Time__c.format() + ' - ' + d.Requested_End_Time__c.format() + ' - ' + d.Status__c);
                        dc.addError('Request ' + dc.Requested_Start_Time__c.format() + ' - ' + dc.Requested_End_Time__c.format() + ' conflicts with\n' + String.join(conflictReqs, '\n'));
                    }
                }
            }

            Set<Id> hasRoles = new Set<Id>();
            Set<Id> hasPerms = new Set<Id>();
            Set<Id> hasPermGroups = new Set<Id>();
            Map<Id, Integer> hasProfiles = new Map<Id, Integer>();

            List<ACNW_Request_Permission__c> pts = [select User_Permission__r.Permission__c, User_Permission__r.Permission__r.Type__c, Request__c from ACNW_Request_Permission__c where Request__c in :okRequests];
            Map<Id, List<ACNW_Permission__c>> grpPermissions = new Map<Id, List<ACNW_Permission__c>>();
            for (ACNW_Request_Permission__c rp : pts) if (rp.User_Permission__r.Permission__r.Type__c == 'Permission Bundles') grpPermissions.put(rp.User_Permission__r.Permission__c, null);
            if (!grpPermissions.isEmpty()) grpPermissions = SiteSwitcherFuncs.getPermsForAccessNowPermissionGroup(grpPermissions.keySet());

            for (ACNW_Request_Permission__c rp : pts) {
                String typ = rp.User_Permission__r.Permission__r.Type__c;
                list<String> types = new List<String>();
                if (typ == 'Permission Bundles') {
                    for (ACNW_Permission__c ap : grpPermissions.get(rp.User_Permission__r.Permission__c)) types.add(ap.Type__c);
                } else {
                    types.add(typ);
                }
                for (String ty : types) {
                    if (ty == 'Role') hasRoles.add(rp.Request__c);
                    else if (ty == 'Permission Set') hasPerms.add(rp.Request__c);
                    else if (ty == 'Permission Set Group') hasPermGroups.add(rp.Request__c);
                    else if (ty == 'Profile') {
                        if (!hasProfiles.containsKey(rp.Request__c)) hasProfiles.put(rp.Request__c, 0);
                        hasProfiles.put(rp.Request__c, hasProfiles.get(rp.Request__c) + 1);
                    }
                }
            }

            Set<Id> idsToSwitch = new Set<Id>();
            DateTime now = System.now();
            for (ACNW_Request__c req : okRequests) {
                if (req.Status__c == 'Pending Approval' && (trigger.isInsert || trigger.oldMap.get(req.Id).Status__c != 'Pending Approved')) {
                    // make sure that we have permission sets or sys admin checked
                    if (hasProfiles.containsKey(req.Id) && hasProfiles.get(req.Id) > 1) req.addError(Label.MSG_ProfileOrPermissionSet);
                    else if (!hasRoles.contains(req.Id) && !hasPermGroups.contains(req.Id) && !hasPerms.contains(req.Id) && !hasProfiles.containsKey(req.Id)) req.addError(Label.MSG_ProfileOrPermissionSet);
                }

                if (trigger.isUpdate && ((req.Status__c == 'Approved' &&  trigger.oldmap.get (req.id).status__c != 'Draft' && trigger.oldMap.get(req.Id).Status__c != 'Pending Approval') || req.Status__c == 'In Progress')) {
                    // make sure nothing can change - duration, owner
                    if (req.Duration_Hours__c != trigger.oldMap.get(req.Id).Duration_Hours__c || req.OwnerId != trigger.oldMap.get(req.Id).OwnerId || req.Requested_Start_Time__c != trigger.oldMap.get(req.Id).Requested_Start_Time__c) {
                        req.addError(Label.ERR_RequestCannotBeEditedAfterApproval);
                        continue;
                    }
                }
                if (trigger.isUpdate && !String.isEmpty(req.Last_Error__c)) {
                    // in an error state - nothing else to do
                } else if (SiteSwitcherFuncs.needToStart(req) || SiteSwitcherFuncs.needToStop(req)) {
                    // need to make a call to start/stop
                    idsToSwitch.add(req.Id);
                }
            }
            if (!idsToSwitch.isEmpty()) {
                SiteSwitcherFuncs.callSiteSwitch(idsToSwitch);
            }
        }
    }
}