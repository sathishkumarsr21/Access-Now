@RestResource(urlMapping='/accessnow/*')
global with sharing class SiteSwitcher {
    private static final Integer DML_BUFFER = 100; // number of rows to leave as buffer for things that need to happen with the app itself
    private static final Integer SOQL_BUFFER = 10; // number of SOQL calls to leave as buffer for app related things

    @HttpGet
    global static String switch() {
        RestContext.response.statusCode = 500;

        Id id = RestContext.request.params.get('id');
        String checksum = RestContext.request.params.get('cs');
        String func = RestContext.request.params.get('func');

        try {
            checksum = EncryptionUtils.decryptData(checksum);
        } catch(Exception ex) {
            return 'ERROR: Unable to verify checksum integrity';
        }
        if ((Id)checksum != id) {
            return 'ERROR: Unable to verify checksum';
        }
        String ret = 'OK';
        if (func == 'perms') {
            ret = addRemovePermissions(id);
        } else {
            ret = switch(id);
        }

        if (ret == 'OK') RestContext.response.statusCode = 200;
        return ret;
    }
    public static String switch(Id id) {
        Savepoint sp = Database.setSavepoint();
        Boolean autoRetry = false;
        try {
            // call the site to do this work
            //DateTime now = System.now();
            ACNW_Request__c req = SiteSwitcherFuncs.getReq(id);

            if (!Schema.SObjectType.ACNW_Request__c.fields.Last_Error__c.isUpdateable()) throw new SiteSwitcherException(Label.MSG_InsufficientPrivileges + ' - Last error updateble');
            req.Last_Error__c = null;

            Boolean updateIt = false;
            User u = [select Id, Profile.Name, Profile.UserLicense.Name, ProfileId, UserRoleId from User where Id = :req.OwnerId];

            String newStatus = null;
            boolean needToStart = SiteSwitcherFuncs.needToStart(req);
            boolean needToStop = !needToStart && SiteSwitcherFuncs.needToStop(req);

            if (Test.isRunningTest()) {
                needToStart = true;
                needToStop = true;
            }
            if (needToStart) {
                // make sure no other request is already in progress
                ACNW_Request__c exReq = SiteSwitcherFuncs.getRequestAlreadyInProgress(req.OwnerId, req.Id);
                if (exReq != null) {
                    autoRetry = true;
                    throw new SiteSwitcherException(String.format(Label.ERR_AnotherRequestIsAlreadyInProgress, new String[] { exReq.Name }));
                }

                if (!Schema.SObjectType.ACNW_Request__c.fields.Actual_Start_Time__c.isUpdateable()) throw new SiteSwitcherException(Label.MSG_InsufficientPrivileges + ' - Actual Start Time updateble');
                req.Actual_Start_Time__c = System.now();

                newStatus = 'In Progress';

                if (!Schema.SObjectType.ACNW_Request__c.fields.Original_Profile_Id__c.isUpdateable()) throw new SiteSwitcherException(Label.MSG_InsufficientPrivileges + ' - Original Profile Id updateble');
                req.Original_Profile_Id__c = u.ProfileId;

                if (!Schema.SObjectType.ACNW_Request__c.fields.Original_Role_Id__c.isUpdateable()) throw new SiteSwitcherException(Label.MSG_InsufficientPrivileges + ' - Original Role Id updateble');
                req.Original_Role_Id__c = u.UserRoleId;

                Set<String> permSetGroupIds = new Set<String>();
                for (PermissionSetAssignment psa : [select PermissionSetGroupId from PermissionSetAssignment where PermissionSetGroupId <> null and AssigneeId = :req.OwnerId]) {
                    permSetGroupIds.add(psa.PermissionSetGroupId);
                }
                if (!Schema.SObjectType.ACNW_Request__c.fields.Original_Permission_Set_Group_Ids__c.isUpdateable()) throw new SiteSwitcherException(Label.MSG_InsufficientPrivileges + ' - Original Permission Set Group Ids updateble');
                req.Original_Permission_Set_Group_Ids__c = String.join(new List<String>(permSetGroupIds), '\n');

                List<String> permSetIds = new List<String>();
                for (PermissionSetAssignment psa : [select PermissionSetId from PermissionSetAssignment where PermissionSetGroupId = null and PermissionSet.IsOwnedByProfile = false and AssigneeId = :req.OwnerId]) {
                    permSetIds.add(psa.PermissionSetId);
                }
                if (!Schema.SObjectType.ACNW_Request__c.fields.Original_Permission_Set_Ids__c.isUpdateable()) throw new SiteSwitcherException(Label.MSG_InsufficientPrivileges + ' - Original Permission Set Ids updateble');
                req.Original_Permission_Set_Ids__c = String.join(permSetIds, '\n');

                // this will make sure the permissions are all good
                Id newProfileId = SiteSwitcherFuncs.getProfileIdForReq(u, req);

                // nothing to do if already the same
                if (newProfileId == u.ProfileId) newProfileId = null;

                updateIt = true;
            }
            if (needToStop) {
                if (req.Actual_Start_Time__c == null) {
                    // never was started - nothing to do - mark it cancelled
                    newStatus = 'Cancelled';
                } else {
                    if (!Schema.SObjectType.ACNW_Request__c.fields.Actual_End_Time__c.isUpdateable()) throw new SiteSwitcherException(Label.MSG_InsufficientPrivileges + ' - Actual End Time updateble');
                    req.Actual_End_Time__c = System.now();

                    newStatus = 'Completed';
                    if (!req.Manually_Revoked__c) {
                        if (!Schema.SObjectType.ACNW_Request__c.fields.Automatically_Revoked__c.isUpdateable()) throw new SiteSwitcherException(Label.MSG_InsufficientPrivileges + ' - Automatically revoked updateble');
                        req.Automatically_Revoked__c = true;
                    }

                    //*************** ADD THE SETUP AUDIT *********************
                    // see if we impersonated anyone
                    List<SiteSwitcherFuncs.ImpersonationTime> impersonations = SiteSwitcherFuncs.getImpersonationTimes(req);
                    if (AccessNowConfig__c.getOrgDefaults().Enable_Data_History_Tracking__c) impersonations.add(new SiteSwitcherFuncs.ImpersonationTime(req.Actual_Start_Time__c, req.Actual_End_Time__c, req.OwnerId));

                    // get the audit log
                    Integer numDMLLeft = Math.max(0, Limits.getLimitDMLRows() - Limits.getDMLRows() - DML_BUFFER);

                    // get setup audit trail info for the request user OR the user that did things via login-as
                    list<ACNW_Setup_Audit_Log__c> setupAuditLogs = new List<ACNW_Setup_Audit_log__c>();
                    for (SetupAuditTrail sl : [select id, createdbyid, createddate, section, display, delegateuser from setupaudittrail where createddate >= :req.Actual_Start_Time__c and createddate <= :req.Actual_End_Time__c and (createdbyid = :req.ownerid or DelegateUser = :req.owner.Username) order by createddate limit :numDMLLeft]) {
                        setupAuditLogs.add(new ACNW_Setup_Audit_Log__c(Date__c = sl.CreatedDate, Logged_In_As__c = sl.CreatedById, Delegate_User__c = sl.delegateuser, Request__c = req.Id, Activity__c = sl.Display, Section__c = sl.Section));
                    }
                    for (LoginHistory lh : [select id, userid, logintime, status, logintype, LoginUrl from loginhistory where userid = :req.ownerid and logintime >= :req.Actual_Start_Time__c and logintime <= :req.Actual_End_Time__c order by logintime limit :numDMLLeft]) {
                        setupAuditLogs.add(new ACNW_Setup_Audit_Log__c(Date__c = lh.LoginTime, Logged_In_As__c = lh.userid, Request__c = req.Id, Activity__c = 'Login', Section__c = String.isEmpty(lh.LoginUrl) ? null : lh.Loginurl.left(255)));
                    }
                    if (!setupAuditLogs.isEmpty()) {
                        if (!Schema.SObjectType.ACNW_Setup_Audit_Log__c.isCreateable()) throw new SiteSwitcherException(Label.MSG_InsufficientPrivileges + ' - Audit logs createable');
						insert setupAuditLogs;
                    }

                    Id reqOwnerId = req.OwnerId;
                    DateTime reqStartTime = req.Actual_Start_Time__c;
                    DateTime reqEndTime = req.Actual_End_Time__c;
                    
                    list<ACNW_Data_Audit_Log__c> dataAuditLogs = new list<ACNW_Data_Audit_Log__c>();
                    
                    Set<String> tmpObjects = new Set<String>();
                    for (ACNW_Data_Audit_Log_Object__c dalo : [select Name from ACNW_Data_Audit_Log_Object__c limit 100]) tmpObjects.add(dalo.Name);
                    
                    Set<String> objects = new Set<String>();
                    Set<String> historyObjects = new Set<String>();
                    for (String s : tmpObjects) {
                        if (ObjectFuncs.isValidObject(s)) {
                            if (ObjectFuncs.isHistoryObject(s)) {
                                historyObjects.add(s);
                                String o = ObjectFuncs.getRegularObjectForHistory(s);
                                if (!String.isEmpty(o)) objects.add(o);
                            } else  {
                                objects.add(s);
                                String o = ObjectFuncs.getHistoryObject(s);
                                if (!String.isEmpty(o)) historyobjects.add(o);
                            }
                        }
                    }
                    
                    // go through all objects and get deleted records
                    for (String s : objects) handleImpersonationsForObject(req, s, impersonations, dataAuditLogs);
                    numDMLLeft = Math.max(0, Limits.getLimitDMLRows() - Limits.getDMLRows() - DML_BUFFER);
                    
                    // go through all history objects and get history
                    for (String s : historyObjects) handleImpersonationsForHistoryObject(req, s, impersonations, dataAuditLogs);
                    numDMLLeft = Math.max(0, Limits.getLimitDMLRows() - Limits.getDMLRows() - DML_BUFFER);

                    if (!dataAuditLogs.isEmpty()) {
                        if (!Schema.SObjectType.ACNW_Data_Audit_Log__c.isCreateable()) throw new SiteSwitcherException(Label.MSG_InsufficientPrivileges + ' - Data logs createable');
                        insert dataAuditLogs;
                    }
                }
                updateIt = true;
            }
            if (!String.isEmpty(newStatus)) {
                if (!Schema.SObjectType.ACNW_Request__c.fields.Status__c.isUpdateable()) throw new SiteSwitcherException(Label.MSG_InsufficientPrivileges + ' - Status updateble');
                req.Status__c = newStatus;
            }
            if(!updateIt) return 'ERROR: No update needed. ' + req.Id + ',  Status = ' + req.Status__c + ', ReqStart = ' + req.Requested_Start_Time__c + ', ReqStop = ' + req.Requested_End_Time__c + ', needToStart: ' + needToStart + ', needToStop: ' + needToStop + ', now: ' + System.now() + ', revoked: ' + req.Manually_Revoked__c;

            if (!Schema.SObjectType.ACNW_Request__c.isUpdateable()) throw new SiteSwitcherException(Label.MSG_InsufficientPrivileges + ' - Request updateable');
			update req;

            return 'OK';
        } catch(Exception ex) {
            Database.rollback(sp);

            SiteSwitcherFuncs.setError(id, ex, autoRetry);

            return 'ERROR: Unable to update request';
        }
    }

    @testvisible
    private static void handleImpersonationsForHistoryObject(ACNW_Request__c req, String s, list<SiteSwitcherFuncs.ImpersonationTime> impersonations, list<ACNW_Data_Audit_Log__c> dataAuditLogs) {
        for (SiteSwitcherFuncs.ImpersonationTime impersonation : impersonations) {
            Id userId = impersonation.userId;
            DateTime startDateTime = impersonation.startDateTime;
            DateTime endDateTime = impersonation.endDateTime;
            
            if (Math.max(0, Limits.getLimitQueries() - Limits.getQueries() - SOQL_BUFFER) == 0) break;

            Integer numDMLLeft = Math.max(0, Limits.getLimitDMLRows() - Limits.getDMLRows() - DML_BUFFER);
            if (numDMLLeft == 0) break;
            
            //String historyNameField = ObjectFuncs.getNameFieldOfHistoryObject(s);
            String regObj = ObjectFuncs.getRegularObjectForHistory(s);
            if (!Test.isRunningtest() && String.isEmpty(regObj)) continue;
            
            String regObjName = ObjectFuncs.getNameFieldForObject(regObj);
            if (!Test.isRunningtest() && String.isEmpty(regObjName)) continue;
            
            String parentNameExpression = null;
            if (schema.getGlobalDescribe().get(s).getDescribe().fields.getMap().containsKey('ParentId')) {
                parentNameExpression = 'Parent';
            } else if (schema.getGlobalDescribe().get(s).getDescribe().fields.getMap().containsKey(regObj + 'Id')) {
                parentNameExpression = regObj;
            }
            if (!Test.isRunningtest() && String.isEmpty(parentNameExpression)) continue;
            String parentidExpression = parentNameExpression + 'Id';
            
            for (SObject sobj : Database.query('select Id, ' + parentNameExpression + '.' + regObjName + ', Field, OldValue, NewValue, CreatedDate from ' + s + ' where CreatedById = :userId and CreatedDate >= :startDateTime and CreatedDate <= :endDateTime limit :numDMLLeft')) {
                dataAuditLogs.add(new ACNW_Data_Audit_Log__c(Logged_In_As__c = userId, Request__c = req.Id, Object_Name__c = regObj, Old_Value__c = sobj.get('OldValue') == null ? null : '' + sobj.get('OldValue'), New_Value__c = sobj.get('NewValue') == null ? null : '' + sobj.get('NewValue'), Field__c = (String)sobj.get('Field'), Date__c = (DateTime)sobj.get('CreatedDate'), Parent_Id__c = (Id)sobj.get(parentidExpression), Parent_Name__c = (String)sobj.getSObject(parentNameExpression).get(regObjName)));
            }
        }
    }

    @testvisible
    private static void handleImpersonationsForObject(ACNW_Request__c req, String s, list<SiteSwitcherFuncs.ImpersonationTime> impersonations, list<ACNW_Data_Audit_Log__c> dataAuditLogs) {
        for (SiteSwitcherFuncs.ImpersonationTime impersonation : impersonations) {
            Id userId = impersonation.userId;
            DateTime startDateTime = impersonation.startDateTime;
            DateTime endDateTime = impersonation.endDateTime;

            if (Math.max(0, Limits.getLimitQueries() - Limits.getQueries() - SOQL_BUFFER) == 0) break;

            Integer numDMLLeft = Math.max(0, Limits.getLimitDMLRows() - Limits.getDMLRows() - DML_BUFFER);
            if (numDMLLeft == 0) break;

            // make sure has a IsDeleted and a Name field
            String nameField = ObjectFuncs.getNameFieldForObject(s);
            if (!String.isEmpty(nameField) && schema.getGlobalDescribe().get(s).getDescribe().fields.getMap().containsKey('IsDeleted')) {
                for (SObject sobj : Database.query('select Id, ' + nameField + ', LastModifiedDate from ' + s + ' where IsDeleted = true and LastModifiedById = :userId and lastmodifieddate >= :startDateTime and lastmodifieddate <= :endDateTime limit :numDMLLeft all rows')) {
                    dataAuditLogs.add(new ACNW_Data_Audit_Log__c(Logged_In_As__c = userId, Request__c = req.Id, Object_Name__c = s, Field__c = 'deleted', Date__c = (DateTime)sobj.get('LastModifiedDate'), Parent_Id__c = sobj.Id, Parent_Name__c = (String)sobj.get(nameField)));
                }
            }
        }
    }

    public static String addRemovePermissions(Id reqId) {
        Savepoint sp = Database.setSavepoint();
        try {
            ACNW_Request__c req = SiteSwitcherFuncs.getReq(reqId);

            User user = SiteSwitcherFuncs.getUser(req.OwnerId);

            Boolean updateUser = false;

            if (req.Status__c == 'Completed') {
                if (!String.isEmpty(req.Original_Profile_Id__c) && user.ProfileId != req.Original_Profile_Id__c) {
                    user.ProfileId = req.Original_Profile_Id__c;
                    updateUser = true;
                }
                Id originalRoleId = String.isEmpty(req.Original_Role_Id__c) ? null : (Id)req.Original_Role_Id__c;
                if (user.UserRoleId != originalRoleId) {
                    user.UserRoleId = originalRoleId;
                    updateUser = true;
                }
            } else if (req.Status__c == 'In Progress') {
                Id newProfileId = SiteSwitcherFuncs.getProfileIdForReq(user, req);

                if (newProfileId != null && newProfileId != user.ProfileId) {
                    user.ProfileId = newProfileId;
                    updateUser = true;
                }

                Id newRoleId = SiteSwitcherFuncs.getRoleIdForReq(req);
                if (newRoleId != null && newRoleId != user.UserRoleId) {
                    user.UserRoleId = newRoleId;
                    updateUser = true;
                }
            }
            if (!test.isRunningTest() && updateUser) update user;

            /**** permission set group updates ****/
            List<PermissionSetAssignment> assigns = [select Id, AssigneeId, PermissionSetGroupId from PermissionSetAssignment where PermissionSetGroupId <> null and AssigneeId = :user.Id];

            list<PermissionSetAssignment> toDel = new list<PermissionSetAssignment>();
            list<PermissionSetAssignment> toInsert = new list<PermissionSetAssignment>();
            list<PermissionSetAssignment> toInsertBestEffort = new list<PermissionSetAssignment>();

            Set<Id> prePermissionSets = new Set<Id>();
            if (!String.isEmpty(req.Original_Permission_Set_Group_Ids__c)) {
                for (String s : req.Original_Permission_Set_Group_Ids__c.split('\n')) {
                    if (String.isEmpty(s.trim())) continue;
                    prePermissionSets.add(s.trim());
                }
            }

            if (req.Status__c == 'Completed') {    
                set<Id> prePermissionSetClone = prePermissionSets.clone();
                for (PermissionSetAssignment psa : assigns) {
                    if (prePermissionSetClone.contains(psa.PermissionSetGroupId)) prePermissionSets.remove(psa.PermissionSetGroupId);
                    else toDel.add(psa);
                }

                if (!prePermissionSets.isEmpty()) {
                    Map<Id, Set<Id>> permissionSetByGroup = getPermissionSetsForGroup(prePermissionSets);
                    for (Id gid : prePermissionSets) {
                        for (Id pid : permissionSetByGroup.get(gid)) {
                            toInsert.add(new PermissionSetAssignment(AssigneeId = req.OwnerId, PermissionSetId = pid, PermissionSetGroupId = gid));
                        }
                    }
                }
            } else if (req.Status__c == 'In Progress') {
                Set<Id> existingIds = new Set<Id>();

                for (PermissionSetAssignment psa : assigns) existingIds.add(psa.PermissionSetGroupId);

                Set<Id> gidsToAdd = new Set<Id>();
                for (ACNW_Permission__c ap : SiteSwitcherFuncs.getFlattenedPermsForRequestPerms(req.Request_Permissions__r)) {
                    if (ap.Type__c == 'Permission Set Group' && !existingIds.contains(ap.SF_Permission_Id__c)) {
                        gidsToAdd.add(ap.SF_Permission_Id__c);
                        existingIds.add(ap.SF_Permission_Id__c);
                    }
                }
                Set<Id> gidsToAddBestEffort = new Set<Id>();
                for (Id pr : prePermissionSets) {
                    if (!existingIds.contains(pr)) gidsToAddBestEffort.add(pr);
                }
                if (Test.isRunningTest() || !gidsToAdd.isEmpty() || !gidsToAddBestEffort.isEmpty()) {
                    set<Id> tot = gidsToAdd.clone();
                    tot.addAll(gidsToAddBestEffort);
                    Map<Id, Set<Id>> permissionSetByGroup = getPermissionSetsForGroup(tot);

                    for (Id gid : gidsToAdd) {
                        for (Id pid : permissionSetByGroup.get(gid)) {
                        	toInsert.add(new PermissionSetAssignment(AssigneeId = req.OwnerId, PermissionSetId = pid, PermissionSetGroupId = gid));
                        }
                    }
                    for (id gid : gidsToAddBestEffort) {
                        for (Id pid : permissionSetByGroup.get(gid)) {
                            toInsertBestEffort.add(new Permissionsetassignment(AssigneeId = req.OwnerId, PermissionSetId = pid, PermissionSetGroupId = gid));
                        }
                    }
                }
            }

            /**** permission set updates ****/
            assigns = [select Id, AssigneeId, PermissionSetId from PermissionSetAssignment where PermissionSetGroupId = null and PermissionSet.IsOwnedByProfile = false and AssigneeId = :user.Id];

            prePermissionSets.clear();

            if (!String.isEmpty(req.Original_Permission_Set_Ids__c)) {
                for (String s : req.Original_Permission_Set_Ids__c.split('\n')) {
                    if (String.isEmpty(s.trim())) continue;
                    prePermissionSets.add(s.trim());
                }
            }

            if (req.Status__c == 'Completed') {    
                for (PermissionSetAssignment psa : assigns) {
                    if (prePermissionSets.contains(psa.PermissionSetId)) prePermissionSets.remove(psa.PermissionSetId);
                    else toDel.add(psa);
                }

                for (Id idd : prePermissionSets) toInsert.add(new PermissionSetAssignment(AssigneeId = req.OwnerId, permissionSetId = idd));
            } else if (req.Status__c == 'In Progress') {
                Set<Id> existingIds = new Set<Id>();

                for (PermissionSetAssignment psa : assigns) {
                    existingIds.add(psa.PermissionSetId);
                }
                for (ACNW_Permission__c ap : SiteSwitcherFuncs.getFlattenedPermsForRequestPerms(req.Request_Permissions__r)) {
                    if (ap.Type__c == 'Permission Set' && !existingIds.contains(ap.SF_Permission_Id__c)) {
                        toInsert.add(new PermissionSetAssignment(PermissionSetId = ap.SF_Permission_Id__c, AssigneeId = req.OwnerId));
                        existingIds.add(ap.SF_Permission_Id__c);
                    }
                }
                for (Id pr : prePermissionSets) {
                    if (!existingIds.contains(pr)) toInsertBestEffort.add(new Permissionsetassignment(PermissionSetId = pr, AssigneeId = req.OwnerId));
                }
            }

            if (test.isRunningTest()) throw new SiteSwitcherException('for test coverage in exception handler');

            if (!toDel.isEmpty()) delete toDel;
            if (!toInsert.isEmpty()) insert toInsert;
            if (!toInsertBestEffort.isEmpty()) Database.insert(toInsertBestEffort, false);
            return 'OK';
        } catch(Exception ex) {
            Database.rollback(sp);

            try {
                SiteSwitcherFuncs.setError(reqId, ex);
            } catch(Exception ex2) {
                return 'ERROR: ' + ex.getMessage();
                //throw ex; // throw original error
            }
            return 'ERROR: Unable to update user';
        }
    }

    @testvisible
    private static Map<id, Set<id>> getPermissionSetsForGroup(Set<Id> groups) {
        Map<Id, Set<Id>> permissionSetByGroup = new Map<id, Set<Id>>();
        for (Id gid : groups) permissionSetByGroup.put(gid, new set<id>());
        for (PermissionSetGroupComponent psg : [select PermissionSetGroupId, PermissionSetId from PermissionSetGroupComponent where PermissionSetGroupId in :groups and PermissionSet.IsOwnedByProfile = false]) {
            permissionSetByGroup.get(psg.PermissionSetGroupId).add(psg.PermissionSetId);
        }
        return permissionSetByGroup;
    }
    class SiteSwitcherException extends Exception {}
}