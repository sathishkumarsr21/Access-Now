public with sharing class AccessNowRequestController {
    public ACNW_Request__c req { get; set; }
    public List<PermissionWrapper> accessNowPermGroups { get; private set; }
    public List<PermissionWrapper> perms { get; private set; }
    public List<PermissionWrapper> permGroups { get; private set; }
    public List<PermissionWrapper> profiles { get; private set; }
    public List<PermissionWrapper> roles { get; private set; }

    public List<ACNW_Setup_Audit_Log__c> setupAuditLog { get {
        List<ACNW_Setup_Audit_Log__c> ret = new List<ACNW_Setup_Audit_Log__c>();
        if (req != null &&
            Schema.SObjectType.ACNW_Setup_Audit_Log__c.isAccessible() &&
            Schema.SObjectType.ACNW_Setup_Audit_Log__c.fields.Id.isAccessible() &&
            Schema.SObjectType.ACNW_Setup_Audit_Log__c.fields.Name.isAccessible() &&
            Schema.SObjectType.ACNW_Setup_Audit_Log__c.fields.Activity__c.isAccessible() &&
            Schema.SObjectType.ACNW_Setup_Audit_Log__c.fields.CreatedById.isAccessible() &&
            Schema.SObjectType.ACNW_Setup_Audit_Log__c.fields.Logged_In_As__c.isAccessible() &&
            Schema.SObjectType.ACNW_Setup_Audit_Log__c.fields.Section__c.isAccessible() &&
            Schema.SObjectType.ACNW_Setup_Audit_Log__c.fields.Date__c.isAccessible() &&
            Schema.SObjectType.ACNW_Setup_Audit_Log__c.fields.Request__c.isAccessible()
           ) {
            ret = [select Id, Name, Activity__c, CreatedBy.Name, Logged_In_As__r.Name, Section__c, Date__c from ACNW_Setup_Audit_Log__c where Request__c = :req.Id order by Date__c asc limit 200];
        }
        return ret;
    } }

    public List<ACNW_Data_Audit_Log__c> dataAuditLog { get {
        List<ACNW_Data_Audit_Log__c> ret = new List<ACNW_Data_Audit_Log__c>();
        if (Schema.SObjectType.ACNW_Data_Audit_Log__c.isAccessible() &&
            Schema.SObjectType.ACNW_Data_Audit_Log__c.fields.Id.isAccessible() &&
            Schema.SObjectType.ACNW_Data_Audit_Log__c.fields.Name.isAccessible() &&
            Schema.SObjectType.ACNW_Data_Audit_Log__c.fields.Logged_In_As__c.isAccessible() &&
            Schema.SObjectType.ACNW_Data_Audit_Log__c.fields.Parent_Name__c.isAccessible() &&
            Schema.SObjectType.ACNW_Data_Audit_Log__c.fields.Parent_Id__c.isAccessible() &&
            Schema.SObjectType.ACNW_Data_Audit_Log__c.fields.Object_Name__c.isAccessible() &&
            Schema.SObjectType.ACNW_Data_Audit_Log__c.fields.Date__c.isAccessible() &&
            Schema.SObjectType.ACNW_Data_Audit_Log__c.fields.Field__c.isAccessible() &&
            Schema.SObjectType.ACNW_Data_Audit_Log__c.fields.Old_Value__c.isAccessible() &&
            Schema.SObjectType.ACNW_Data_Audit_Log__c.fields.New_Value__c.isAccessible() &&
            Schema.SObjectType.ACNW_Data_Audit_Log__c.fields.Request__c.isAccessible()
          ) {
            ret = [select Id, Name, Logged_In_As__r.Name, Parent_Name__c, Parent_Id__c, Object_Name__c, Date__c, Field__c, Old_Value__c, New_Value__c from ACNW_Data_Audit_Log__c where Request__c = :req.Id order by Date__c asc, Parent_Id__c limit 200];
        }
        return ret;
    } }

    public Boolean allowSave { get {
        return req.Id == null || req.Status__c == 'Draft';
    } }
    public Boolean allowCancel { get {
        return req.Id != null && req.Status__c == 'Draft';
    } }
    public Boolean allowRetry { get {
        return req.Status__c == 'Error' && (SiteSwitcherFuncs.needToStart(req) || SiteSwitcherFuncs.needToStop(req));
    } }
    public Boolean allowRevoke { get {
        return (req.status__c == 'Approved' || req.Status__c == 'In Progress') && !req.Manually_Revoked__c;
    } }
    public Boolean allowSubmitForApproval { get {
        return req.Status__c == 'Draft';
    } }
    public AccessNowRequestController(ApexPages.StandardController std) {
        try {
            Id idd = std.getRecord().Id;
            loadRec(idd);
        } catch(Exception ex) {
            ApexPages.addMessage(new ApexPages.Message(ApexPages.Severity.Error, ex.getMessage() + ' - ' + ex.getLineNumber()));
        }
    }
    private void loadRec(Id idd) {
        Id userId = UserInfo.getUserId();
        if (idd == null) {
            req = new ACNW_Request__c();
            if (Schema.SObjectType.ACNW_Request__c.fields.OwnerId.isCreateable() && Schema.SObjectType.ACNW_Request__c.fields.OwnerId.isUpdateable()) {
            	req.OwnerId = UserInfo.getUserId();
            }
            if (Schema.SObjectType.ACNW_Request__c.fields.Status__c.isCreateable() && Schema.SObjectType.ACNW_Request__c.fields.Status__c.isUpdateable()) {
                req.Status__c = 'Draft';
            } else {
                throw new AccessNowException(Label.MSG_InsufficientPrivileges + ' - Request status updateable');
            }
            if (Schema.SObjectType.ACNW_Request__c.fields.Request_on_Behalf_Of__c.isCreateable() && Schema.SObjectType.ACNW_Request__c.fields.Request_on_Behalf_Of__c.isUpdateable()) {
                req.Request_on_Behalf_Of__c = UserInfo.getUserId();
            } else {
                throw new AccessNowException(Label.MSG_InsufficientPrivileges + ' - Request on Behalf of createable');
            }

            Boolean hasStartDate = false;
            // if not showing start date in fieldset, set provision immediately to true by default
            for (Schema.FieldsetMember fsm : Schema.SObjectType.ACNW_Request__c.fieldSets.getMap().get('accessnow__Request_Form_Fields').getFields()) {
                if (fsm.getFieldPath() == 'accessnow__Requested_Start_Time__c') {
                    hasStartDate = true;
                    break;
                }
            }
            if (!hasStartDate) {
                if (Schema.SObjectType.ACNW_Request__c.fields.accessnow__Provision_Immediately__c.isCreateable() && Schema.SObjectType.ACNW_Request__c.fields.accessnow__Provision_Immediately__c.isUpdateable()) {
                    req.accessnow__Provision_Immediately__c = true;
                } else {
                    throw new AccessNowException(Label.MSG_InsufficientPrivileges + ' - Request provision immediately updateable');
                }
            }
        } else {
            if (Schema.SObjectType.ACNW_Request__c.isAccessible() &&
                Schema.SObjectType.ACNW_Request__c.fields.Request_on_Behalf_Of__c.isAccessible() &&
                Schema.SObjectType.ACNW_Request__c.fields.Admin_Page__c.isAccessible() &&
                Schema.SObjectType.ACNW_Request__c.fields.OwnerId.isAccessible() &&
                Schema.SObjectType.ACNW_Request__c.fields.Status__c.isAccessible() &&
                Schema.SObjectType.ACNW_Request__c.fields.Duration_Hours__c.isAccessible() &&
                Schema.SObjectType.ACNW_Request__c.fields.Provision_Immediately__c.isAccessible() &&
                Schema.SObjectType.ACNW_Request__c.fields.Automatically_Revoked__c.isAccessible() &&
                Schema.SObjectType.ACNW_Request__c.fields.Actual_Start_Time__c.isAccessible() &&
                Schema.SObjectType.ACNW_Request__c.fields.Actual_End_Time__c.isAccessible() &&
                Schema.SObjectType.ACNW_Request__c.fields.Reference_Number__c.isAccessible() &&
                Schema.SObjectType.ACNW_Request__c.fields.Approved_On__c.isAccessible() &&
                Schema.SObjectType.ACNW_Request__c.fields.Requested_Start_Time__c.isAccessible() &&
                Schema.SObjectType.ACNW_Request__c.fields.Requested_End_Time__c.isAccessible() &&
                Schema.SObjectType.ACNW_Request__c.fields.Last_Error__c.isAccessible() &&
                Schema.SObjectType.ACNW_Request__c.fields.Reason_for_Escalation__c.isAccessible()
            ) {

                Set<String> fields = new Set<String>();
    			Map<String, SObjectField> fieldsDef = ACNW_Request__c.sobjecttype.getDescribe().fields.getMap();
                for (Schema.FieldsetMember fsm : Schema.SObjectType.ACNW_Request__c.fieldSets.getMap().get('accessnow__Request_Form_Fields').getFields()) {
                    if (fieldsDef.get(fsm.getFieldPath()).getDescribe().isAccessible()) fields.add(fsm.getFieldPath().toLowerCase());
                }
                fields.add(('' + ACNW_Request__c.Request_on_Behalf_Of__c).toLowerCase());
                fields.add(('' + ACNW_Request__c.Admin_Page__c).toLowerCase());
                fields.add(('' + ACNW_Request__c.OwnerId).toLowerCase());
                fields.add(('' + ACNW_Request__c.Id).toLowerCase());
                fields.add(('' + ACNW_Request__c.Name).toLowerCase());
                fields.add(('' + ACNW_Request__c.CreatedDate).toLowerCase());
                fields.add(('' + ACNW_Request__c.CreatedById).toLowerCase());
                fields.add(('' + ACNW_Request__c.LastModifiedDate).toLowerCase());
                fields.add(('' + ACNW_Request__c.LastModifiedById).toLowerCase());
                fields.add(('' + ACNW_Request__c.Status__c).toLowerCase());
                fields.add(('' + ACNW_Request__c.Duration_Hours__c).toLowerCase());
                fields.add(('' + ACNW_Request__c.Provision_Immediately__c).toLowerCase());
                fields.add(('' + ACNW_Request__c.Automatically_Revoked__c).toLowerCase());
                fields.add(('' + ACNW_Request__c.Manually_Revoked__c).toLowerCase());
                fields.add(('' + ACNW_Request__c.Actual_Start_Time__c).toLowerCase());
                fields.add(('' + ACNW_Request__c.Actual_End_Time__c).toLowerCase());
                fields.add(('' + ACNW_Request__c.Reference_Number__c).toLowerCase());
                fields.add(('' + ACNW_Request__c.Approved_On__c).toLowerCase());
                fields.add(('' + ACNW_Request__c.Requested_Start_Time__c).toLowerCase());
                fields.add(('' + ACNW_Request__c.Requested_End_Time__c).toLowerCase());
                fields.add(('' + ACNW_Request__c.Reason_for_Escalation__c).toLowerCase());
                fields.add(('' + ACNW_Request__c.Last_Error__c).toLowerCase());

                req = (ACNW_Request__c)Database.query('select (select Id, User_Permission__c from Request_Permissions__r), ' + String.join(new List<String>(fields), ',') + ' from ACNW_Request__c where Id = :idd');
                userId = req.OwnerId;
            }
        }

        reloadUserPerms();

        if (req.Id != null) {
            for (ACNW_Request_Permission__c p : req.Request_Permissions__r) {
                checkPerms(p, accessNowPermGroups);
                checkPerms(p, permGroups);
                checkPerms(p, perms);
                checkPerms(p, profiles);
                checkPerms(p, roles);
            }
        }

        if (!allowSave) {
            // remove all that don't have checked = true
            removeUnchecked(accessNowPermGroups);
            removeUnchecked(perms);
            removeUnchecked(permGroups);
            removeUnchecked(profiles);
            removeUnchecked(roles);
        }

        if (accessNowPermGroups.isEmpty()) accessNowPermGroups = null;
        if (permGroups.isEmpty()) permGroups = null;
        if (perms.isEmpty()) perms = null;
        if (profiles.isEmpty()) profiles = null;
        if (roles.isEmpty()) roles = null;
    }
    @testvisible
    private void removeUnchecked(List<PermissionWrapper> perms) {
        for (Integer i = perms.size() - 1; i >= 0; i--) {
            if (!perms.get(i).checked) perms.remove(i);
        }
    }
    @testvisible
    private void checkPerms(ACNW_Request_Permission__c p, List<PermissionWrapper> perms) {
        for (PermissionWrapper pw : perms) {
            if (p.User_Permission__c == pw.perm.Id) {
                pw.checked = true;
            }
        }
    }
    public void reloadUserPermsFunc() {
        if (Schema.SObjectType.ACNW_Request__c.isUpdateable() && Schema.SObjectType.ACNW_Request__c.fields.OwnerId.isUpdateable() && Schema.SObjectType.ACNW_Request__c.fields.Request_on_Behalf_Of__c.isUpdateable()) {
            req.Request_on_Behalf_Of__c = ApexPages.currentPage().getParameters().get('idd');
    	    req.OwnerId = req.Request_on_Behalf_Of__c;
        	reloadUserPerms();
        }
    }
    private void reloadUserPerms() {
        Id userId = req.OwnerId;
        accessNowPermGroups = new List<PermissionWrapper>();
        permGroups = new List<PermissionWrapper>();
        perms = new List<PermissionWrapper>();
        profiles = new List<PermissionWrapper>();
        roles = new List<PermissionWrapper>();
        //if (Schema.SObjectType.User_Permission__c.isAccessible() &&
        //    Schema.SObjectType.User_Permission__c.fields.Permission__c.isAccessible() &&
        //    Schema.SObjectType.User_Permission__c.fields.User__c.isAccessible()
        //    ) {
            for (ACNW_User_Permission__c perm : [select Id, Permission__r.Name__c, Permission__r.Type__c from ACNW_User_Permission__c where User__c = :userId order by Permission__r.Name limit 1000]) {
                if (perm.Permission__r.Type__c == 'Permission Bundles') accessNowPermGroups.add(new PermissionWrapper(perm));
                else if (perm.Permission__r.Type__c == 'Permission Set Group') permGroups.add(new PermissionWrapper(perm));
                else if (perm.Permission__r.Type__c == 'Permission Set') perms.add(new PermissionWrapper(perm));
                else if (perm.Permission__r.Type__c == 'Profile') profiles.add(new PermissionWrapper(perm));
                else if (perm.Permission__r.Type__c == 'Role') roles.add(new PermissionWrapper(perm));
            }
        //}
        if (allowSave && perms.isEmpty() && profiles.isEmpty() && roles.isEmpty() && permGroups.isEmpty() && accessNowPermGroups.isEmpty()) {
            Apexpages.addMessage(new ApexPages.Message(ApexPages.Severity.Error, Label.ERR_NoPermissionsAvailable));
        }
    }
    private PageReference getViewPage() {
        PageReference detPage = new ApexPages.StandardController(req).view();
        detPage.setRedirect(true);
        return detPage;
    }
    public PageReference save() {
        Savepoint sp = Database.setSavepoint();
        boolean newRec = req.Id == null;
        try {
            saveOnly();

            if (newRec) {
                return getViewPage();
            } else {
                loadRec(req.Id);
                ApexPages.addMessage(new ApexPages.Message(ApexPages.Severity.Confirm, Label.MSG_RequestUpdated));
                return null;
            }
        } catch(Exception ex) {
            if (newRec) req.Id = null;
            Database.rollback(sp);
            ApexPages.addMessages(ex);
            if (Test.isRunningTest()) throw ex;
            return null;
        }
    }
    private void saveOnly() {
        if (req.Requested_Start_Time__c != null && !req.Provision_Immediately__c) {
            if (req.Requested_Start_Time__c < System.now()) {
                throw new AccessNowException(Label.ERR_RequestMustBeForTheFuture);
            }
        }

        if (req.Id == null) {
            if (Schema.SObjectType.ACNW_Request__c.isCreateable()) insert req;
            else throw new AccessNowException(Label.MSG_InsufficientPrivileges + ' - Request insertable');
        } else {
            if (Schema.SObjectType.ACNW_Request__c.isUpdateable()) update req;
            else throw new AccessNowException(Label.MSG_InsufficientPrivileges + ' - Request updateable');
        }

        Map<Id, ACNW_Request_Permission__c> existingPerms = new Map<Id, ACNW_Request_Permission__c>();
        for (ACNW_Request_Permission__c rp : [select Id, User_Permission__c from ACNW_Request_Permission__c where Request__c = :req.Id]) {
            existingPerms.put(rp.User_Permission__c, rp);
        }

        List<ACNW_Request_Permission__c> rps = new List<ACNW_Request_Permission__c>();
        Integer numRolesSelected = 0;
        Integer numPermissionSetsSelected = 0;
        Integer numPermissionGroupsSelected = 0;
        Integer numProfilesSelected = 0;

        /******************/
        Map<Id, List<ACNW_Permission__c>> accessNowGroupPerms = new Map<Id, List<ACNW_Permission__c>>();
        if (accessNowPermGroups != null) {
            for (PermissionWrapper pw : accessNowPermGroups) {
                if (pw.checked) {
                    accessNowGroupPerms.put(pw.perm.Id, null);
                    if (existingPerms.remove(pw.perm.Id) == null) rps.add(new ACNW_Request_Permission__c(User_Permission__c = pw.perm.Id, Request__c = req.Id));
                }
            }
        }
        if (!accessNowGroupPerms.isEmpty()) {
            accessNowGroupPerms = SiteSwitcherFuncs.getPermsForAccessNowPermissionGroup(accessNowGroupPerms.keySet());
            for (Id idx : accessNowGroupPerms.keySet()) {
                for (ACNW_Permission__c apw : accessNowGroupPerms.get(idx)) {
                    if (apw.Type__c == 'Role') numRolesSelected++;
                    else if (apw.Type__c == 'Permission Set Group') numPermissionGroupsSelected++;
                    else if (apw.Type__c == 'Permission Set') numPermissionSetsSelected++;
                    else if (apw.Type__c == 'Profile') numProfilesSelected++;
                }
            }
        }
        /*******************/

        if (perms != null) {
            for (PermissionWrapper pw : perms) {
                if (pw.checked) {
                    numPermissionSetsSelected++;
                    if (existingPerms.remove(pw.perm.Id) == null) rps.add(new ACNW_Request_Permission__c(User_Permission__c = pw.perm.Id, Request__c = req.Id));
                }
            }
        }

        if (permGroups != null) {
            for (PermissionWrapper pw : permGroups) {
                if (pw.checked) {
                    numPermissionGroupsSelected++;
                    if (existingPerms.remove(pw.perm.Id) == null) rps.add(new ACNW_Request_Permission__c(User_Permission__c = pw.perm.Id, Request__c = req.Id));
                }
            }
        }

        if (profiles != null) {
            for (PermissionWrapper pw : profiles) {
                if (pw.checked) {
                    numProfilesSelected++;
                    if (existingPerms.remove(pw.perm.Id) == null) rps.add(new ACNW_Request_Permission__c(User_Permission__c = pw.perm.Id, Request__c = req.Id));
                }
            }
        }

        if (roles != null) {
            for (PermissionWrapper pw : roles) {
                if (pw.checked) {
                    numRolesSelected++;
                    if (existingPerms.remove(pw.perm.Id) == null) rps.add(new ACNW_Request_Permission__c(User_Permission__c = pw.perm.Id, Request__c = req.Id));
                }
            }
        }

        if (numProfilesSelected > 1 || (numProfilesSelected > 0 && (numPermissionSetsSelected > 0 || numPermissionGroupsSelected > 0))) throw new AccessNowException(Label.MSG_ProfileOrPermissionSet);
        if (numRolesSelected > 1) throw new AccessNowException(Label.MSG_OnlyOneRole);

        if (!existingPerms.isEmpty()) {
            if (Schema.SObjectType.ACNW_Request_Permission__c.isDeletable()) {
                delete existingPerms.values();
            } else {
                throw new AccessNowException(Label.MSG_InsufficientPrivileges + ' - Request permission deletable');
            }
        }
        if (!rps.isEmpty()) {
            if (Schema.SObjectType.ACNW_Request_Permission__c.isCreateable()) {
                insert rps;
            } else {
                throw new AccessNowException(Label.MSG_InsufficientPrivileges + ' - Request permission createable');
            }
        }
    }
    public PageReference submitForApproval() {
        Savepoint sp = Database.setSavepoint();
        boolean newRec = req.Id == null;
        try {
            if (!allowSubmitForApproval) throw new AccessNowException(Label.ERR_RequestIsNotAvailableToSubmitForApproval);

            saveOnly();
            Id ownerId = [select OwnerId from ACNW_Request__c where Id = :req.Id].OwnerId;

            ACNW_Request__c exReq = SiteSwitcherFuncs.getRequestAlreadyInProgress(ownerId, req.Id);
            if (req.Provision_Immediately__c && exReq != null) {
                throw new AccessNowException(String.format(Label.ERR_AnotherRequestIsAlreadyInProgress, new String[] { exReq.Name }));
            }
            // make sure the profile checks out
            SiteSwitcherFuncs.getProfileIdForReq(SiteSwitcherFuncs.getUser(ownerId), SiteSwitcherFuncs.getReq(req.Id));

            if (Schema.SObjectType.ACNW_Request__c.isUpdateable() && Schema.SObjectType.ACNW_Request__c.fields.Status__c.isUpdateable()) {
                update new ACNW_request__c(id = req.id, status__c = 'Pending Approval');
            } else {
                throw new AccessNowException(Label.MSG_InsufficientPrivileges + ' - Request + Status updateable');
            }

            if (newRec) {
                return getViewPage();
            } else {
                loadRec(req.Id);
                ApexPages.addMessage(new ApexPages.Message(ApexPages.Severity.Confirm, Label.MSG_RequestSubmitted));
                return null;
            }
        } catch(Exception ex) {
            if (newRec) req.Id = null;
            Database.rollback(sp);
            ApexPages.addMessages(ex);
            if (Test.isRunningTest()) throw ex;
            return null;
        }
    }
    public void cancel() {
        Savepoint sp = Database.setSavepoint();
        String oldStatus = req.Status__c;
        try {
            if (Schema.SObjectType.ACNW_Request__c.fields.Status__c.isUpdateable()) {
                req.Status__c = 'Cancelled';
            } else {
                throw new AccessNowException(Label.MSG_InsufficientPrivileges + ' - Request status updateable');
            }

            if (Schema.SObjectType.ACNW_Request__c.isUpdateable()) {
                update req;
            } else {
                throw new AccessNowException(Label.MSG_InsufficientPrivileges + ' - Request updateable');
            }

            loadRec(req.Id);
            ApexPages.addMessage(new ApexPages.Message(ApexPages.Severity.Confirm, Label.MSG_RequestUpdated));
        } catch(Exception ex) {
            if (Schema.SObjectType.ACNW_Request__c.fields.Status__c.isUpdateable()) {
                req.Status__c = oldStatus;
            }
            Database.rollback(sp);
            ApexPages.addMessages(ex);
            if (Test.isRunningTest()) throw ex;
        }
    }
    public void revoke() {
        Savepoint sp = Database.setSavepoint();
        Boolean oldRevoked = req.Manually_Revoked__c;
        try {
            if (!allowRevoke) throw new AccessNowException(Label.ERR_RequestNotAvailableForManualRevoke);

            if (Schema.SObjectType.ACNW_Request__c.fields.Manually_Revoked__c.isUpdateable()) {
                req.Manually_Revoked__c = true;
            } else {
                throw new AccessNowException(Label.MSG_InsufficientPrivileges + ' - Request manually revoked updateable');
            }

            if (Schema.SObjectType.ACNW_Request__c.isUpdateable()) {
                update req;
            } else {
                throw new AccessNowException(Label.MSG_InsufficientPrivileges + ' - Request updateable');
            }

            loadRec(req.Id);
            ApexPages.addMessage(new ApexPages.Message(ApexPages.Severity.Info, Label.MSG_RequestSubmitted));
        } catch(Exception ex) {
            req.Manually_Revoked__c = oldRevoked;
            Database.rollback(sp);
            ApexPages.addMessages(ex);
            if (Test.isRunningTest()) throw ex;
        }
    }
    public void retry() {
        Savepoint sp = Database.setSavepoint();
        try {
            // just need to touch it
            if (Schema.SObjectType.ACNW_Request__c.fields.Last_Error__c.isUpdateable()) {
                req.Last_Error__c = null;
            } else {
                throw new AccessNowException(Label.MSG_InsufficientPrivileges + ' - Request last error updateable');
            }

            if (Schema.SObjectType.ACNW_Request__c.isUpdateable()) {
                update req;
            } else {
                throw new AccessNowException(Label.MSG_InsufficientPrivileges + ' - Request updateable');
            }

            loadRec(req.Id);
            ApexPages.addMessage(new ApexPages.Message(ApexPages.Severity.Info, Label.MSG_SubmittedForRetry));
        } catch(Exception ex) {
            Database.rollback(sp);
            ApexPages.addMessages(ex);
            if (Test.isRunningTest()) throw ex;
        }
    }
    public class PermissionWrapper {
        public Boolean checked { get; set; }
        public ACNW_User_Permission__c perm { get; private set; }
        public PermissionWrapper(ACNW_User_Permission__c perm) {
            this.perm = perm;
            this.checked = false;
        }
    }
    class AccessNowException extends Exception {}
}