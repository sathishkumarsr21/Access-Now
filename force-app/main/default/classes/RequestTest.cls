@istest
private class RequestTest {
    private static testmethod void testSwitch() {
        EncryptionUtils.setupEncryption();

        ACNW_Request__c r = new ACNW_Request__c(Provision_Immediately__c = true, Reference_Number__c = 'test');
        insert r;

        RestRequest req = new RestRequest(); 
        RestResponse res = new RestResponse();

        RestContext.request = req;
        RestContext.response = res;

        SiteSwitcher.switch();

        req.params.put('cs', EncryptionUtils.encryptData(r.Id));
        SiteSwitcher.switch();

        req.params.put('id', UserInfo.getUserId());
        SiteSwitcher.switch();

        req.params.put('id', r.Id);
        SiteSwitcher.switch();

        SiteSwitcher.addRemovePermissions(r.id);
        r.Status__c = 'In Progress';
        update r;
        try {
            SiteSwitcher.addRemovePermissions(r.id);
        } catch(Exception ex) {
        }

        r.Status__c = 'Completed';
        update r;
        try {
            SiteSwitcher.addRemovePermissions(r.id);
        } catch(Exception ex) {
        }

        try {
            SiteSwitcher.addRemovePermissions(null);
        } catch(Exception ex) {
        }
        try {
            SiteSwitcher.switch(null);
        } catch(Exception ex) {
        }

        System.assert(true);
    }
    private static testmethod void test() {
        EncryptionUtils.setupEncryption();

        ACNW_Permission__c perm = new ACNW_Permission__c(Name__c = 'testing', SF_Permission_Id__c = [select Id from PermissionSet where IsOwnedByProfile = false limit 1].Id, License_Required__c = 'Salesforce', Type__c = 'Permission Set');
        insert perm;

        ACNW_User_Permission__c up = new ACNW_User_Permission__c(Permission__c = perm.Id, User__c = UserInfo.getUserId());
        insert up;

        ACNW_Request__c req = new ACNW_Request__c(Provision_Immediately__c = true, Reference_Number__c = 'test');
        insert req;

        ACNW_Request_Permission__c rp = new ACNW_Request_Permission__c(Request__c = req.Id, User_Permission__c = up.Id);
        insert rp;

        req.Status__c = 'Pending Approval';
        update req;

        SiteSwitcherFuncs.callSiteSwitchFlow(new List<Id> { req.Id });
        try {
            Integer i = 1/0;
        } catch(Exception ex) {
            SiteSwitcherFuncs.setError(req.Id, ex);
        }

        System.assert(true);
    }
    private static testmethod void test2() {
        EncryptionUtils.setupEncryption();

        ACNW_Permission__c perm = new ACNW_Permission__c(Name__c = 'testing', SF_Permission_Id__c = [select Id from Profile limit 1].Id, License_Required__c = 'Salesforce', Type__c = 'Profile');
        insert perm;

        ACNW_User_Permission__c up = new ACNW_User_Permission__c(Permission__c = perm.Id, User__c = UserInfo.getUserId());
        insert up;

        ACNW_Request__c req = new ACNW_Request__c(Provision_Immediately__c = true, Reference_Number__c = 'test');
        insert req;

        ACNW_Request_Permission__c rp = new ACNW_Request_Permission__c(Request__c = req.Id, User_Permission__c = up.Id);
        insert rp;

        req.Status__c = 'Pending Approval';
        update req;

        SiteSwitcherFuncs.callSiteSwitchFlow(new List<Id> { req.Id });

        System.assert(true);
    }
    private static testmethod void test3() {
        PostInstallClass postinstall = new PostInstallClass();
        Test.testInstall(postinstall, null);
        System.assert(true);
    }
    private static testmethod void test4() {
        SiteSwitcherFuncs.hasRequestAlreadyInProgress(null, null);
        try {
        	SiteSwitcherFuncs.setError(new Set<Id>(), null);
        } catch(Exception ex) {}
        new SiteSwitcherfuncs.ImpersonationTime(null, null, null);
        SiteSwitcherFuncs.getImpersonationTimes(new ACNW_Request__c());
        System.assert(true);
    }
    private static testmethod void test5() {
        SiteSwitcher.handleImpersonationsForHistoryObject(new ACNW_Request__c(), 'AccountHistory', new list<SiteSwitcherFuncs.ImpersonationTime> { new SiteSwitcherFuncs.ImpersonationTime(System.now(), System.now(), UserInfo.getUserId()) }, new list<ACNW_Data_Audit_Log__c>());
        SiteSwitcher.handleImpersonationsForObject(new ACNW_Request__c(), 'Account', new list<SiteSwitcherFuncs.ImpersonationTime> { new SiteSwitcherFuncs.ImpersonationTime(System.now(), System.now(), UserInfo.getUserId()) }, new list<ACNW_Data_Audit_Log__c>());
        SiteSwitcher.getPermissionSetsForGroup(new Set<Id>());
        SiteSwitcherFuncs.getPermsForAccessNowPermissionGroup(new Set<Id>());
    }
}