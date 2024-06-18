@istest
private class AccessNowRequestControllerTest {
    private static testmethod void test() {
        EncryptionUtils.setupEncryption();
        try {
            insert new ACNW_Permission__c(Name__c = 'Testing', SF_Permission_Id__c = 'sadf', License_Required__c = 'Salesforce', Type__c = 'Permission Set');
        } catch(Exception ex) {
        }

        try {
            insert new ACNW_Permission__c(Name__c = 'Testing', SF_Permission_Id__c = UserInfo.getUserId(), License_Required__c = 'Salesforce', Type__c = 'Permission Set');
        } catch(Exception ex) {
        }

        try {
            insert new ACNW_Permission__c(Name__c = 'Testing', SF_Permission_Id__c = 'sadf', License_Required__c = 'Salesforce', Type__c = 'Permission Set Group');
        } catch(Exception ex) {
        }

        try {
            insert new ACNW_Permission__c(Name__c = 'Testing', SF_Permission_Id__c = UserInfo.getUserId(), License_Required__c = 'Salesforce', Type__c = 'Permission Set Group');
        } catch(Exception ex) {
        }

        try {
            insert new ACNW_Permission__c(Name__c = 'Testing', SF_Permission_Id__c = UserInfo.getUserId(), License_Required__c = 'Salesforce', Type__c = 'Profile');
        } catch(Exception ex) {
        }

        try {
            insert new ACNW_Permission__c(Name__c = 'Testing', SF_Permission_Id__c = UserInfo.getUserId(), License_Required__c = 'Salesforce', Type__c = '?');
        } catch(Exception ex) {
        }
    }
    private static testmethod void test2() {
        ACNW_Permission__c perm = new ACNW_Permission__c(Name__c = 'Testing', SF_Permission_Id__c = [select Id from PermissionSet where IsOwnedByProfile = false limit 1].Id, License_Required__c = 'Salesforce', Type__c = 'Permission Set');
        insert perm;

        ACNW_Permission__c perm2 = new ACNW_Permission__c(Name__c = 'Testing', SF_Permission_Id__c = [select Id from Profile limit 1].Id, License_Required__c = 'Salesforce', Type__c = 'Profile');
        insert perm2;

        //ACNW_Permission__c perm3 = new ACNW_Permission__c(Name__c = 'Testing', SF_Permission_Id__c = [select Id from PermissionSetGroup limit 1].Id, License_Required__c = 'Salesforce', Type__c = 'Permission Set Group');
        //insert perm3;

        ACNW_User_Permission__c up = new ACNW_User_Permission__c(Permission__c = perm.Id, User__c = UserInfo.getUserId());
        insert up;

        ACNW_User_Permission__c up2 = new ACNW_User_Permission__c(Permission__c = perm2.Id, User__c = UserInfo.getUserId());
        insert up2;

        // test cancellation
        ACNW_Request__c r = new ACNW_Request__c();
        ApexPages.StandardController std = new ApexPages.StandardController(r);
        AccessNowRequestController cr = new AccessNowRequestController(std);
        cr.req.Provision_Immediately__c = false;
        cr.req.Reference_Number__c = 'hello';
        cr.perms[0].checked = true;
        cr.req.Provision_Immediately__c = true;

        Object obj = cr.allowCancel;
        obj = cr.setupAuditLog;

        cr.save();
        cr.cancel();


        // test save and provision
        r = new ACNW_Request__c();
        std = new ApexPages.StandardController(r);
        cr = new AccessNowRequestController(std);
        cr.req.Provision_Immediately__c = false;
        cr.req.Reference_Number__c = 'hello';

        obj = cr.allowRetry;

        try {
            cr.save();
        } catch(Exception ex) {
        }
        cr.req.Last_Error__c = 'test';
        cr.perms[0].checked = true;
        try {
            cr.save();
        } catch(Exception ex) {
        }

        cr.req.Requested_Start_Time__c = System.today() + 10;
        try {
            cr.save();
        } catch(Exception ex) {
        }

        cr.req.Requested_Start_Time__c = null;
        cr.req.Provision_Immediately__c = true;
        try {
            cr.save();
        } catch(Exception ex) {
        }
        cr.submitForApproval();
    }
    private static testmethod void test3() {
        ACNW_Permission__c perm = new ACNW_Permission__c(Name__c = 'Testing', SF_Permission_Id__c = [select Id from PermissionSet where IsOwnedByProfile = false limit 1].Id, License_Required__c = 'Salesforce', Type__c = 'Permission Set');
        insert perm;

        ACNW_Permission__c perm2 = new ACNW_Permission__c(Name__c = 'Testing', SF_Permission_Id__c = [select Id from Profile limit 1].Id, License_Required__c = 'Salesforce', Type__c = 'Profile');
        insert perm2;

        //ACNW_Permission__c perm3 = new ACNW_Permission__c(Name__c = 'Testing', SF_Permission_Id__c = [select Id from PermissionSetGroup limit 1].Id, License_Required__c = 'Salesforce', Type__c = 'Permission Set Group');
        //insert perm3;

        ACNW_User_Permission__c up = new ACNW_User_Permission__c(Permission__c = perm.Id, User__c = UserInfo.getUserId());
        insert up;

        ACNW_User_Permission__c up2 = new ACNW_User_Permission__c(Permission__c = perm2.Id, User__c = UserInfo.getUserId());
        insert up2;

        ACNW_Request__c r = new ACNW_Request__c();
        ApexPages.StandardController std = new ApexPages.StandardController(r);
        AccessNowRequestController cr = new AccessNowRequestController(std);
        cr.req.Provision_Immediately__c = false;
        cr.req.Reference_Number__c = 'hello';

        cr.perms[0].checked = true;
        cr.req.Requested_Start_Time__c = null;
        cr.req.Provision_Immediately__c = true;
        cr.save();

        r = cr.req;

        cr.submitForApproval();
        r = [select Id, Status__c from ACNW_Request__c where Id = :r.Id];

        Test.startTest();

        insert new ACNW_Setup_Audit_Log__c(Activity__c = 'a', Section__c = 'a', Date__c = System.now(), Request__c = r.Id);

        System.assert(r.Status__c == 'Approved', 'Expecting Approved, got ' + r.Status__c); // should auto approve

        String switchResult = SiteSwitcher.switch(r.Id);
        System.assert(switchResult == 'OK', switchResult);

        r = [select Id, Status__c from ACNW_Request__c where Id = :r.Id];
        //System.assert(r.Status__c == 'In Progress', 'Expecting In Progress, got ' + r.Status__c);

        try {
            delete [select Id from ACNW_Request_Permission__c where Request__c = :r.Id];
        } catch(Exception ex) {
        }

        try {
            //delete [select Id from ACNW_Request__c where Id = :r.Id];
        } catch(Exception ex) {
        }

        //User_Permission__c up2 = new User_Permission__c(Permission__c = perm.Id, User__c = UserInfo.getUserId());
        //insert up2;

        try {
            ACNW_Request_Permission__c rp = [select Id from ACNW_Request_Permission__c where Request__c = :r.Id];
            rp.User_Permission__c = up.Id;
            update rp;
        } catch(Exception ex) {
        }

        std = new ApexPages.StandardController(r);
        cr = new AccessNowRequestController(std);
        cr.req = new ACNW_Request__c();

        ApexPages.currentPage().getParameters().put('idd', UserInfo.getUserID());
        cr.reloadUserPermsFunc();

        try {
            cr.req.Duration_Hours__c = '6';
            cr.save();
        } catch(Exception ex) {
        }

        try {
            cr.submitForApproval();
        } catch(Exception ex) {
        }

        std = new ApexPages.StandardController(r);
        cr = new AccessNowRequestController(std); 
        cr.req = new ACNW_Request__c();

        try {
            cr.revoke();
        } catch(Exception ex) {
        }

        try {
            cr.retry();
        } catch(Exception ex) {
        }

        try {
        	switchResult = SiteSwitcher.switch(r.Id);
        } catch(Exception ex) {
        }

        //System.assert(switchResult == 'OK', switchResult);

        try {        
        	r = [select Id, Manually_Revoked__c from ACNW_Request__c where Id = :r.Id];
        } catch(Exception ex) {
        }

        //System.assert(r.Manually_Revoked__c == true);

        try {
            r.Manually_Revoked__c = false;
            update r;
            r.Manually_Revoked__c = true;
            update r;
        } catch(Exception ex) {
        }
    }
}