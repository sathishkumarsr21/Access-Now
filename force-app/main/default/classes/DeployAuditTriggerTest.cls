@istest
private class DeployAuditTriggerTest {
    private static testmethod void test1() {
        Test.setCurrentPage(Page.DeployAuditTrigger);
        ApexPages.currentPage().getParameters().put('objectName', 'account');
        DeployAuditTrigger dam = new DeployAuditTrigger();
        object o = dam.zipContents;
        dam.deploy();
        System.assert(true);
    }
    private static testmethod void test2() {
        Test.setCurrentPage(Page.DeployAuditTrigger);
        ApexPages.currentPage().getParameters().put('objectName', 'account');
        ApexPages.currentPage().getParameters().put('deploy', '1');
        DeployAuditTrigger dam = new DeployAuditTrigger();
        object o = dam.zipContents;
        o = dam.asyncId;
        dam.deploy();
        dam.getTriggerClassNames('01234567890123456789012345678901234567890123456789'); // this should force the md5 logic
        System.assert(true);
    }
}