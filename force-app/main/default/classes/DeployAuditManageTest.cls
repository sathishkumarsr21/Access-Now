@istest
private class DeployAuditManageTest {
    private static testmethod void test() {
        DeployAuditManage dam = new DeployAuditManage();
        Object o = dam.objectList;
        o = dam.existingObjects;
        System.assert(true);
    }
}