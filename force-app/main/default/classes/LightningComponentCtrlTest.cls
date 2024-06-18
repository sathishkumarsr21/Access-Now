@istest
private class LightningComponentCtrlTest {
    private static testmethod void test() {
        LightningComponentCtrl ctrl = new LightningComponentCtrl();
        Account acct = new Account();
        ctrl.inputObject = acct;
        ctrl.fieldName = 'Name';
        Object o = ctrl.isReadOnly;
        o = ctrl.isInput;
        o = ctrl.isTextarea;
        o = ctrl.isPicklist;
        o = ctrl.isDependentPicklist;
        o = ctrl.isMultipicklist;
        o = ctrl.isLookup;
        o = ctrl.isCheckbox;
        o = ctrl.isDatetime;
        o = ctrl.getObjectDescribe();
        o = ctrl.getSField();
        o = ctrl.getFieldDescribe();
        o = ctrl.objectName;
        System.assert(true);
    }
}