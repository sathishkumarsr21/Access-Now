@istest
private class ObjectFuncsTest {
  private static testmethod void test() {
     insert new ACNW_Data_Audit_Log_Object__c(Name = 'Account');

    System.assert(ObjectFuncs.isValidObject('Account'));
    System.assert(!ObjectFuncs.isvalidObject('asdf'));

    System.assert(ObjectFuncs.isHistoryObject('AccountHistory'));
    System.assert(!ObjectFuncs.isHistoryObject('something'));
    System.assert(!ObjectFuncs.isHistoryObject('Account'));

    System.assert(ObjectFuncs.getHistoryObject('Account') == 'AccountHistory');
    System.assert(ObjectFuncs.getHistoryObject('something') == null);
    System.assert(ObjectFuncs.getHistoryObject('AccountHistory') == null);
    ObjectFuncs.getHistoryObject('ACNW_Request__c');
    ObjectFuncs.getNameFieldForObject('Case');

    System.assert(ObjectFuncs.getRegularObjectForHistory('AccountHistory') == 'Account');
    ObjectFuncs.getRegularObjectForHistory('ACNW_Request__history');
    System.assert(ObjectFuncs.getRegularObjectForHistory('asdf') == null);

    System.assert(ObjectFuncs.getNameFieldForObject('Account') == 'Name');
  }
}