@istest
private class AccessNowSObjToRequestCreationTest {
    private static testmethod void test() {
        insert new AccessNow_SObject_to_Request_Mapping__c(Name = 'test1', SObject_API_Name__c = 'account', SObject_Field_API_Name__c = 'name', AccessNow_Request_Field_API_Name__c = 'accessnow__Reference_Number__c');

        Account a = new Account(Name = 'test');
        insert a;

        list<id> rids = AccessNowSObjToRequestCreation.createRequest(new list<id> { a.Id });
        ACNW_Request__c ra = [select accessnow__Reference_Number__c from ACNW_Request__c where Id in :rids];
        System.assert(ra.accessnow__Reference_Number__c == a.Name, 'Reference number should have been ' + a.Name + ' but got '  + ra.accessnow__Reference_Number__c);
    }
}