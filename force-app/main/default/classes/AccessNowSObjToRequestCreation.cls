global with sharing class AccessNowSObjToRequestCreation {
	@InvocableMethod(label='AccessNow SObject to Request' description='Creates an AccessNowRequest from an SObject')
    global static List<Id> createRequest(List<Id> ids) {
        if (ids == null || ids.isEmpty()) throw new AccessNowSObjToRequestCreationException('Need a list of Ids to create a request');

		String destObjType = ids[0].getSObjectType().getDescribe().getName();

        map<string, string> sourceToDest = new map<String, string>();
        for (AccessNow_SObject_to_Request_Mapping__c m : AccessNow_SObject_to_Request_Mapping__c.getAll().values()) {
            if (m.SObject_API_Name__c == destObjType) {
            	sourceToDest.put(m.SObject_Field_API_Name__c, m.AccessNow_Request_Field_API_Name__c);
            }
        }
        if (sourceToDest.isEmpty()) throw new AccessNowSObjToRequestCreationException('Field mapping for ' + destObjType + ' not specified');

        List<Id> ret = new List<Id>();
        list<ACNW_Request__c> anrs = new list<ACNW_Request__c>();
        list<string> flds = new list<string>();
        flds.addAll(sourceToDest.keyset());
        Map<String, SObjectField> fieldsDef = ACNW_Request__c.sobjecttype.getDescribe().fields.getMap();
        for (SObject obj : Database.query('select ' + String.join(flds, ',') + ' from ' + destObjType + ' where Id in :ids')) {
            ACNW_Request__c a = new ACNW_Request__c();
            for (String s : sourceToDest.keyset()) {
                try {
					if (!fieldsDef.get(sourceToDest.get(s)).getDescribe().isCreateable()) throw new AccessNowSObjToRequestCreationException(Label.MSG_InsufficientPrivileges + ' - Request - ' + sourceToDest.get(s));
                	a.put(sourceToDest.get(s), obj.get(s));
                } catch(Exception ex) {
                    throw new AccessNowSObjToRequestCreationException('Unable to set Request field: ' + sourceToDest.get(s) + ' with source value in field: ' + s + ', ' + obj.get(s) + ' - ' + ex.getMessage());
                }
            }
            if (!a.Provision_Immediately__c && a.Requested_Start_Time__c == null) a.Requested_Start_Time__c = System.now();
            anrs.add(a);
        }
        if (!Schema.SObjectType.ACNW_Request__c.isCreateable()) throw new AccessNowSObjToRequestCreationException(Label.MSG_InsufficientPrivileges + ' - Request object to update last error info');
        insert anrs;
        for (ACNW_Request__c a : anrs) {
            ret.add(a.Id);
        }
        return ret;
    }
    class AccessNowSObjToRequestCreationException extends Exception {}
}