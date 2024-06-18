public with sharing class ObjectFuncs {
    // returns whether this object is valid
    public static Boolean isValidObject(String objectName) {
        return schema.getGlobalDescribe().containsKey(objectName);
    }
    // returns whether this object is a history object
    public static Boolean isHistoryObject(String objectName) {
        return isValidObject(objectName) && objectName.toLowerCase().endsWith('history') && schema.getGlobalDescribe().get(objectName).getDescribe().fields.getMap().containsKey('NewValue');
    }
    // returns the history object for this regular object (ex - Account will return AccountHistory)
    public static String getHistoryObject(String objectName) {
        if (isValidObject(objectName) && !isHistoryObject(objectName)) {
            if (objectName == 'Opportunity') objectName = 'OpportunityFieldHistory';
            else if (objectName.toLowerCase().endsWith('__c')) {
                String[] s = objectName.split('__');
                s[s.size() - 1] = 'History';
                objectName = String.join(s, '__');
            } else {
                // standard object - just put in history at the end
                objectName += 'History';
            }
            if (isHistoryObject(objectName)) return objectName;
        }
        return null;
    }
    // returns the object that a history object points to (ex - AccountHistory input will return Account output)
    public static String getRegularObjectForHistory(String objectName) {
        if (isValidObject(objectName) && isHistoryObject(objectName)) {
            if (objectName.toLowerCase().endsWith('__history')) {
                String[] s = objectName.split('__');
                s[s.size() - 1] = 'c';
                objectName = String.join(s, '__');
            } else {
                // replace the last History part with the regular object name
                if (objectName == 'OpportunityFieldHistory') objectName = 'Opportunity';
                else objectName = objectName.substring(0, objectName.length() - 7);
            }
            if (isValidObject(objectName)) return objectName;
        }
        return null;
    }
    // returns the field on the history object that points to its parent...like ParentId, CaseId, AccountId, etc
    /*
    public static String getNameFieldOfHistoryObject(String objectName) {
        Map<String, Schema.SObjectField> flds = schema.getglobaldescribe().get(objectName).getdescribe().fields.getMap();
        for (String s : flds.keyset()) {
            if (s == 'createdbyid') continue; // don't want this one - but the other one
            if (flds.get(s).getdescribe().gettype() == Schema.DisplayType.REFERENCE) return s;
        }
        return null;
    }
    */
    // returns the name field for an object (ex - Account = Name, Case = CaseNumber, etc)
    public static String getNameFieldForObject(String objectName) {
        Map<String, Schema.SObjectField> flds = schema.getGlobalDescribe().get(objectName).getdescribe().fields.getMap();
        if (flds.containsKey('Name') && flds.get('name').getdescribe().isnamefield()) return 'Name';
        for (String s : flds.keySet()) {
            if (flds.get(s).getDescribe().isNameField()) return s;
        }
        return null;
    }
}