trigger DataAuditLogObjectTrigger on ACNW_Data_Audit_Log_Object__c (before insert, before update) {
    for (ACNW_Data_Audit_Log_Object__c d : trigger.new) {
        if (!ObjectFuncs.isValidObject(d.Name)) {
            d.addError(Label.ERR_DataAuditLogObjectInvalid);
        }
    }
}