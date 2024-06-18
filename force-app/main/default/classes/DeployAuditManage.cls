public with sharing class DeployAuditManage {
    public List<List<SelectOption>> objectList { get {
        Map<String, String> mapp = new Map<String, String>();
        Map<String, Schema.SObjectType> objs = Schema.getGlobalDescribe();
        for (String apiName : objs.keySet()) {
            if (apiName.endsWith('history') || apiName.endswith('share') || apiName.endswith('tag') || apiName.endswith('feed')) continue;
            String lbl = objs.get(apiName).getDescribe().getLabel();
            mapp.put(lbl + ' (' + apiName + ')', apiName);
        }
        List<String> lst = new List<String>(mapp.keySet());
        lst.sort();

        List<List<SelectOption>> sos = new List<List<SelectOption>>();
        List<SelectOption> curr = null;
        for (String s : lst) {
            if (curr == null || curr.size() == 500) {
                curr = new List<SelectOption>();
                sos.add(curr);
            }
            curr.add(new SelectOption(mapp.get(s), s));
        }
        return sos;
    } }

    public List<String> existingObjects { get {
        List<String> ret = new List<String>();

        for (ApexTrigger at : [SELECT TableEnumOrId FROM ApexTrigger WHERE Name like 'AccessNowAuditTrigger%' or Name like 'ACNW_A_%']) {
            ret.add(at.TableEnumOrId);
        }

        return ret;
    } }

    public DeployAuditManage() {
    }
}