public class SiteSwitcherFuncs {
    public static Map<Id, List<ACNW_Permission__c>> grpPermCache = new Map<Id, List<ACNW_Permission__c>>();

    @InvocableMethod
    public static void callSiteSwitchFlow(List<Id> requestIds) {
        Set<Id> idds = new Set<id>();
        idds.addAll(requestIds);
        callSiteSwitch(idds);
    }

    @future(callout=true)
    public static void callSiteSwitch(Set<Id> requestIdsSet) {
        Map<Id, ACNW_Request__c> erroredReqs = new Map<Id, ACNW_Request__c>();
        try {
            List<Id> requestIdsList = new List<Id>();

            Map<Id, ACNW_Request__c> originalReqs = new Map<Id, ACNW_Request__c>([select Id, Manually_Revoked__c, Status__c, Requested_Start_Time__c, Requested_End_Time__c from ACNW_Request__c where Id in :requestIdsSet]);
            for (ACNW_Request__c ar : originalReqs.values()) if (needToStart(ar) || needToStop(ar)) requestIdsList.add(ar.Id);

            erroredReqs.putAll(callSiteSwitchNow(requestIdsList, null));
    
            // now see which ones changed so we can call the site again to do the permission update
            List<Id> idsToPermUpdate = new List<Id>();
            Map<Id, ACNW_Request__c> newReqs = new Map<Id, ACNW_Request__c>([select Id, Status__c from ACNW_Request__c where Id in :requestIdsList and Id not in :erroredReqs.keySet()]);
            for (Id rid : requestIdsList) {
                if (newReqs.containsKey(rid) && (originalReqs.get(rid).Status__c != newReqs.get(rid).Status__c) && (newReqs.get(rid).Status__c == 'In Progress' || newReqs.get(rid).Status__c == 'Completed')) {
                    idsToPermUpdate.add(rid);
                }
            }
            if (!idsToPermUpdate.isEmpty()) {
                erroredReqs.putAll(callSiteSwitchNow(idsToPermUpdate, 'perms'));
            }
        } catch(Exception ex) {
            String err = (ex.getMessage() + ' - ' + ex.getStackTraceString()).left(255);
            if (!Schema.SObjectType.ACNW_Request__c.isUpdateable() || !Schema.SObjectType.ACNW_Request__c.fields.Status__c.isUpdateable() || !Schema.SObjectType.ACNW_Request__c.fields.Last_Error__c.isUpdateable()) throw new SiteSwitcherException(Label.MSG_InsufficientPrivileges + ' - Request object to update last error info');
            for (Id idd : requestIdsSet) erroredReqs.put(idd, new ACNW_Request__c(Id = idd, Status__c = 'Error', Last_Error__c = err));
        }
        // now update the ones that errored out
        if (!erroredReqs.isEmpty()) {
            for (Id idx : new Map<Id, ACNW_Request__c>([select Id from ACNW_Request__c where Id in :erroredReqs.keySet() and Last_Error__c <> '']).keySet()) {
                erroredReqs.remove(idx);
            }
        }
        if (!erroredReqs.isEmpty()) {
            if (!Schema.SObjectType.ACNW_Request__c.isUpdateable()) throw new SiteSwitcherException('Insufficient rights to update Request object');
            update erroredReqs.values();
        }
    }

    private static Map<Id, ACNW_Request__c> callSiteSwitchNow(List<Id> requestIds, String function) {
        AccessNowConfig__c config = AccessNowConfig__c.getOrgDefaults();
        if (config.Id == null && !Test.isRunningTest()) {
            throw new SiteSwitcherException(Label.ERR_AccessNowURLNotDefined);
        }

        Map<Id, ACNW_Request__c> reqToUpdate = new Map<Id, ACNW_Request__c>();

        Http h = new Http();
        for (Id idd : requestIds) {
            HttpRequest req = new HttpRequest();
            req.setMethod('GET');
            String url = fixCalloutUrl(config.Site_Url__c) + '/services/apexrest/accessnow/accessnow?id=' + EncodingUtil.urlEncode(idd,'UTF-8') + '&cs=' + EncodingUtil.urlEncode(EncryptionUtils.encryptData(idd),'UTF-8');
            if (!String.isEmpty(function)) url += '&func=' + EncodingUtil.urlEncode(function, 'UTF-8');
            req.setEndpoint(url);
            if (test.isRunningTest()) {
				if (!Schema.SObjectType.ACNW_Request__c.isUpdateable() || !Schema.SObjectType.ACNW_Request__c.fields.Status__c.isUpdateable() || !Schema.SObjectType.ACNW_Request__c.fields.Last_Error__c.isUpdateable()) throw new SiteSwitcherException(Label.MSG_InsufficientPrivileges + ' - Request object to update last error info');
                reqToUpdate.put(idd, new ACNW_Request__c(Id = idd, Status__c = 'Error', Last_Error__c = 'in test method'));
            } else {
                HttpResponse res = h.send(req);
				while (res.getStatusCode() == 302) {
                	req.setEndpoint(res.getHeader('Location'));
                	res = h.send(req);
            	}
                if (res.getBody() != '"OK"') {
					if (!Schema.SObjectType.ACNW_Request__c.isUpdateable() || !Schema.SObjectType.ACNW_Request__c.fields.Status__c.isUpdateable() || !Schema.SObjectType.ACNW_Request__c.fields.Last_Error__c.isUpdateable()) throw new SiteSwitcherException(Label.MSG_InsufficientPrivileges + ' - Request object to update last error info');
                    reqToUpdate.put(idd, new ACNW_Request__c(Id = idd, Status__c = 'Error', Last_Error__c = 'Got site error: ' + res.getStatusCode() + ' - ' + res.getBody().left(200)));
                }
            }
        }
        return reqToUpdate;
        /*
        if (!reqToUpdate.isEmpty()) {
            for (Id idx : new Map<Id, ACNW_Request__c>([select Id from ACNW_Request__c where Last_Error__c <> '']).keySet()) {
                reqToUpdate.remove(idx);
            }
        }
        if (!reqToUpdate.isEmpty()) update reqToUpdate.values();
        */
    }
    public static boolean needToStart(ACNW_Request__c req) {
        return !req.Manually_Revoked__c && (req.Status__c == 'Approved' || req.Status__c == 'Error') && (req.Requested_Start_Time__c != null && System.now().addMinutes(1) >= req.Requested_Start_Time__c) && (req.Requested_End_Time__c != null && System.now() < req.Requested_End_Time__c);
    }
    public static boolean needToStop(ACNW_Request__c req) {
        // add 1 min to current time to take into account the event getting triggered not taking seconds into account...so this way it will stop the request instead of throwing an error
        return (req.Status__c == 'In Progress' || req.Status__c == 'Error') && (System.now().addMinutes(1) >= req.Requested_End_Time__c || req.Manually_Revoked__c);
    }
    public static Id getRoleIdForReq(ACNW_Request__c req) {
        for (ACNW_Permission__c ap : getFlattenedPermsForRequestPerms(req.Request_Permissions__r)) {
            if (ap.Type__c == 'Role') return ap.SF_Permission_Id__c;
        }
        return null;
    }
    public static Id getProfileIdForReq(User u, ACNW_Request__c req) {
        AccessNowConfig__c conf = AccessNowConfig__c.getOrgDefaults();
        Id newProfileId = null;
        List<ACNW_Permission__c> aps = getFlattenedPermsForRequestPerms(req.Request_Permissions__r);
        for (ACNW_Permission__c ap : aps) {
            if (ap.Type__c == 'Profile') newProfileId = ap.SF_Permission_Id__c;
        }
        if (newProfileId == null) {
            // see based on permissions whether we need to switch to a different profile
            Boolean hasLicense = true;
            for (ACNW_Permission__c ap : aps) {
                if (String.isEmpty(ap.License_Required__c)) continue;
                Boolean hasIt = false;
                for (String s : ap.License_Required__c.split(';')) {
                    if (s.trim() == u.Profile.UserLicense.Name) {
                        hasIt = true;
                        break;
                    }
                }
                if (!hasIt) {
                    hasLicense = false;
                    break;
                }
            }
            if (test.isRunningTest() || !hasLicense) {
                map<String, String> fromTo = new map<string, string>();
                for (ProfileMapping__c mapp : ProfileMapping__c.getAll().values()) {
                    fromTo.put(mapp.From_Profile__c.toLowerCase(), mapp.To_Profile__c.toLowerCase());
                }

                String newProfileName = fromTo.get(u.Profile.Name.toLowerCase());
                if (!Test.isRunningTest() && String.isEmpty(newProfileName)) throw new SiteSwitcherException(string.format(Label.ERR_ProfileMappingNotFound, new List<String>{u.Profile.Name}));

                List<Profile> profiles = [select Id from Profile where Name = :newProfileName];
                if (profiles.isEmpty()) {
                    if (!Test.isRunningTest()) throw new SiteSwitcherException(String.format(Label.ERR_ProfileNotFound, new List<String>{newProfileName}));
                } else {
                    newProfileId = profiles[0].Id;
                }
            }
        }
        return newProfileId;
    }

    public static Boolean hasRequestAlreadyInProgress(Id userId, Id ignoreReqId) {
        return getRequestAlreadyInProgress(userId, ignoreReqId) != null;
    }
    public static ACNW_Request__c getRequestAlreadyInProgress(Id userId, Id ignoreReqId) {
        for (ACNW_Request__c req : [select Id, Name from ACNW_Request__c where Id != :ignoreReqId and OwnerId = :userId and Status__c in ('In Progress','Error') limit 1]) return req;
        return null;
    }

    public static ACNW_Request__c getReq(Id id) {
        return getReqs(new Set<Id> { id }).get(id);
    }

    public static Map<Id, ACNW_Request__c> getReqs(Set<Id> ids) {
        return new Map<Id, ACNW_Request__c>([select (select Id, User_Permission__r.Permission__r.License_Required__c, User_Permission__r.Permission__r.Type__c, User_Permission__r.Permission__r.SF_Permission_Id__c from Request_Permissions__r), Id, Original_Profile_Id__c, Original_Role_Id__c, Original_Permission_Set_Ids__c, Original_Permission_Set_Group_Ids__c, OwnerId, Owner.Username, Status__c, Manually_Revoked__c, Requested_Start_Time__c, Requested_End_Time__c, Actual_Start_Time__c, Actual_End_Time__c from ACNW_Request__c where Id in :ids]);
    }

    public static User getUser(Id id) {
        return getUsers(new Set<Id> { id }).get(id);
    }
    public static Map<Id, User> getUsers(Set<Id> ids) {
        return new Map<Id, User>([select Id, Profile.Name, Profile.UserLicense.Name, ProfileId, UserRoleId from User where Id in :ids]);
    }

    public static void setError(Id id, Exception ex) {
        setError(id, ex, false);
    }
    public static void setError(Id id, Exception ex, Boolean autoRetry) {
        setError(new Set<Id> { id }, ex, autoRetry);
    }
    @testvisible
    private static void setError(Set<Id> ids, Exception ex) {
        setError(ids, ex, false);
    }
    @testvisible
    private static void setError(Set<Id> ids, Exception ex, Boolean autoRetry) {
        String msg = (autoRetry ? 'RETRY: ' : '') + ex.getMessage() + ' - ' + ex.getLineNumber();
        if (String.isEmpty(msg)) msg = 'Unknown error occurred';
        if (msg.length() > 255) msg = msg.substring(0, 255);

        if (!Schema.SObjectType.ACNW_Request__c.isUpdateable()) throw new SiteSwitcherException(Label.MSG_InsufficientPrivileges + ' - Request updateble');
        if (!Schema.SObjectType.ACNW_Request__c.fields.Last_Error__c.isUpdateable()) throw new SiteSwitcherException(Label.MSG_InsufficientPrivileges + ' - Last error updateble');
        if (!Schema.SObjectType.ACNW_Request__c.fields.Status__c.isUpdateable()) throw new SiteSwitcherException(Label.MSG_InsufficientPrivileges + ' - Status updateble');

        List<ACNW_Request__c> reqs = new List<ACNW_Request__c>();
        for (Id id : ids) {
            reqs.add(new ACNW_Request__c(Id = id, Auto_Retry_On__c = null, Last_Error__c = msg, Status__c = 'Error'));
        }
        update reqs;

        if (Test.isRunningTest() || autoRetry) {
            reqs = new List<ACNW_Request__c>();
            for (Id id : ids) {
                // do it this way because the time based workflow kicks off when it goes to not null (since it can't do time based on changes)
                reqs.add(new ACNW_Request__c(Id = id, Auto_Retry_On__c = System.now().addMinutes(1)));
            }
            update reqs;
        }
    }

    public static List<ImpersonationTime> getImpersonationTimes(ACNW_Request__c req) {
        List<ImpersonationTime> ret = new List<ImpersonationTime>();
        DateTime lastDT = req.Actual_Start_Time__c;
        for (SetupAuditTrail sat : [select CreatedById, CreatedDate from SetupAuditTrail where DelegateUser = :req.Owner.Username and CreatedDate >= :req.Actual_Start_time__c and CreatedDate <= :req.Actual_End_Time__c and Action = 'suOrgAdminLogout' order by CreatedDate]) {
            ret.add(new ImpersonationTime(lastDT, sat.CreatedDate, sat.CreatedById));
            lastDT = sat.CreatedDate;
        }
        return ret;
    }

    public static List<ACNW_Permission__c> getFlattenedPermsForRequestPerms(List<ACNW_Request_Permission__c> reqPerms) {
        List<ACNW_Permission__c> perms = new List<ACNW_Permission__c>();
        Map<Id, List<ACNW_Permission__c>> gtoa = new Map<Id, List<ACNW_Permission__c>>();
        for (ACNW_Request_Permission__c rp : reqPerms) {
            if (rp.User_Permission__r.Permission__r.Type__c == 'Permission Bundles') gtoa.put(rp.User_Permission__r.Permission__c, null);
            else perms.add(rp.User_Permission__r.Permission__r);
        }
        if (!gtoa.isEmpty()) {
            gtoa = getPermsForAccessNowPermissionGroup(gtoa.keyset());
            for (List<ACNW_Permission__c> ppx : gtoa.values()) perms.addAll(ppx);
        }
        return perms;
    }

    public static Map<Id, List<ACNW_Permission__c>> getPermsForAccessNowPermissionGroup(Set<Id> grpA) {
        Map<Id, List<ACNW_Permission__c>> ret = new Map<Id, List<ACNW_Permission__c>>();
        Set<Id> grpC = grpA.clone();
        for (Id idd : grpC) {
            if (grpPermCache.containsKey(idd)) {
                ret.put(idd, grpPermCache.get(idd));
                grpC.remove(idd);
            }
        }
        if (!grpC.isEmpty()) {
            for (Id idd : grpC) grpPermCache.put(idd, new list<ACNW_Permission__c>());
            for (ACNW_Permission_Group_Component__c pgc : [select Id, AccessNow_Permission_Group__c, Permission__r.Id, Permission__r.Type__c, Permission__r.SF_Permission_Id__c, Permission__r.Approval_relavent__c, Permission__r.Permission_Count__c, Permission__r.Name__c, Permission__r.License_Required__c, Permission__r.OwnerId from ACNW_Permission_Group_Component__c where AccessNow_Permission_Group__c in :grpC]) grpPermCache.get(pgc.AccessNow_Permission_Group__c).add(pgc.Permission__r);
            for (Id idd : grpC) ret.put(idd, grpPermCache.get(idD));
        }
        return ret;
    }

    public class ImpersonationTime {
        public Id userId;
        public DateTime startDateTime;
        public DateTime endDateTime;

        public ImpersonationTime(DateTime startDateTime, DateTime endDateTime, Id userId) {
            this.userId = userId;
            this.startDateTime = startDatetime;
            this.endDateTime = endDateTime;
        }
    }

    public static String fixCalloutUrl(String url) {
        if (!String.isEmpty(url) && url.indexOf('callout:') >= 0) return url.substring(url.indexOf('callout:'));
        return url;
    }
    class SiteSwitcherException extends Exception {}
}