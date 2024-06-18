public with sharing class AccessNowSetup {
    public Site cachedSite = null;
    public String cachedSiteURL = null;
    public Id accessNowAdminPermissionSet { get; private set; }

    public Boolean accessNowSiteSetup { get {
        return getSite != null;
    } }
    public String siteURL { get {
        if (cachedSiteURL == null) {
        	Site s = getSite;
            if (s != null) {
		        String path = '/sites/servlet.SiteDebugMode';
				PageReference pr = new PageReference(path);
				pr.getParameters().put('guid', s.GuestUserId);
				pr.getParameters().put('sitedebugmode', 'x');
				cachedSiteURL = pr.getContent().toString().substringAfter('URL=').substringBefore(path).replace('http://', 'https://');
            }
        }
        return cachedSiteURL;
    } }
    public Boolean accessNowSiteUserSetup { get {
        Site s = getSite;
        if (s != null) {
            return ![select Id from PermissionSetAssignment where AssigneeId = :s.GuestUserId and PermissionSetId = :accessNowAdminPermissionSet].isEmpty();
        }
        return false;
    } }
    public Site getSite { get {
        if (cachedSite == null) {
            List<Site> ss = [Select id, GuestUserId from site where name = 'accessnow'];
        	cachedSite = ss.isEmpty() ? null : ss[0];
        }
        return cachedSite;
    } }
    public Boolean accessNowCustomSettingSetup { get {
        AccessNowConfig__c config = AccessNowConfig__c.getOrgDefaults();
        return config.Id != null && !String.isEmpty(config.Site_Url__c) && config.Site_Url__c == siteURL;
    } }

    public String asyncId { get; private set; }

    public List<ZipContent> siteZipContents { get {
        return new List<ZipContent> {
        	new ZipContent('package.xml', '<?xml version="1.0" encoding="UTF-8"?><Package xmlns="http://soap.sforce.com/2006/04/metadata"><types><members>accessnow</members><name>CustomSite</name></types><version>42.0</version></Package>'),
        	new ZipContent('sites/accessnow.site', '<?xml version="1.0" encoding="UTF-8"?><CustomSite xmlns="http://soap.sforce.com/2006/04/metadata"><active>true</active><browserXssProtection>true</browserXssProtection><contentSniffingProtection>true</contentSniffingProtection><cspUpgradeInsecureRequests>true</cspUpgradeInsecureRequests><allowHomePage>false</allowHomePage><referrerPolicyOriginWhenCrossOrigin>true</referrerPolicyOriginWhenCrossOrigin><allowStandardPortalPages>false</allowStandardPortalPages><allowStandardAnswersPages>false</allowStandardAnswersPages><allowStandardIdeasPages>false</allowStandardIdeasPages><allowStandardLookups>false</allowStandardLookups><allowStandardSearch>false</allowStandardSearch><authorizationRequiredPage>Unauthorized</authorizationRequiredPage><bandwidthExceededPage>BandwidthExceeded</bandwidthExceededPage><clickjackProtectionLevel>SameOriginOnly</clickjackProtectionLevel><description>Manage user permissions</description><fileNotFoundPage>FileNotFound</fileNotFoundPage><genericErrorPage>Exception</genericErrorPage><inMaintenancePage>InMaintenance</inMaintenancePage><inactiveIndexPage>InMaintenance</inactiveIndexPage><indexPage>SiteLogin</indexPage><masterLabel>accessnow</masterLabel><requireHttps>true</requireHttps><requireInsecurePortalAccess>false</requireInsecurePortalAccess><siteAdmin>' + UserInfo.getUserName() + '</siteAdmin><siteTemplate>SiteTemplate</siteTemplate><siteType>Visualforce</siteType><subdomain></subdomain><urlPathPrefix>accessnow</urlPathPrefix></CustomSite>')
		};
    } }
    public List<ZipContent> remoteSiteSettingZipContents { get {
        return new List<ZipContent> {
        	new ZipContent('package.xml', '<?xml version="1.0" encoding="UTF-8"?><Package xmlns="http://soap.sforce.com/2006/04/metadata"><types><members>accessnow</members><name>RemoteSiteSetting</name></types><version>42.0</version></Package>'),
        	new ZipContent('remoteSiteSettings/accessnow.remoteSite', '<?xml version="1.0" encoding="UTF-8"?><RemoteSiteSetting xmlns="http://soap.sforce.com/2006/04/metadata"><disableProtocolSecurity>false</disableProtocolSecurity><isActive>true</isActive><url>' + siteURL + '</url></RemoteSiteSetting>')
		};
    } }

    public AccessNowSetup() {
        accessNowAdminPermissionSet = [Select id from permissionset where name = 'accessnow_administrator' and namespaceprefix = 'accessnow'].Id;
    }

    public void setupUser() {
        try {
            /*Site s = getSite;
            if (s == null) throw new AccessNowSetupException('Site not yet set up');

            Organization o = [SELECT Id, TimeZoneSidKey FROM Organization];
            update new User(Id = s.GuestUserId, FirstName = 'accessnow', LastName = 'User', Email = UserInfo.getUserEmail(), TimeZoneSidKey = o.TimeZoneSidKey, UserPreferencesHideS1BrowserUI = true);

            // add the permission set
            insert new PermissionSetAssignment(AssigneeId = s.GuestUserId, PermissionSetId = accessNowAdminPermissionSet);*/
            throw new AccessNowSetupException('No longer implemented');
        } catch(Exception ex) {
            ApexPages.addMessages(ex);
        }
    }

    public void remoteSiteSettingDeploy() {
        // first call deploy then after the web service call set up the custom setting
        String remoteSiteURL = siteURL;
        if (String.isEmpty(remoteSiteURL)) {
            ApexPages.addMessage(new ApexPages.Message(ApexPages.Severity.ERROR, 'Site not yet set up'));
            return;
        }
        deploy();
        if (asyncId != null) {
            // no errors - set up the custom setting
        	AccessNowConfig__c config = AccessNowConfig__c.getOrgDefaults();
            if (Schema.SObjectType.AccessNowConfig__c.isCreateable() && Schema.SObjectType.AccessNowConfig__c.isUpdateable() && Schema.SObjectType.AccessNowConfig__c.fields.Site_Url__c.isCreateable() &&Schema.SObjectType.AccessNowConfig__c.fields.Site_Url__c.isUpdateable()) {
                config.Site_Url__c = remoteSiteURL;
				upsert config;
            }
        }
    }

    public void deploy() {
        try {
            asyncId = null;
            Map<String, Schema.SObjectType> objs = Schema.getGlobalDescribe();
            List<String> testRuns = new List<String>();

            String zip = ApexPages.currentPage().getParameters().get('zip');

            MetadataService.MetadataPort service = new MetadataService.MetadataPort();
            service.SessionHeader = new MetadataService.SessionHeader_element();
            service.SessionHeader.sessionId = UserInfo.getSessionId();

            MetadataService.DeployOptions deployOptions = new MetadataService.DeployOptions();
            deployOptions.testLevel = 'NoTestRun';

            deployOptions.allowMissingFiles = false;
            deployOptions.autoUpdatePackage = false;
            deployOptions.checkOnly = false;
            deployOptions.ignoreWarnings = false;
            deployOptions.performRetrieve = false;
            deployOptions.purgeOnDelete = false;
            deployOptions.rollbackOnError = true;
            deployOptions.singlePackage = true;     
            MetadataService.AsyncResult asyncResult = service.deploy(zip, DeployOptions);
            asyncId = asyncResult.id;
        } catch(Exception ex) {
            ApexPages.addMessages(ex);
        }
    }

    class ZipContent {
        public String fileName { get; private set; }
        public String content { get; private set; }
        public ZipContent(String fileName, String content) {
            this.fileName = fileName;
            this.content = content;
        }
    }

    class AccessNowSetupException extends Exception {}
}