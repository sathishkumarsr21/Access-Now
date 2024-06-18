@istest
private class AccessNowSetupTest {
    private static testmethod void test() {
        AccessNowSetup ans = new AccessNowSetup();
        ans.setupUser();
        ans.remoteSiteSettingDeploy();
        ans.deploy();
        Object o = ans.accessNowSiteUserSetup;
        o = ans.accessNowSiteSetup;
        o = ans.accessNowCustomSettingSetup;
        o = ans.siteZipContents;
        o = ans.remoteSiteSettingZipContents;
    }
    private static testmethod void test2() {
        AccessNowSetup ans = new AccessNowSetup();
        ans.cachedSiteURL = 'http://somewhere.com';
        ans.cachedSite = new Site();

        ans.setupUser();
        ans.remoteSiteSettingDeploy();
        ans.deploy();
        Object o = ans.accessNowSiteUserSetup;
        o = ans.accessNowSiteSetup;
        o = ans.accessNowCustomSettingSetup;
        o = ans.siteZipContents;
        o = ans.remoteSiteSettingZipContents;        
    }
}