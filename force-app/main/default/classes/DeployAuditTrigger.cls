public class DeployAuditTrigger {
    private static String API_VERSION = '42.0';

    public String asyncId { get; private set; }

    @testvisible private List<String> objectNames;
    private Boolean deploy;

    public List<ZipContent> zipContents { get {
        List<ZipContent> ret = new List<ZipContent>();

        List<String> classNames = new List<String>();
        List<String> triggerNames = new List<String>();

        List<String> triggerMemberNames = new List<String>();
        List<String> classMemberNames = new List<String>();

        for (String objectName : objectNames) {
            Map<String, String> cn = getTriggerClassNames(objectName);
            String className = cn.get('class');
            String triggerName = cn.get('trigger');

    	    classNames.add(className);
	        triggerNames.add(triggerName);

            triggerMemberNames.add('<members>' + triggerName + '</members>');
            classMemberNames.add('<members>' + className + '</members>');
        }

        if (deploy) {
            ret.add(new ZipContent('package.xml', '<?xml version="1.0" encoding="UTF-8"?><Package xmlns="http://soap.sforce.com/2006/04/metadata"><types>' + String.join(triggerMemberNames, '\n') + '<name>ApexTrigger</name></types><types>' + String.join(classMemberNames, '\n') + '<name>ApexClass</name></types><version>' + API_VERSION + '</version></Package>'));
            for (Integer i = 0; i < objectNames.size(); i++) {
                ret.add(new ZipContent('classes/' + classNames[i] + '.cls-meta.xml', '<?xml version="1.0" encoding="UTF-8"?><ApexClass xmlns="http://soap.sforce.com/2006/04/metadata"><apiVersion>' + API_VERSION + '</apiVersion><status>Active</status></ApexClass>'));
                ret.add(new ZipContent('classes/' + classNames[i] + '.cls', '@istest(seealldata=true)\nprivate class ' + classNames[i] + ' {\n\nprivate static testmethod void test() {\n\ntry { update [select Id from ' + objectNames[i] + ' limit 1]; } catch(Exception ex) {}\n\ntry { insert new ' + objectNames[i] + '(); } catch(Exception ex) {} }\n\n}'));
                ret.add(new ZipContent('triggers/' + triggerNames[i] + '.trigger-meta.xml', '<?xml version="1.0" encoding="UTF-8"?><ApexTrigger xmlns="http://soap.sforce.com/2006/04/metadata"><apiVersion>' + API_VERSION + '</apiVersion><status>Active</status></ApexTrigger>'));
                ret.add(new ZipContent('triggers/' + triggerNames[i] + '.trigger', 'trigger ' + triggerNames[i] + ' on ' + objectNames[i] + ' (after insert, after update, after delete, after undelete)\n{ accessnow.AuditFuncs.auditRecords(); }'));
            }
        } else {
            ret.add(new ZipContent('package.xml', '<?xml version="1.0" encoding="UTF-8"?><Package xmlns="http://soap.sforce.com/2006/04/metadata"><version>' + API_VERSION + '</version></Package>'));
            ret.add(new ZipContent('destructiveChanges.xml', '<?xml version="1.0" encoding="UTF-8"?><Package xmlns="http://soap.sforce.com/2006/04/metadata"><types>' + String.join(triggerMemberNames, '\n') + '<name>ApexTrigger</name></types><types>' + String.join(classMemberNames, '\n') + '<name>ApexClass</name></types><version>' + API_VERSION + '</version></Package>'));
        }
        return ret;
    } }

    public DeployAuditTrigger() {
        objectNames = ApexPages.currentPage().getParameters().get('objectName').split(',');
        deploy = ApexPages.currentPage().getParameters().get('deploy') == '1';
    }

    public void deploy() {
        try {
            Map<String, Schema.SObjectType> objs = Schema.getGlobalDescribe();
            List<String> testRuns = new List<String>();
            for (String objectName : objectNames) {
	            if (!objs.containsKey(objectName)) throw new DeployAuditTriggerException(String.format(Label.ERR_InvalidObjectAPIName, new List<String> { objectName }));
                testRuns.add(getTriggerClassNames(objectName).get('class'));
            }

            String zip = ApexPages.currentPage().getParameters().get('zip');
    
            MetadataService.MetadataPort service = new MetadataService.MetadataPort();
            service.SessionHeader = new MetadataService.SessionHeader_element();
            service.SessionHeader.sessionId = UserInfo.getSessionId();
    
            MetadataService.DeployOptions deployOptions = new MetadataService.DeployOptions();
            deployOptions.testLevel = 'RunSpecifiedTests';

            deployOptions.runTests = testRuns;

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

    public Map<String, String> getTriggerClassNames(String c) {
        c = c.replace('__', '_').toLowerCase();
        String d = 'AccessNowAudit' + 'Test' + c;
        if (d.length() > 40) {
            // switch to md5
            String md5Name = getMD5(c);
            return new Map<String, String> {
                'class' => 'ACNW_A_' + md5Name,
                'trigger' => 'ACNW_A_' + c
            };
        } else {
            // go with this
            return new Map<String, String> {
                'class' => d,
                'trigger' => 'AccessNowAudit' + 'Trigger' + c
            };
        }
    }
    public String getMD5(String s) {
		return EncodingUtil.convertToHex(Crypto.generateDigest('MD5', Blob.valueOf(s)));
    }
    class ZipContent {
        public String fileName { get; private set; }
        public String content { get; private set; }
        public ZipContent(String fileName, String content) {
            this.fileName = fileName;
            this.content = content;
        }
    }
    class DeployAuditTriggerException extends Exception {}
}