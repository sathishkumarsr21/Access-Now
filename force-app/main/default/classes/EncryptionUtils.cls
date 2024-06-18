public class EncryptionUtils {
    private static String generateRandomString(Integer len) {
        final String chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyz';
        String randStr = '';
        while (randStr.length() < len) {
           Integer idx = Math.mod(Math.abs(Crypto.getRandomInteger()), chars.length());
           randStr += chars.substring(idx, idx+1);
        }
        return randStr;
    }

    public static void setupEncryption() {
        AccessNowPrivateConfig__c ac = AccessNowPrivateConfig__c.getOrgDefaults();
        if (Schema.SObjectType.AccessNowPrivateConfig__c.isCreateable() && Schema.SObjectType.AccessNowPrivateConfig__c.fields.Encryption_Key__c.isCreateable()) {
            ac.Encryption_Key__c = generateRandomString(32);
        	insert ac;
        }
    }

    // returns hex
    public static String encryptData(String strToEncrypt) {
        return EncodingUtil.convertToHex(Crypto.encryptWithManagedIV('AES256', Blob.valueOf(AccessNowPrivateConfig__c.getOrgDefaults().Encryption_Key__c), Blob.valueOf(strToEncrypt)));
    }
    public static String decryptData(String hexData) {
        return Crypto.decryptWithManagedIV('AES256', Blob.valueOf(AccessNowPrivateConfig__c.getOrgDefaults().Encryption_Key__c), EncodingUtil.convertFromHex(hexData)).toString();
    }
}