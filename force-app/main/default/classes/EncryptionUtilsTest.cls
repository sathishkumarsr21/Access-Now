@istest
private class EncryptionUtilsTest {
    private static testmethod void test() {
        EncryptionUtils.setupEncryption();

        System.assert('H' == EncryptionUtils.decryptData(EncryptionUtils.encryptData('H')));
    }
}