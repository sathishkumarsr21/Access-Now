global class PostInstallClass implements InstallHandler {
  global void onInstall(InstallContext context) {
    if(context.previousVersion() == null) {
      EncryptionUtils.setupEncryption();
    }
  }
}