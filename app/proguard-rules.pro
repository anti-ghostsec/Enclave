-keep class org.bouncycastle.crypto.generators.Argon2BytesGenerator { *; }
-keep class org.bouncycastle.crypto.params.Argon2Parameters** { *; }
-dontwarn org.bouncycastle.**
# Enclave's own code is small; keep it whole so nothing the vault format depends on is renamed.
-keep class app.enclave.** { *; }
