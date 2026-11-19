plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.plugin.compose")
    id("org.jetbrains.kotlin.plugin.serialization")
}

android {
    namespace = "app.enclave"
    compileSdk = 37
    ndkVersion = "29.0.14206865"

    defaultConfig {
        applicationId = "app.enclave"
        minSdk = 29
        targetSdk = 36
        versionCode = 10
        versionName = "0.5.3"
        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
        // Phones, and x86_64 for emulators and PCs running Android, which can't run ARM code.
        ndk { abiFilters += listOf("arm64-v8a", "x86_64") }
    }

    sourceSets.getByName("main").jniLibs.directories.add(layout.buildDirectory.dir("jniLibs").get().asFile.path)

    // Release signing comes from your user-level ~/.gradle/gradle.properties (never from this
    // repo): ENCLAVE_STORE_FILE, ENCLAVE_STORE_PASSWORD, ENCLAVE_KEY_ALIAS, ENCLAVE_KEY_PASSWORD.
    val storeFile = providers.gradleProperty("ENCLAVE_STORE_FILE").orNull
    signingConfigs {
        if (storeFile != null) create("release") {
            this.storeFile = file(storeFile)
            storePassword = providers.gradleProperty("ENCLAVE_STORE_PASSWORD").get()
            keyAlias = providers.gradleProperty("ENCLAVE_KEY_ALIAS").get()
            keyPassword = providers.gradleProperty("ENCLAVE_KEY_PASSWORD").get()
        }
    }

    buildTypes {
        release {
            isMinifyEnabled = true
            isShrinkResources = true
            proguardFiles(getDefaultProguardFile("proguard-android-optimize.txt"), "proguard-rules.pro")
            if (storeFile != null) signingConfig = signingConfigs.getByName("release")
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    buildFeatures {
        compose = true
    }
}

dependencies {
    implementation(platform("androidx.compose:compose-bom:2026.09.00"))
    implementation("androidx.compose.ui:ui")
    implementation("androidx.compose.material3:material3")
    implementation("androidx.compose.material:material-icons-extended")
    implementation("androidx.activity:activity-compose:1.13.0")
    implementation("androidx.core:core-ktx:1.19.1")
    implementation("androidx.lifecycle:lifecycle-process:2.11.0")
    implementation("androidx.lifecycle:lifecycle-runtime-compose:2.11.0")
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-android:1.11.0")
    implementation("org.jetbrains.kotlinx:kotlinx-serialization-json:1.12.0")
    // Argon2id (lightweight API only; no JCA provider is registered)
    implementation("org.bouncycastle:bcprov-jdk18on:1.86")

    testImplementation("junit:junit:4.13.2")
    testImplementation("org.robolectric:robolectric:4.17")
    testImplementation("androidx.test:core:1.7.0")
    androidTestImplementation("androidx.test:runner:1.7.0")
    androidTestImplementation("androidx.test.ext:junit:1.3.0")
    androidTestImplementation("junit:junit:4.13.2")
}

// ---- Native code: the deniable storage crate, built with cargo ----------------------------

val nativeDir = rootProject.file("native")
val isWindows = System.getProperty("os.name").lowercase().contains("windows")
val ndkHost = when {
    isWindows -> "windows-x86_64"
    System.getProperty("os.name").lowercase().contains("mac") -> "darwin-x86_64"
    else -> "linux-x86_64"
}

// Each Android ABI the app ships for, with the Rust target that builds it.
val androidTargets = mapOf("arm64-v8a" to "aarch64-linux-android", "x86_64" to "x86_64-linux-android")

val cargoAndroid by tasks.registering(Exec::class) {
    description = "Builds the native library for Android (arm64 and x86_64)."
    workingDir = nativeDir
    inputs.dir(nativeDir.resolve("deniable/src"))
    inputs.dir(nativeDir.resolve("enclave-jni/src"))
    inputs.files(nativeDir.resolve("Cargo.toml"), nativeDir.resolve("Cargo.lock"))
    androidTargets.values.forEach { outputs.file(nativeDir.resolve("target/$it/release/libenclave_jni.so")) }
    commandLine(listOf("cargo", "build", "--release", "--locked", "-p", "enclave-jni") + androidTargets.values.flatMap { listOf("--target", it) })
    doFirst {
        val ndk = androidComponents.sdkComponents.sdkDirectory.get().asFile.resolve("ndk/${android.ndkVersion}")
        androidTargets.values.forEach { target ->
            val clang = ndk.resolve("toolchains/llvm/prebuilt/$ndkHost/bin/${target}29-clang" + if (isWindows) ".cmd" else "")
            environment("CARGO_TARGET_" + target.uppercase().replace('-', '_') + "_LINKER", clang.path)
        }
    }
}

val copyJniLibs by tasks.registering(Copy::class) {
    dependsOn(cargoAndroid)
    androidTargets.forEach { (abi, target) ->
        from(nativeDir.resolve("target/$target/release/libenclave_jni.so")) { into(abi) }
    }
    into(layout.buildDirectory.dir("jniLibs"))
}
tasks.named("preBuild") { dependsOn(copyJniLibs) }

// The same library built for this computer, so unit tests run the real storage code.
val hostLib = nativeDir.resolve(
    "target/release/" + when {
        isWindows -> "enclave_jni.dll"
        System.getProperty("os.name").lowercase().contains("mac") -> "libenclave_jni.dylib"
        else -> "libenclave_jni.so"
    },
)
val cargoHost by tasks.registering(Exec::class) {
    description = "Builds the native library for this computer, for unit tests."
    workingDir = nativeDir
    inputs.dir(nativeDir.resolve("deniable/src"))
    inputs.dir(nativeDir.resolve("enclave-jni/src"))
    outputs.file(hostLib)
    commandLine("cargo", "build", "--release", "--locked", "-p", "enclave-jni")
}
tasks.withType<Test>().configureEach {
    dependsOn(cargoHost)
    systemProperty("enclave.native", hostLib.path)
}
