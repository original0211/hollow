plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
}

android {
    namespace = "eu.org.brodydung.hollow"
    compileSdk = 34

    defaultConfig {
        applicationId = "eu.org.brodydung.hollow" // D8 (NP-1114-28 §10, approved)
        minSdk = 26 // Android 8.0 floor (task book)
        targetSdk = 34 // D4
        // Versioning rule (M3-5, runbook §1): versionCode increments
        // by exactly 1 on EVERY release build that leaves the repo;
        // versionName is semver — M3 MVP line is 0.x.
        versionCode = 10
        versionName = "0.2.8"
        ndk {
            // D5: arm64-v8a only for the MVP.
            abiFilters += listOf("arm64-v8a")
        }
    }

    signingConfigs {
        // Release signing comes from the environment ONLY (CI Secrets,
        // M3-5/D9): no keystore file or password ever lives in the
        // repo. When the env is absent (local dev), assembleRelease
        // produces an unsigned APK instead of failing — CI always
        // provides the env (see android-build.yml release job).
        create("release") {
            val ksFile = System.getenv("HOLLOW_KEYSTORE_FILE")
            if (ksFile != null) {
                storeFile = file(ksFile)
                storePassword = System.getenv("HOLLOW_KEYSTORE_PASSWORD")
                keyAlias = System.getenv("HOLLOW_KEY_ALIAS")
                keyPassword = System.getenv("HOLLOW_KEY_PASSWORD")
            }
        }
    }

    buildTypes {
        release {
            // M3-5 shrinking decision (runbook §1): R8 minify ON for
            // the Kotlin shell with explicit keeps for the gomobile
            // JNI seam (proguard-rules.pro); resource shrinking OFF
            // (the UI is programmatic — there is nothing meaningful
            // to shrink and the risk/benefit is upside-down). The Go
            // AAR is NOT symbol-stripped: panic stacks stay readable
            // for crash diagnosis (recorded trade-off, runbook §1).
            isMinifyEnabled = true
            isShrinkResources = false
            proguardFiles(
                getDefaultProguardFile("proguard-android-optimize.txt"),
                "proguard-rules.pro"
            )
            signingConfig = signingConfigs.getByName("release")
        }
    }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
    kotlinOptions {
        jvmTarget = "17"
    }
}

dependencies {
    implementation("com.google.zxing:core:3.5.3")
    // The gomobile-built core (android/core). CI binds it into this
    // folder before assembling; a local build must do the same (see
    // android/README.md). Absent AAR = compile error by design (fail
    // loud, never a silently coreless APK).
    implementation(files("libs/hollowcore.aar"))
    implementation("org.jetbrains.kotlin:kotlin-stdlib:2.0.20")
}
