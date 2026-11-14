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
        versionCode = 1
        versionName = "0.1.0"
        ndk {
            // D5: arm64-v8a only for the MVP.
            abiFilters += listOf("arm64-v8a")
        }
    }

    buildTypes {
        release {
            isMinifyEnabled = false // M3-5 decides shrinking; skeleton keeps mapping simple
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
    // The gomobile-built core (android/core). CI binds it into this
    // folder before assembling; a local build must do the same (see
    // android/README.md). Absent AAR = compile error by design (fail
    // loud, never a silently coreless APK).
    implementation(files("libs/hollowcore.aar"))
    implementation("org.jetbrains.kotlin:kotlin-stdlib:2.0.20")
}
