plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
    id("org.jetbrains.kotlin.plugin.compose")
}

android {
    namespace = "de.mykvm.client"
    compileSdk = 36

    defaultConfig {
        applicationId = "de.mykvm.client"
        // 26 is what the accessibility gesture API needs (StrokeDescription with
        // willContinue, for dragging). Below that there is no usable pointer.
        minSdk = 26
        targetSdk = 36
        versionCode = 1
        versionName = "0.1.0"
        ndk {
            abiFilters += "arm64-v8a"
        }
    }

    buildTypes {
        release {
            isMinifyEnabled = false
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    kotlinOptions {
        jvmTarget = "17"
    }

    buildFeatures {
        compose = true
    }

    sourceSets {
        getByName("main") {
            jniLibs.srcDirs("src/main/jniLibs")
        }
    }
}

dependencies {
    implementation("androidx.core:core-ktx:1.15.0")
    implementation("androidx.appcompat:appcompat:1.7.0")

    val compose = platform("androidx.compose:compose-bom:2024.12.01")
    implementation(compose)
    implementation("androidx.compose.material3:material3")
    implementation("androidx.compose.ui:ui")
    implementation("androidx.activity:activity-compose:1.9.3")
    implementation("androidx.lifecycle:lifecycle-runtime-compose:2.8.7")
}

/**
 * Builds the Rust core and drops the .so where the packager expects it.
 *
 * Wired into preBuild so there is no way to ship an APK carrying a stale
 * library — the mismatch between Kotlin and a months-old core would surface as
 * an UnsatisfiedLinkError at runtime, far from its cause.
 */
val cargoNdk by tasks.registering(Exec::class) {
    workingDir = file("../core")
    val ndkHome = System.getenv("ANDROID_NDK_HOME")
        ?: "${System.getProperty("user.home")}/Android/Sdk/ndk/29.0.14206865"
    val cargoBin = "${System.getProperty("user.home")}/.cargo/bin"

    environment("ANDROID_NDK_HOME", ndkHome)
    environment("PATH", "$cargoBin:${System.getenv("PATH")}")
    commandLine(
        "$cargoBin/cargo", "ndk",
        "-t", "arm64-v8a",
        "-o", file("src/main/jniLibs").absolutePath,
        "build", "--release",
    )
}

tasks.named("preBuild") {
    dependsOn(cargoNdk)
}
