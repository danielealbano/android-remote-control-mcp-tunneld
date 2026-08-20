plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
}

android {
    namespace = "com.example.tunnelapp"
    compileSdk = 36
    defaultConfig {
        applicationId = "com.example.tunnelapp"
        minSdk = 33
        targetSdk = 36
        versionCode = 1
        versionName = "1.0"
    }
    buildTypes { getByName("debug") { isDebuggable = true } }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
    packaging {
        // Netty + BouncyCastle jars collide on these META-INF resources.
        resources.excludes += setOf(
            "META-INF/versions/9/OSGI-INF/MANIFEST.MF", "META-INF/DEPENDENCIES",
            "META-INF/LICENSE.md", "META-INF/LICENSE-notice.md", "META-INF/NOTICE.md",
            "META-INF/INDEX.LIST", "META-INF/io.netty.versions.properties", "META-INF/{AL2.0,LGPL2.1}",
        )
        jniLibs { useLegacyPackaging = true }
    }
}

kotlin {
    compilerOptions {
        jvmTarget.set(org.jetbrains.kotlin.gradle.dsl.JvmTarget.JVM_17)
    }
}

dependencies {
    implementation("com.squareup.okhttp3:okhttp:4.12.0") // 5.x requires compileSdk 37
    implementation("org.bouncycastle:bcpkix-jdk18on:1.85")
    implementation("org.bouncycastle:bcprov-jdk18on:1.85")
    implementation("io.ktor:ktor-server-core:3.4.0")  // Netty engine + platform Conscrypt terminate TLS;
    implementation("io.ktor:ktor-server-netty:3.4.0") // no explicit netty-* / conscrypt-android dep
}
