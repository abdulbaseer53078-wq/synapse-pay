plugins {
    id("com.android.library")
    id("org.jetbrains.kotlin.android")
    `maven-publish`
}

android {
    namespace = "com.synapsepay.android"
    compileSdk = 35
    defaultConfig {
        minSdk = 26 // java.util.Base64 and modern EC crypto
        consumerProguardFiles("consumer-rules.pro")
    }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
    kotlinOptions { jvmTarget = "17" }
    publishing { singleVariant("release") { withSourcesJar() } }
}

dependencies {
    implementation("androidx.appcompat:appcompat:1.7.0")
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-android:1.9.0")
    implementation("androidx.lifecycle:lifecycle-runtime-ktx:2.8.7")
}

publishing {
    publications {
        register<MavenPublication>("release") {
            groupId = "com.synapsepay"
            artifactId = "synapsepay-android"
            version = "0.1.0"
            afterEvaluate { from(components["release"]) }
        }
    }
}
