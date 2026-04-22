@file:Suppress("UnstableApiUsage", "UseVersionCatalog")
plugins {
    alias(libs.plugins.android.application)
    alias(libs.plugins.jetbrains.kotlin.android)
}

android {
    namespace = "com.yourcompany.pqzkesim"
    sourceSets {
        getByName("main") {
            java.srcDirs("src/main/java")
        }
    }
    compileSdk = 34

    ndkVersion = "26.3.11579264"

    defaultConfig {
        applicationId = "com.yourcompany.pqzkesim"
        minSdk = 28
        targetSdk = 34
        versionCode = 1
        versionName = "1.0"

        externalNativeBuild {
            cmake {
                cppFlags += ""
                abiFilters += "arm64-v8a"
                // 强制链接 C++ 共享库
                arguments("-DANDROID_STL=c++_shared")
            }
        }
        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"

        // ========== 新增：安全权限配置（生物识别 + StrongBox 硬件安全） ==========
        manifestPlaceholders["android.permission.USE_BIOMETRIC"] = "true"
        manifestPlaceholders["android.permission.USE_STRONGBOX"] = "true"
    }

    externalNativeBuild {
        cmake {
            path = file("src/main/cpp/CMakeLists.txt")
            version = "3.22.1"
        }
    }

   // ========== 新增：证书资源配置（GSMA 证书存放目录） ==========
    sourceSets {
        getByName("main") {
            java.srcDirs("src/main/java")
            // 固定资源目录，兼容证书/布局/图片
            res.srcDirs("src/main/res")
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_11
        targetCompatibility = JavaVersion.VERSION_11
    }

    kotlinOptions {
        jvmTarget = "11"
    }

    buildFeatures {
        // ✅ 必须显式开启，否则项目里找不到 BuildConfig 类
        buildConfig = true
    }
    buildFeatures {
        viewBinding = true
    }
}

dependencies {
    implementation(libs.androidx.core.ktx)
    implementation(libs.androidx.appcompat)
    implementation(libs.material)
    implementation(libs.androidx.activity)
    implementation(libs.androidx.constraintlayout)
    testImplementation(libs.junit)
    androidTestImplementation(libs.androidx.junit)
    androidTestImplementation(libs.androidx.espresso.core)
    implementation("com.google.android.material:material:1.9.0")
    implementation("androidx.cardview:cardview:1.0.0")
    implementation("com.squareup.okhttp3:okhttp:4.12.0")
    // 生物特征识别库 (用于阶段零和阶段三的 TEE 模拟)
    implementation("androidx.biometric:biometric:1.2.0-alpha05")
    // 协程支持
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-android:1.10.1")
    // Jetpack Compose 相关依赖 (此处省略标准 Compose 依赖清单)
    implementation("androidx.lifecycle:lifecycle-runtime-ktx:2.8.7")
    implementation(fileTree(mapOf("dir" to "libs", "include" to listOf("*.jar", "*.aar"))))
    // 1. 确保这一行绝对存在且正确（指向你导入的 opencv 模块）
    implementation(project(":opencv"))

    // 2. 检查是否缺少了 lifecycle 相关的支持（OpenCV 预览需要它）
    implementation("androidx.lifecycle:lifecycle-common-java8:2.6.1")
}
