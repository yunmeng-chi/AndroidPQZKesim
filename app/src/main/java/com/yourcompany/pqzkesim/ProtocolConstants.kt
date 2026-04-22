package com.yourcompany.pqzkesim

object ProtocolConstants {
    // 运营商域标识符（测试环境用，生产环境替换为真实MNO ID）
    const val DOMAIN_ID = "com.mno.test"

    // 密码学原语统一标准
    const val HASH_ALGORITHM = "SHA-256"
    const val MAC_ALGORITHM = "HmacSHA256"

    // 超时配置
    const val FACE_CAPTURE_TIMEOUT_MS = 10000L
    const val NETWORK_TIMEOUT_MS = 8000L
}