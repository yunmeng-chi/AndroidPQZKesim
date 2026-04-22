package com.yourcompany.pqzkesim

import android.graphics.Bitmap
import android.util.Log


/**
 * PQ-ZK-eSIM 底层算法库调度器
 * 职责：驱动底层C算法库执行密码协议，Java层仅做数据透传
 */
object NativeLib {
    private const val TAG = "PQZK-Native"

    // 增加初始化状态标志位
    @Volatile var isDetectorInitialized = false
        private set

    init {
        try {
            System.loadLibrary("pqzkesim") // 确保这里的名字和 CMakeLists 里的 project 一致
            Log.d("PQZK-Native", "库文件 pqzkesim 加载成功")
        } catch (e: UnsatisfiedLinkError) {
            Log.e("PQZK-Native", "库文件加载失败: ${e.message}")
        }
    }

    /**
     * 初始化检测器（封装层）
     */
    fun initDetector(modelPath: String): Boolean {
        if (isDetectorInitialized) {
            Log.d(TAG, "检测器已初始化，跳过重复操作")
            return true
        }
        return try {
            val success = nativeInitDetector(modelPath)
            isDetectorInitialized = success
            Log.d(TAG, "检测器初始化结果: $success, 路径: $modelPath")
            success
        } catch (e: Exception) {
            Log.e(TAG, "检测器初始化异常", e)
            false
        }
    }
    /**
     * 提取人脸特征并写入 latestRBio 数组
     * @param matAddr OpenCV Mat 的原生地址
     * @param latestRBio 接收特征的字节数组
     */
    fun processFaceAndGetRbio(matAddr: Long, latestRBio: ByteArray): Int {
        if (!isDetectorInitialized) {
            Log.e(TAG, "❌ 检测器未初始化，无法提取特征！请先调用 initDetector()")
            return -1
        }
        return try {
            val ret = nativeProcessFaceAndGetRbio(matAddr, latestRBio)
            Log.d(TAG, "特征提取返回值: $ret, 数据非零: ${latestRBio.any { it != 0.toByte() }}")
            ret
        } catch (e: Exception) {
            Log.e(TAG, "特征提取JNI异常", e)
            -2
        }
    }

    // --- 原生 JNI 函数声明（重命名避免混淆） ---
    private external fun nativeInitDetector(modelPath: String): Boolean
    private external fun nativeProcessFaceAndGetRbio(matAddr: Long, latestRBio: ByteArray): Int
    // --- 注册阶段接口  ---

    /**
     * 提取人脸特征：调用 OpenCV DNN (YuNet+SFace) [cite: 53]
     */
    external fun extractFaceFeature(bitmap: Bitmap): ByteArray

    /**
     * 获取设备专属静态 Salt [cite: 54]
     */
    external fun getDeviceStaticSalt(): ByteArray

    /**
     * 计算 Merkle 树根 R_bio：输入特征和 Salt，返回 Hash 结果 [cite: 54]
     */
    external fun buildMerkleRoot(
        features: Array<ByteArray>,
        salt: ByteArray
    ): ByteArray

    /**
     * 执行原生注册协议：生成公钥 T 并通过 eUICC 模拟器存储私钥 S [cite: 51, 55]
     * @return 0 表示成功，其他表示错误码
     */
    // 修改后：增加 path 参数
    external fun nativeRegisterDevice(rBio: ByteArray, nvramDirPath: String): Int


    // --- 认证阶段接口 (对应文档 3.4) ---

    /**
     * 阶段 1：本地预计算 (PQC_PreCompute + Commit) [cite: 87]
     */
    external fun pqcPreCompute(): Int

    /**
     * 阶段 4-5：生成证明 (ComputeZ_and_Mask + Aggregate) [cite: 87]
     * Java 层不生成掩码 M_mask，由 C 层内部生成 [cite: 203]
     */
    external fun pqcComputeAndAggregate(cSeed: ByteArray, m1: ByteArray): ByteArray

    // 项目核心JNI接口
    external fun PQC_eUICC_Commit(nvramDir: String, outWSec: ByteArray, outMacW: ByteArray): Int
    external fun PQC_PreCompute(inWSec: ByteArray, outWTotal: ByteArray, outSeedY: ByteArray): Int
    external fun PQC_GenChallenge(commW: ByteArray, cSeed: ByteArray, outCAgg: ByteArray): Int
    external fun PQC_ComputeZ_and_Mask(
        nvramDir: String, cAgg: ByteArray, cSeed: ByteArray,
        rDynamic: ByteArray, hashM2: ByteArray, authToken: ByteArray, outZMasked: ByteArray
    ): Int
    external fun PQC_LPA_Aggregate(zMaskedIn: ByteArray, seedY: ByteArray, outZFinal: ByteArray): Int
    // 从NVRAM读取真实计数器ctr_local
    external fun PQC_Get_Current_Ctr(nvramDir: String): Long


    // --- 设备状态获取 (对应文档 3.3) ---

    /**
     * 获取设备唯一标识符 EID [cite: 63]
     */
    external fun getEID(): String

    /**
     * 获取最后一次成功认证的时间戳 [cite: 65]
     */
    external fun getLastAuthTime(): String

    /**
     * 检查本地是否已完成注册 [cite: 20]
     */
    external fun isRegistered(nvramDirPath: String): Int

    external fun extractFingerprintFeature(): ByteArray
}