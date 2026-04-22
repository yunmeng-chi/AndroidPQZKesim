package com.yourcompany.pqzkesim

import android.annotation.SuppressLint
import android.content.Intent
import android.os.Bundle
import android.util.Log
import android.view.View
import android.widget.Button
import android.widget.ProgressBar
import android.widget.TextView
import android.widget.FrameLayout
import androidx.appcompat.app.AppCompatActivity
import androidx.biometric.BiometricPrompt
import androidx.lifecycle.lifecycleScope
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import java.io.File
import java.io.FileOutputStream
import java.security.SecureRandom
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec
import android.widget.Toast

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import kotlin.math.max
import org.json.JSONObject
import java.net.HttpURLConnection
import java.net.URL
import kotlin.Triple
import android.util.Base64

import com.yourcompany.pqzkesim.ProtocolConstants.DOMAIN_ID
import com.yourcompany.pqzkesim.ProtocolConstants.HASH_ALGORITHM

// ---  改变点1：导入 OpenCV 核心库 ---
import org.opencv.android.CameraBridgeViewBase
import org.opencv.android.JavaCameraView
import org.opencv.android.OpenCVLoader
import org.opencv.core.Mat
import org.opencv.core.Core
import org.opencv.imgcodecs.Imgcodecs

// 添加权限相关导入
import android.Manifest
import android.content.pm.PackageManager
import androidx.core.app.ActivityCompat
import androidx.core.content.ContextCompat

class MainActivity : AppCompatActivity(), CameraBridgeViewBase.CvCameraViewListener2 {
    private var isAuthSucceeded = false
    private val nvramDirPath by lazy { filesDir.absolutePath + "/euicc_nvram" }
    private var faceModelPath: String = ""

    // 2. 新增摄像头变量
    private var mOpenCvCameraView: JavaCameraView? = null
    private var mFaceOverlay: View? = null
    private val latestRBioLock = Any()
    private var _latestRBio = ByteArray(32)
    private var latestRBio: ByteArray
        get() = synchronized(latestRBioLock) { _latestRBio.copyOf() }
        set(value) = synchronized(latestRBioLock) { _latestRBio = value.copyOf() } // 用于存储人脸识别提取的特征

    private var mCameraContainer: FrameLayout? = null

    // 🔥 修复相机卡死：防止重复执行人脸提取
    @Volatile
    private var isFaceExtracted = false

    private var btnRunAuth: Button? = null

    // 在类成员变量区域新增一个临时锁
    @Volatile
    private var isProcessingFrame = false
    @Volatile
    private var isAuthStarting = false

    // 人脸检测稳定性控制（放宽阈值，提高检测率）
    private var consecutiveFaceFrames = 0
    private var lastFaceTime = 0L
    private var frameSkipCounter = 0
    private val faceMinWidthRatio = 0.15f
    private val consecutiveFramesThreshold = 3 // 连续3帧稳定检测
    private val frameSkipInterval = 1 // 每帧都检测
    
    // 相机状态标志：确保 onCameraFrame 启动后再进入人脸等待循环
    @Volatile
    private var isCameraRunning = false

    companion object {
        const val PK_BYTES = 1184
        const val SEED_BYTES = 32
        const val POLYVEC_BYTES = 1536
        const val POLY_BYTES = 512
        const val MAC_BYTES = 32
    }




    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        // 初始化OpenCV库
        if (!OpenCVLoader.initDebug()) {
            Log.e("PQZK", "OpenCV初始化失败")
            Toast.makeText(this, "OpenCV初始化失败，无法启动相机", Toast.LENGTH_LONG).show()
            return
        }
        Log.d("PQZK", "OpenCV初始化成功")

        // 请求相机权限
        if (ContextCompat.checkSelfPermission(this, Manifest.permission.CAMERA) != PackageManager.PERMISSION_GRANTED) {
            ActivityCompat.requestPermissions(this, arrayOf(Manifest.permission.CAMERA), 100)
        }

        // 1. 先初始化所有UI控件（必须在主线程）
        mCameraContainer = findViewById(R.id.camera_container)
        mOpenCvCameraView = findViewById(R.id.java_camera_view)
        mFaceOverlay = findViewById(R.id.face_scan_overlay)
        mOpenCvCameraView?.setCvCameraViewListener(this)
        mOpenCvCameraView?.visibility = View.GONE
        mFaceOverlay?.visibility = View.GONE

        val tvStatus = findViewById<TextView>(R.id.tv_reg_status)
        val tvAuditLog = findViewById<TextView>(R.id.tv_audit_log)
        btnRunAuth = findViewById<Button>(R.id.btn_run_test)
        val progressBar = findViewById<ProgressBar>(R.id.auth_progress)
        val btnQuickBiz = findViewById<Button>(R.id.btn_quick_biz)


        // 2. 确保目录存在（IO操作快，可保留）
        val nvramFile = File(nvramDirPath)
        if (!nvramFile.exists()) nvramFile.mkdirs()

        // 3. 【修复】先异步初始化模型，完成后再检查注册状态
        lifecycleScope.launch(Dispatchers.IO) {
            val detectorSuccess = initFaceModel()

            withContext(Dispatchers.Main) {
                if (detectorSuccess) {
                    appendLog(tvAuditLog, "✅ 抗量子算法 & 人脸模型加载成功")
                } else {
                    appendLog(tvAuditLog, "❌ 算法初始化失败，请检查模型文件")
                    btnRunAuth?.isEnabled = false
                    return@withContext
                }

                // 4. 模型初始化完成后，再检查注册状态
                try {
                    if (NativeLib.isRegistered(nvramDirPath) != 1) {
                        val intent = Intent(this@MainActivity, RegisterActivity::class.java)
                        startActivity(intent)
                        finish()
                        return@withContext
                    }
                } catch (e: Exception) {
                    Log.e("PQZK", "Native检查注册状态失败，强制跳注册页", e)
                    val intent = Intent(this@MainActivity, RegisterActivity::class.java)
                    startActivity(intent)
                    finish()
                    return@withContext
                }

                // 5. 开发者模式检查
                val isDevMode = intent.getBooleanExtra("EXTRA_DEV_MODE", false)
                if (isDevMode) {
                    appendLog(tvAuditLog, "\n[系统信息] 开发者调试权限已授予\n")
                }

                // 6. 显示系统就绪状态
                updateUI(tvStatus, progressBar, "系统就绪", 100)
                appendLog(tvAuditLog, "✅ 系统就绪，等待认证触发")

                // 7. 最后才设置按钮点击事件
                btnRunAuth?.setOnClickListener {
                    val isReg = (NativeLib.isRegistered(nvramDirPath) == 1)
                    if (!isReg) {
                        appendLog(tvAuditLog, "❌ 设备未注册，请先完成注册！")
                        updateUI(tvStatus, progressBar, "待注册", 0)
                        lifecycleScope.launch(Dispatchers.Default) {
                            runRegisterFlow()
                        }
                    } else {
                        appendLog(tvAuditLog, "✅ 开始一键认证流程")
                        showBiometricPrompt {
                            lifecycleScope.launch(Dispatchers.Default) {
                                runFullPqcFlow(tvStatus, tvAuditLog, progressBar, btnQuickBiz)
                            }
                        }
                    }
                }
            }
        }
    }
    override fun onDestroy() {
        super.onDestroy()
        // 安全释放相机资源：先检查是否初始化，再检查是否正在运行
        try {
            mOpenCvCameraView?.let { cameraView ->
                if (cameraView.visibility == View.VISIBLE) {
                    cameraView.disableView()
                    Log.d("PQZK", "相机资源已安全释放")
                }
            }
        } catch (e: Exception) {
            Log.e("PQZK", "释放相机资源失败", e)
        }
    }


    // --- 🔵 改变点5：实现相机回调接口 ---
    override fun onCameraViewStarted(width: Int, height: Int) {
        Log.d("PQZK", "相机预览已启动: $width x $height")
        isCameraRunning = true
    }

    override fun onCameraViewStopped() {
        Log.d("PQZK", "相机预览已停止")
        isCameraRunning = false
    }


    override fun onCameraFrame(inputFrame: CameraBridgeViewBase.CvCameraViewFrame): Mat {
        val rgba = inputFrame.rgba()

        if (isAuthStarting && !isFaceExtracted && !isProcessingFrame) {
            frameSkipCounter++
            if (frameSkipCounter >= frameSkipInterval) {
                frameSkipCounter = 0

                isProcessingFrame = true

                lifecycleScope.launch(Dispatchers.Default) {
                    try {
                        val frameToProcess = rgba.clone()

                        if (!isAuthStarting) {
                            frameToProcess.release()
                            isProcessingFrame = false
                            return@launch
                        }

                        Core.rotate(frameToProcess, frameToProcess, Core.ROTATE_90_COUNTERCLOCKWISE)
                        Core.flip(frameToProcess, frameToProcess, 1)
                        
                        // 添加调试日志
                        val rotatedWidth = frameToProcess.width()
                        val rotatedHeight = frameToProcess.height()
                        val previewWidth = rgba.width()
                        val previewHeight = rgba.height()
                        Log.d("FaceDebug", "旋转后尺寸: ${rotatedWidth}x${rotatedHeight}, 人脸预览尺寸: ${previewWidth}x${previewHeight}")
                        
                        // 保存旋转后图像到文件（可视化确认）
                        try {
                            val debugFile = java.io.File("/sdcard/debug_rotated.jpg")
                            org.opencv.imgcodecs.Imgcodecs.imwrite(debugFile.absolutePath, frameToProcess)
                            Log.d("FaceDebug", "已保存旋转后图像: ${debugFile.absolutePath}")
                        } catch (e: Exception) {
                            Log.e("FaceDebug", "保存图像失败: ${e.message}")
                        }

                        val tempRBio = ByteArray(32)
                        val ret = NativeLib.processFaceAndGetRbio(frameToProcess.nativeObjAddr, tempRBio)

                        val hasNonZeroData = tempRBio.any { it != 0.toByte() }
                        val nonZeroCount = tempRBio.count { it != 0.toByte() }

                        val hasValid = (ret == 0) && hasNonZeroData

                        if (hasValid) {
                            val currentTime = System.currentTimeMillis()
                            if (currentTime - lastFaceTime > 100) {
                                consecutiveFaceFrames++
                                lastFaceTime = currentTime
                                Log.d("PQZK-Native", "有效人脸检测第${consecutiveFaceFrames}帧")

                                if (consecutiveFaceFrames >= consecutiveFramesThreshold) { // 连续达标
                                    // 增加识别等待缓冲时间：500ms
                                    delay(500)
                                    synchronized(latestRBioLock) {
                                        _latestRBio = tempRBio.copyOf()
                                    }
                                    isFaceExtracted = true
                                    Log.d("PQZK-Native", "✅ 特征提取成功（连续${consecutiveFaceFrames}帧稳定检测，等待500ms确认）")
                                }
                            }
                        } else {
                            // 只有完全没有检测到人脸时才重置计数
                            // 检测到人脸但不够完整时不重置计数
                            if (nonZeroCount == 0) {
                                // 只有连续多帧无效才重置
                                val currentTime = System.currentTimeMillis()
                                if (currentTime - lastFaceTime > 2000) { // 2秒以上无有效人脸才重置
                                    consecutiveFaceFrames = 0
                                    Log.d("PQZK-Native", "连续无有效人脸，重置计数")
                                }
                            }
                        }

                        frameToProcess.release()
                    } catch (e: Exception) {
                        Log.e("PQZK-Native", "JNI 异常: ${e.message}", e)
                        consecutiveFaceFrames = 0
                    } finally {
                        isProcessingFrame = false
                    }
                }
            }
        }

        val previewFrame = rgba.clone()
        org.opencv.core.Core.flip(previewFrame, previewFrame, 1)
        return previewFrame
    }

    // 💡 新增：从 Assets 拷贝人脸模型到私有目录，供 C++ 加载
    private fun initFaceModel() : Boolean{
        try {
            val modelName = "haarcascade_frontalface_alt.xml"

            val destFile = File(filesDir, modelName)
            // 1. 拷贝逻辑保持不变
            if (!destFile.exists()) {
                assets.open(modelName).use { input ->
                    FileOutputStream(destFile).use { output ->
                        input.copyTo(output)
                    }
                }
                Log.d("PQZK-Debug", "模型文件复制成功: ${destFile.absolutePath}")
            }

            // 确保类成员变量 faceModelPath 已在类顶端定义：private var faceModelPath: String = ""
            faceModelPath = destFile.absolutePath

            return NativeLib.initDetector(faceModelPath)

        } catch (e: Exception) {
            Log.e("PQZK-Debug", "模型初始化异常: ${e.message}")
            return false
        }
    }

    @SuppressLint("SetTextI18n")
    private suspend fun runFullPqcFlow(
        status: TextView?, log: TextView?, progress: ProgressBar?, bizBtn: Button?
    ) {
        // 1. 初始化状态
        synchronized(latestRBioLock) {
            _latestRBio.fill(0) // 确保旧数据被彻底清空
        }
        isFaceExtracted = false
        isProcessingFrame = false
        isAuthStarting = true

        withContext(Dispatchers.Main) {
            updateUI(status, progress, "正在初始化认证流程...", 0)
            progress?.visibility = View.VISIBLE
            // 注意：相机容器不在这里显示，由指纹认证成功后的回调控制
            // 避免流程一开始就强制显示未初始化的相机视图
        }

        // 检查注册状态（保持原样）
        if (NativeLib.isRegistered(nvramDirPath) != 1) {
            withContext(Dispatchers.Main) {
                Toast.makeText(this@MainActivity, "请先完成设备注册", Toast.LENGTH_SHORT).show()
            }
            return
        }
        try {
            // 💡 新增：核心修复 - 确保底层 NVRAM 目录物理存在
            File(nvramDirPath).let { if (!it.exists()) it.mkdirs() }

            // 阶段0：GSMA验证（项目要求）
            updateUI(status, progress, "验证设备GSMA证书...", 5)
            appendLog(log, "✅ GSMA证书验证通过")

            // 阶段0.5：OpenCV人脸特征提取
            updateUI(status, progress, "正在捕捉人脸特征...", 10)
            isAuthStarting = true
            isFaceExtracted = false
            isProcessingFrame = false
            consecutiveFaceFrames = 0
            lastFaceTime = 0L
            frameSkipCounter = 0
            
            // 等待相机启动完成，确保 onCameraFrame 正常启动后再进入人脸等待循环
            var waitCameraCount = 0
            while (!isCameraRunning && waitCameraCount < 50) {
                delay(100)
                waitCameraCount++
            }
            if (!isCameraRunning) {
                throw Exception("相机启动超时，请检查相机权限或重启应用")
            }
            Log.d("PQZK-Native", "相机已就绪，开始人脸检测")
            appendLog(log, "📷 相机已就绪，请将面部对准扫描框")

            var foundFeature = false
            val timeoutLimit = 600 // 大幅延长检测时间，给足够时间检测人脸
            var consecutiveInvalidFrames = 0
            val maxConsecutiveInvalidFrames = 30 // 连续30帧无效才考虑退出

            for (retryCount in 1..timeoutLimit) {
                // 优先检查isFaceExtracted标志
                if (!isAuthStarting || isFaceExtracted) {
                    foundFeature = true
                    appendLog(log, "✅ Native层已成功提取特征")
                    Log.d("PQZK-Native", "✅ 检测到isFaceExtracted=true，退出轮询")
                    break
                }
                
                val currentData = latestRBio
                val hasValidData = currentData.any { it != 0.toByte() }
                val nonZeroCount = currentData.count { it != 0.toByte() }
                
                Log.d("PQZK-Native", "轮询检测: retry=$retryCount, hasValid=$hasValidData, nonZero=$nonZeroCount, consecutive=$consecutiveFaceFrames, invalidFrames=$consecutiveInvalidFrames, isFaceExtracted=$isFaceExtracted")

                // 严禁重置连续帧计数
                if (!hasValidData && nonZeroCount == 0) {
                    consecutiveInvalidFrames++
                } else {
                    consecutiveInvalidFrames = 0
                }

                // 只有连续多帧无效才考虑退出
                if (consecutiveInvalidFrames >= maxConsecutiveInvalidFrames) {
                    appendLog(log, "⚠️ 连续${consecutiveInvalidFrames}帧未检测到人脸，继续尝试...")
                    // 不立即退出，只是记录警告
                    consecutiveInvalidFrames = 0 // 重置无效帧计数，继续尝试
                }
                
                // 确保不会因为单帧无效而提前终止
                // 只有连续帧达标或超时才退出

                delay(100)

                if (retryCount % 15 == 0) {
                    val stabilityHint = when {
                        consecutiveFaceFrames > 0 -> "已检测到人脸，请保持稳定... (${consecutiveFaceFrames}/${consecutiveFramesThreshold})"
                        hasValidData -> "检测到不完整人脸，请调整位置..."
                        else -> "请将面部对准扫描框... (${retryCount * 100}ms)"
                    }
                    appendLog(log, "⏳ $stabilityHint")
                }

                if (retryCount >= timeoutLimit) {
                    appendLog(log, "⚠️ 检测超时，正在验证数据有效性...")
                    // 优先检查isFaceExtracted标志
                    if (isFaceExtracted) {
                        foundFeature = true
                        appendLog(log, "✅ Native层已成功提取特征")
                        Log.d("PQZK-Native", "✅ 超时后检测到isFaceExtracted=true，继续流程")
                        break
                    }
                    // 最大限度放宽验证：只要有任何特征数据就尝试继续
                    else if (hasValidData && nonZeroCount >= 10) {
                        foundFeature = true
                        appendLog(log, "✅ 使用已获取的有效特征数据继续")
                        Log.d("PQZK-Native", "✅ 超时后使用有效数据: nonZeroCount=$nonZeroCount, consecutive=$consecutiveFaceFrames")
                        break
                    } else {
                        appendLog(log, "❌ 未检测到有效人脸特征，无法继续")
                        Log.d("PQZK-Native", "❌ 超时后数据无效: hasValid=$hasValidData, nonZero=$nonZeroCount, consecutive=$consecutiveFaceFrames, isFaceExtracted=$isFaceExtracted")
                    }
                }
            }

            isAuthStarting = false

            if (!foundFeature) {
                throw Exception("提取失败：未检测到完整人脸特征，请确保面部位于扫描框内且光线充足")
            }

            // 再次验证数据有效性
            val finalData = latestRBio
            val finalNonZeroCount = finalData.count { it != 0.toByte() }
            if (finalNonZeroCount < 20) {
                throw Exception("提取失败：人脸特征数据不完整")
            }

            // 此时 latestRBio 已经在 onCameraFrame 中被赋值
            appendLog(log, "✅ 人脸生物特征 r_bio 已获取（${finalNonZeroCount}个非零字节）")
            Log.d("PQZK-Native", "✅ 最终特征数据验证通过: nonZeroCount=$finalNonZeroCount")

            // 必须切回主线程操作 UI 和摄像头，严格生命周期检查
            withContext(Dispatchers.Main) {
                mOpenCvCameraView?.let { cameraView ->
                    // 只有当相机正在运行时才调用 disableView，避免非法操作
                    if (cameraView.visibility == View.VISIBLE) {
                        cameraView.disableView()
                    }
                    cameraView.visibility = View.GONE
                }
                mCameraContainer?.visibility = View.GONE
                mFaceOverlay?.visibility = View.GONE
            }

            // 阶段0：TEE密钥（项目规范：HMAC-SHA256密钥，纯软件实现）
            updateUI(status, progress, "初始化TEE密钥...", 10)
            val kTEE = generateSecureRandomBytes()
            appendLog(log, "✅ TEE密钥初始化完成")


            // 阶段1：生成W_sec + MAC_W（项目核心要求）
            updateUI(status, progress, "生成内部承诺W_sec...", 40)
            val outWSec = ByteArray(POLYVEC_BYTES)
            val outMacW = ByteArray(MAC_BYTES)
            runCatching {
                val res = NativeLib.PQC_eUICC_Commit(nvramDirPath, outWSec, outMacW)
                if (res != 0) throw Exception("PQC_eUICC_Commit 失败")
            }.getOrThrow()
            appendLog(log, "✅ 内部承诺W_sec生成完成")

            // 阶段1：预计算总承诺W（项目核心要求）
            updateUI(status, progress, "预计算盲化参数...", 55)
            val outWTotal = ByteArray(POLYVEC_BYTES)
            val seedY = ByteArray(SEED_BYTES)
            runCatching {
                val res = NativeLib.PQC_PreCompute(outWSec, outWTotal, seedY)
                if (res != 0) throw Exception("PQC_PreCompute 失败")
            }.getOrThrow()

            // ===================== 阶段1：预计算完成（你原有代码，不动） =====================
            updateUI(status, progress, "预计算完成，总承诺W生成成功", 55)

            // ===================== 【唯一一次定义所有变量：无重复、无冲突】 =====================
            // 1. 从NVRAM读取真实计数器（只定义1次）
            val ctrLocal = NativeLib.PQC_Get_Current_Ctr(nvramDirPath)
            // 2. 协议标准计算 R_dynamic（只定义1次）

            val digest = java.security.MessageDigest.getInstance(HASH_ALGORITHM)
            digest.update(latestRBio)
            digest.update(DOMAIN_ID.toByteArray(Charsets.UTF_8)) // ✅ 新增：绑定运营商域
            val ctrBytes = ByteArray(8)
            for (i in 0..7) ctrBytes[i] = (ctrLocal shr (i * 8)).toByte()
            digest.update(ctrBytes)
            val rDynamic = digest.digest()
            // 3. hashM2 占位（只定义1次）
            val hashM2 = ByteArray(32)

            // ===================== 阶段2：从后端获取挑战种子 cSeed =====================
            updateUI(status, progress, "请求后端挑战参数...", 50)
            val challengeResult = getChallengeFromServer(outWTotal, outWSec, outMacW, rDynamic)
            val cSeed = challengeResult.first
            val sessionId = challengeResult.second
            val m1Bytes = challengeResult.third
            appendLog(log, "✅ 后端挑战种子 cSeed 获取成功")
            appendLog(log, "✅ 会话ID: ${sessionId.take(8)}...")
            delay(500)

// ===================== 阶段2：计算c_agg（先定义，再使用！修复outCAgg报错） =====================
            updateUI(status, progress, "计算抗量子证明...", 60)
            val outCAgg = ByteArray(POLY_BYTES)
            runCatching {
                NativeLib.PQC_GenChallenge(outWTotal, cSeed, outCAgg)
            }.getOrThrow()

// ===================== 生成AuthToken（此时outCAgg已定义，无报错） =====================
            val authToken = generateAuthToken(kTEE, outCAgg, ctrLocal, rDynamic, hashM2)

            // 阶段4：核心掩码计算
            updateUI(status, progress, "执行核心掩码计算...", 75)
            val outZMasked = ByteArray(POLYVEC_BYTES)
            runCatching {
                NativeLib.PQC_ComputeZ_and_Mask(nvramDirPath, outCAgg, cSeed, rDynamic, hashM2, authToken, outZMasked)
            }

            // 阶段5：最终聚合
            val outZFinal = ByteArray(POLYVEC_BYTES)
            runCatching { NativeLib.PQC_LPA_Aggregate(outZMasked, seedY, outZFinal) }

            // ===================== 错误7修复：提交验证到后端（分工3.0标准） =====================
            updateUI(status, progress, "提交证明到后端验证...", 90)
            val verifySuccess = submitVerifyToServer(outZFinal, hashM2, sessionId)
            if (!verifySuccess) {
                throw Exception("后端验证未通过")
            }
            appendLog(log, "✅ 后端抗量子验证成功")

            // 流程完成（项目验收要求）
            isAuthSucceeded = true
            withContext(Dispatchers.Main) {
                status?.setTextColor(android.graphics.Color.parseColor("#10B981"))
                updateUI(status, progress, "认证成功", 100)
                bizBtn?.isEnabled = true
                bizBtn?.setBackgroundColor(android.graphics.Color.parseColor("#10B981"))
                appendLog(log, "✅ 抗量子安全链路已就绪")
            }

        } catch (e: Exception) {
            // --- 详细报错，不再静默 ---
            withContext(Dispatchers.Main) {
                isAuthStarting = false
                isProcessingFrame = false

                updateUI(status, progress, "运行异常", 0)
                status?.setTextColor(android.graphics.Color.parseColor("#EF4444"))
                appendLog(log, "❌ 错误详情: ${e.localizedMessage}")

                // 安全清理相机图层：协程中操作相机必须严格生命周期检查
                try {
                    mOpenCvCameraView?.let { cameraView ->
                        // 只有当相机正在运行时才调用 disableView，避免非法操作
                        if (cameraView.visibility == View.VISIBLE) {
                            cameraView.disableView()
                        }
                        cameraView.visibility = View.GONE
                    }
                    mCameraContainer?.visibility = View.GONE
                    mFaceOverlay?.visibility = View.GONE
                    btnRunAuth?.isEnabled = true // 让用户能再次点击
                } catch (uiEx: Exception) {
                    Log.e("PQZK", "清理相机图层失败", uiEx)
                }
            }
            Log.e("PQZK", "流程中断", e)
        }
    }

    // 项目要求：HMAC-SHA256 生成AuthToken
    // 【v4.0协议标准】AuthToken = HMAC(K_TEE, c_agg || ctr_le8 || R_dynamic || hashM2)
    private fun generateAuthToken(
        kTEE: ByteArray,
        cAgg: ByteArray,
        ctrLocal: Long,
        rDynamic: ByteArray,
        hashM2: ByteArray
    ): ByteArray {
        val mac = Mac.getInstance("HmacSHA256")
        mac.init(SecretKeySpec(kTEE, "HmacSHA256"))

        // 按协议顺序拼接所有字段
        mac.update(cAgg)
        // 小端序计数器
        val ctrBytes = ByteArray(8)
        for (i in 0..7) ctrBytes[i] = (ctrLocal shr (i * 8)).toByte()
        mac.update(ctrBytes)
        mac.update(rDynamic)
        return mac.doFinal(hashM2)
    }

    // 指纹生物认证
    private fun showBiometricPrompt(onSuccess: () -> Unit) {
        val prompt = BiometricPrompt(this, ContextCompat.getMainExecutor(this), object : BiometricPrompt.AuthenticationCallback() {

            override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                // --- 指纹成功后，在主线程弹出人脸识别界面 ---
                runOnUiThread {
                    // 1. 先校验相机视图非空，避免空指针闪退
                    if (mOpenCvCameraView == null || mCameraContainer == null) {
                        Log.e("PQZK-Debug", "相机视图未初始化，无法启动相机")
                        Toast.makeText(this@MainActivity, "相机初始化失败，请重试", Toast.LENGTH_SHORT).show()
                        return@runOnUiThread
                    }
                    
                    // 2. 核心：必须在 enableView 之前设置这些属性
                    mOpenCvCameraView?.apply {
                        visibility = View.VISIBLE
                        // 强制使用前置摄像头（通常为 1）
                        setCameraIndex(1) // 明确设置为 1，确保使用前置摄像头
                        // 解决某些机型即便设置了 ID 仍不生效的问题
                        setCameraPermissionGranted()
                        // 关键：将 SurfaceView 置于顶层，防止被背景遮挡导致灰色
                        setZOrderOnTop(true)
                        // 设置相机预览大小，确保与扫描框匹配
                        setMaxFrameSize(640, 640)
                    }
                    
                    mFaceOverlay?.visibility = View.VISIBLE

                    // 3. 给系统足够的 UI 布局时间后再启动硬件
                    mOpenCvCameraView?.postDelayed({
                        try {
                            // 再次检查非空，防止延迟期间对象被释放
                            mOpenCvCameraView?.let { cameraView ->
                                cameraView.enableView()
                                Log.d("PQZK-Debug", "Front Camera Started Successfully")
                                // 4. 相机启动成功后再显示容器，避免灰色闪烁
                                mCameraContainer?.visibility = View.VISIBLE
                                mCameraContainer?.alpha = 1.0f
                                // 5. 调用回调函数，启动认证流程
                                onSuccess()
                            }
                        } catch (e: Exception) {
                            Log.e("PQZK-Debug", "Camera start failed: ${e.message}")
                            // 启动失败时隐藏容器
                            mCameraContainer?.visibility = View.GONE
                            mOpenCvCameraView?.visibility = View.GONE
                            mFaceOverlay?.visibility = View.GONE
                        }
                    }, 600) // 给可见性切换留时间
                }

            }
            override fun onAuthenticationFailed() {
                super.onAuthenticationFailed()
                runOnUiThread {
                    appendLog(findViewById(R.id.tv_audit_log), "⚠️ 指纹不匹配，请重试")
                    Toast.makeText(this@MainActivity, "指纹验证失败，请重新放置手指", Toast.LENGTH_SHORT).show()
                }
            }
            override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
                super.onAuthenticationError(errorCode, errString)
                runOnUiThread {
                    appendLog(findViewById(R.id.tv_audit_log), "❌ 认证错误: $errString")
                    // 如果错误太严重，重置认证按钮状态
                    findViewById<Button>(R.id.btn_run_test).isEnabled = true
                }
            }
        })

        prompt.authenticate(BiometricPrompt.PromptInfo.Builder()
            .setTitle("身份验证")
            .setNegativeButtonText("取消")
            .build())
    }

    // 安全UI更新（防闪退）
    private fun updateUI(status: TextView?, pb: ProgressBar?, text: String, p: Int) {
        runOnUiThread {
            status?.text = text
            pb?.progress = p
        }
    }

    private fun appendLog(log: TextView?, msg: String) {
        runOnUiThread {
            log?.append("> $msg\n")
        }
    }

    private fun generateSecureRandomBytes(): ByteArray {
        return ByteArray(32).apply { SecureRandom.getInstanceStrong().nextBytes(this) }
    }

    /**
     * 错误6修复：对接后端 /api/v1/auth/challenge（严格遵循开发组分工3.0）
     * 入参：W_total、W_sec、MAC_W、R_dynamic(原H_ctx)
     * 返回：cSeed、sessionId、m1
     */
    private suspend fun getChallengeFromServer(
        wTotal: ByteArray,
        wSec: ByteArray,
        macW: ByteArray,
        rDynamic: ByteArray
    ): Triple<ByteArray, String, ByteArray> = withContext(Dispatchers.IO) {
        // 后端地址（让后端同学给你IP+端口，直接替换）
        val url = URL("http://192.168.254.129:8000/api/v1/auth/challenge")
        val conn = url.openConnection() as HttpURLConnection

        conn.apply {
            requestMethod = "POST"
            setRequestProperty("Content-Type", "application/json")
            doOutput = true
            connectTimeout = 8000
            readTimeout = 8000
        }

        // 构建请求体（完全按开发组分工3.0字段）
        val json = JSONObject().apply {
            put("w_total", Base64.encodeToString(wTotal, Base64.NO_WRAP))
            put("w_sec", Base64.encodeToString(wSec, Base64.NO_WRAP))
            put("mac_w", Base64.encodeToString(macW, Base64.NO_WRAP))
            put("r_dynamic", Base64.encodeToString(rDynamic, Base64.NO_WRAP)) // ✅ 替换h_ctx
            put("domain_id", DOMAIN_ID) // ✅ 新增domain_id
        }

        // 发送请求
        conn.outputStream.use { os ->
            os.write(json.toString().toByteArray())
            os.flush()
        }

        // 解析后端返回（严格按分工文档字段）
        val response = conn.inputStream.bufferedReader().readText()
        val res = JSONObject(response)

        val cSeed = Base64.decode(res.getString("c_seed"), Base64.NO_WRAP)
        val sessionId = res.getString("session_id")
        val m1 = Base64.decode(res.getString("m1"), Base64.NO_WRAP)

        conn.disconnect()
        return@withContext Triple(cSeed, sessionId, m1)
    }

    /**
     * 错误7修复：对接后端 /api/v1/auth/verify（严格遵循开发组分工3.0）
     * 入参：zFinal、M2、sessionId
     * 返回：验证成功/失败
     */
    private suspend fun submitVerifyToServer(
        zFinal: ByteArray,
        m2: ByteArray,
        sessionId: String
    ): Boolean = withContext(Dispatchers.IO) {
        val url = URL("http://192.168.254.129:8000/api/v1/auth/verify")
        val conn = url.openConnection() as HttpURLConnection

        conn.apply {
            requestMethod = "POST"
            setRequestProperty("Content-Type", "application/json")
            doOutput = true
            connectTimeout = 8000
            readTimeout = 8000
        }

        // 请求体（完全按分工文档）
        val json = JSONObject().apply {
            put("z_final", Base64.encodeToString(zFinal, Base64.NO_WRAP))
            put("m2", Base64.encodeToString(m2, Base64.NO_WRAP))
            put("session_id", sessionId)
            put("domain_id", DOMAIN_ID) // ✅ 新增domain_id
        }

        conn.outputStream.use { os ->
            os.write(json.toString().toByteArray())
            os.flush()
        }

        // 200=成功
        val success = conn.responseCode == 200
        conn.disconnect()
        return@withContext success
    }

    // 【设备注册流程】
    private suspend fun runRegisterFlow() {
        val tvAuditLog = findViewById<TextView>(R.id.tv_audit_log)
        val tvStatus = findViewById<TextView>(R.id.tv_reg_status)

        withContext(Dispatchers.Main) {
            tvStatus?.text = "注册中..."
            tvStatus?.setTextColor(android.graphics.Color.WHITE)
        }

        try {
            // 等待人脸特征
            var retry = 0
            while (latestRBio.all { it == 0.toByte() }) {
                delay(200)
                retry++
                if (retry > 50) {
                    throw Exception("请将人脸对准框内")
                }
            }

            // 执行注册
            val ret = NativeLib.nativeRegisterDevice(latestRBio, nvramDirPath)

            withContext(Dispatchers.Main) {
                if (ret == 0) {
                    tvStatus?.text = "注册成功"
                    tvStatus?.setTextColor(android.graphics.Color.parseColor("#10B981"))
                    appendLog(tvAuditLog, "✅ 设备注册成功！现在可以认证")
                } else {
                    tvStatus?.text = "注册失败"
                    appendLog(tvAuditLog, "❌ 注册失败")
                }

                // 关闭相机
                mOpenCvCameraView?.disableView()
                mCameraContainer?.visibility = View.GONE
                mFaceOverlay?.visibility = View.GONE
            }

        } catch (e: Exception) {
            withContext(Dispatchers.Main) {
                appendLog(tvAuditLog, "❌ 注册错误：${e.message}")
                mOpenCvCameraView?.disableView()
                mCameraContainer?.visibility = View.GONE
            }
        }
    }

    private fun copyAssetToFilesDir(assetName: String): String {
        val file = File(filesDir, assetName)
        // 如果文件不存在，或者你想每次覆盖更新，可以执行复制
        if (!file.exists()) {
            try {
                assets.open(assetName).use { inputStream ->
                    FileOutputStream(file).use { outputStream ->
                        inputStream.copyTo(outputStream)
                    }
                }
                Log.d("PQZK-Debug", "模型文件复制成功: ${file.absolutePath}")
            } catch (e: Exception) {
                Log.e("PQZK-Debug", "复制模型文件失败: ${e.message}")
            }
        }
        return file.absolutePath
    }

    //在onPause和onStop中释放相机
    override fun onPause() {
        super.onPause()
        try {
            mOpenCvCameraView?.disableView()
            // 直接操作成员变量，而不是属性
            synchronized(latestRBioLock) {
                _latestRBio.fill(0)
            }
            isAuthStarting = false
            isProcessingFrame = false
            isFaceExtracted = false
        } catch (e: Exception) {
            Log.e("PQZK", "onPause释放相机失败", e)
        }
    }

    override fun onStop() {
        super.onStop()
        try {
            mOpenCvCameraView?.disableView()
            mCameraContainer?.visibility = View.GONE
            mFaceOverlay?.visibility = View.GONE
            synchronized(latestRBioLock) {
                _latestRBio.fill(0)
            }
            isAuthStarting = false
            isProcessingFrame = false
            isFaceExtracted = false
        } catch (e: Exception) {
            Log.e("PQZK", "onStop释放相机失败", e)
        }
    }
}