package com.yourcompany.pqzkesim

import android.content.Intent
import android.content.pm.PackageManager
import android.graphics.Bitmap
import android.os.Bundle
import android.util.Log
import android.view.View
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity
import androidx.lifecycle.lifecycleScope
import com.yourcompany.pqzkesim.databinding.ActivityRegisterBinding
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import org.opencv.android.CameraBridgeViewBase
import org.opencv.android.OpenCVLoader
import org.opencv.core.Mat
import java.io.File

class RegisterActivity : AppCompatActivity(), CameraBridgeViewBase.CvCameraViewListener2 {

    private lateinit var binding: ActivityRegisterBinding
    private var isProcessing = false
    private var captureRequest = false

    private var hasScheduledCapture = false
    // 🟢 新增：定义 NVRAM 存储路径
    private val nvramDirPath by lazy { filesDir.absolutePath + "/euicc_nvram" }

    // 🟢 注册流程状态机
    private enum class RegisterStep {
        FACE,
        FINGERPRINT,
        DONE
    }

    private var currentStep = RegisterStep.FINGERPRINT

    // 🟢 存储人脸结果
    private lateinit var faceFeature: ByteArray
    private lateinit var fingerprintFeature: ByteArray

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        try {
            // 1. 初始化 ViewBinding
            binding = ActivityRegisterBinding.inflate(layoutInflater)
            setContentView(binding.root)

            // 2. 初始状态设置 (防止 ID 引用错误导致闪退)
            binding.btnNextStep.isEnabled = false
            binding.btnNextStep.text = "载入算法中..."
            binding.registerCameraView.visibility = View.GONE

            // 3. 初始化 OpenCV 核心
            if (!OpenCVLoader.initLocal()) {
                Log.e("PQZK", "OpenCV 初始化失败")
            }
            binding.registerCameraView.setCvCameraViewListener(this)

            // 4. 🔴 严谨的模型加载（闪退高发区）
            lifecycleScope.launch(Dispatchers.IO) {
                try {
                    val modelFile = File(filesDir, "haarcascade_frontalface_alt.xml")

                    // 检查 Assets 拷贝
                    if (!modelFile.exists()) {
                        // 🔴 注意：请确认你 assets 文件夹下文件名叫这个，一个字母都不能错！
                        assets.open("haarcascade_frontalface_alt.xml").use { input ->
                            modelFile.outputStream().use { output -> input.copyTo(output) }
                        }
                    }

                    // 调用 JNI（如果 NativeLib 里没载入 .so 也会闪退）
                    val isInit = NativeLib.initDetector(modelFile.absolutePath)

                    withContext(Dispatchers.Main) {
                        if (isInit) {
                            binding.btnNextStep.isEnabled = true
                            binding.btnNextStep.text = "开始采集指纹" // ✅ 与初始步骤FINGERPRINT匹配
                        } else {
                            binding.btnNextStep.text = "插件初始化失败"
                        }
                    }
                } catch (e: Exception) {
                    Log.e("PQZK", "模型拷贝或初始化崩溃: ${e.message}")
                    // 如果文件找不到会进这里
                }
            }

            binding.btnNextStep.setOnClickListener {

                when (currentStep) {

                    RegisterStep.FINGERPRINT -> {
                        // 👉 防止重复点击
                        binding.btnNextStep.isEnabled = false
                        binding.btnNextStep.text = "正在采集指纹..."
                        startFingerprintProcess()
                    }

                    RegisterStep.FACE -> {
                        if (checkCameraPermission()) {
                            binding.btnNextStep.text = "正在启动摄像头..."
                            startCaptureProcess()
                        } else {
                            requestCameraPermission()
                        }
                    }

                    RegisterStep.DONE -> {
                        Toast.makeText(this, "已完成注册", Toast.LENGTH_SHORT).show()
                    }
                }
            }

        } catch (e: Exception) {
            Log.e("PQZK", "onCreate 布局初始化失败: ${e.message}")
        }
    }

    private fun startFingerprintProcess() {

        binding.btnNextStep.isEnabled = false
        binding.btnNextStep.text = "正在采集指纹..."

        lifecycleScope.launch(Dispatchers.Default) {
            try {

                Log.d("FACE_FLOW", "👉 开始采集指纹")

                // ✅ 1. 获取指纹特征（JNI）
                fingerprintFeature = NativeLib.extractFingerprintFeature()

                Log.d("FACE_FLOW", "✅ 指纹特征获取完成")

                withContext(Dispatchers.Main) {
                    // 👉 切换到人脸步骤
                    currentStep = RegisterStep.FACE

                    binding.btnNextStep.text = "开始采集人脸"
                    binding.btnNextStep.isEnabled = true
                }

            } catch (e: Exception) {
                withContext(Dispatchers.Main) {
                    handleError("指纹采集失败")
                }
            }
        }
    }

    /**
     * 核心逻辑：处理人脸特征并调用 JNI 注册 [cite: 51, 53]
     */
    private fun handleFaceCaptured(faceBitmap: Bitmap) {
        isProcessing = false
        binding.registerCameraView.disableView()

        lifecycleScope.launch(Dispatchers.Default) {
            try {
                // 👉 1. 提取人脸特征
                faceFeature = NativeLib.extractFaceFeature(faceBitmap)

                // 👉 2. 获取 salt
                val salt = NativeLib.getDeviceStaticSalt()

                // 👉 3. 构建 Merkle Tree（关键！）
                val features = arrayOf(
                    fingerprintFeature,
                    faceFeature
                )

                val rBio = NativeLib.buildMerkleRoot(features, salt)

                // 👉 4. 注册
                val result = NativeLib.nativeRegisterDevice(rBio, nvramDirPath)

                withContext(Dispatchers.Main) {
                    if (result == 0) {
                        currentStep = RegisterStep.DONE
                        startActivity(Intent(this@RegisterActivity, MainActivity::class.java))
                        finish()
                    } else {
                        handleError("注册失败: $result")
                    }
                }

            } catch (e: Exception) {
                withContext(Dispatchers.Main) {
                    handleError("人脸处理失败")
                }
            }
        }
    }

    private fun handleError(msg: String) {
        isProcessing = false
        binding.btnNextStep.isEnabled = true
        binding.btnNextStep.text = "重新采集"
        Toast.makeText(this, "❌ $msg", Toast.LENGTH_LONG).show()
    }

    // --- OpenCV 回调接口 ---
    override fun onCameraViewStarted(width: Int, height: Int) {}
    override fun onCameraViewStopped() {}
    override fun onCameraFrame(inputFrame: CameraBridgeViewBase.CvCameraViewFrame): Mat {
        val rgba = inputFrame.rgba()
        // 此处简化处理：只要画面不为空就提示可采集

        // ✅ 第一层保险：不在采集中直接返回
        if (!isProcessing || currentStep != RegisterStep.FACE) {
            return rgba
        }

        // ✅ 第二层：只处理有效帧
        if (rgba.empty()) return rgba

        if (captureRequest) {

            Log.d("FACE_FLOW", "📸 捕获帧")

            captureRequest = false
            hasScheduledCapture = false   // ✅ 重置调度标志

            val frameMat = rgba.clone()

            lifecycleScope.launch(Dispatchers.Default) {

                val bmp = Bitmap.createBitmap(
                    frameMat.cols(),
                    frameMat.rows(),
                    Bitmap.Config.ARGB_8888
                )

                org.opencv.android.Utils.matToBitmap(frameMat, bmp)
                frameMat.release()

                withContext(Dispatchers.Main) {
                    handleFaceCaptured(bmp)
                }
            }

        } else if (!hasScheduledCapture) {

            // ✅ 关键修复：只允许调度一次
            hasScheduledCapture = true

            Log.d("FACE_FLOW", "⏳ 安排1秒后采集")

            binding.root.postDelayed({
                captureRequest = true
            }, 1000)
        }

        return rgba
    }

    override fun onResume() {
        super.onResume()
        // 只有在 OpenCV 初始化成功后，且已经点击过开始采集（isProcessing）时，才尝试使能相机
        if (OpenCVLoader.initLocal()) {
            if (isProcessing) {
                binding.registerCameraView.enableView()
            }
        }
    }

    override fun onPause() {
        super.onPause()
        binding.registerCameraView.disableView()
    }

    private fun checkCameraPermission(): Boolean {
        return androidx.core.content.ContextCompat.checkSelfPermission(
            this, android.Manifest.permission.CAMERA
        ) == android.content.pm.PackageManager.PERMISSION_GRANTED
    }

    private fun requestCameraPermission() {
        androidx.core.app.ActivityCompat.requestPermissions(
            this, arrayOf(android.Manifest.permission.CAMERA), 101
        )
    }

    private fun startCaptureProcess() {
        isProcessing = true
        captureRequest = false
        hasScheduledCapture = false

        binding.btnNextStep.isEnabled = false
        binding.btnNextStep.text = "正在激活相机..."

        // 🔴 关键：先让控件可见，再开启硬件
        binding.registerCameraView.visibility = View.VISIBLE

        binding.registerCameraView.setCameraPermissionGranted()

        // 给 UI 线程一点点渲染时间
        binding.root.postDelayed({
            binding.registerCameraView.enableView()
            // 不要在这里设置 captureRequest = true，移到回调中判断
            binding.btnNextStep.text = "请正对摄像头..."
        }, 200)
    }

    override fun onRequestPermissionsResult(requestCode: Int, permissions: Array<out String>, grantResults: IntArray) {
        super.onRequestPermissionsResult(requestCode, permissions, grantResults)
        if (requestCode == 101) {
            if (grantResults.isNotEmpty() && grantResults[0] == PackageManager.PERMISSION_GRANTED) {
                startCaptureProcess()
            } else {
                Toast.makeText(this, "需要相机权限才能进行人脸采集", Toast.LENGTH_LONG).show()
                binding.btnNextStep.isEnabled = true
                binding.btnNextStep.text = "重新采集人脸"
            }
        }
    }
}