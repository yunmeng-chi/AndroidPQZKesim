package com.yourcompany.pqzkesim // 确保包名与项目一致

import android.content.Intent
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.util.Log
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity
import java.io.File
import android.widget.Toast
import com.yourcompany.pqzkesim.NativeLib.isRegistered

class SplashActivity : AppCompatActivity() {
    private var clickCount = 0 // 新增：点击计数器
    private val DEVELOPER_CLICK_THRESHOLD = 5 // 新增：触发阈值

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_splash)

        // 🟢 新增：获取 Logo 控件并设置监听
        val ivLogo = findViewById<android.widget.ImageView>(R.id.iv_logo)
        val tvStatus = findViewById<TextView>(R.id.tv_init_status)

        ivLogo.setOnClickListener {
            clickCount++
            if (clickCount >= DEVELOPER_CLICK_THRESHOLD) {
                // 触发开发者逻辑
                enterDeveloperMode()
                clickCount = 0 // 重置
            } else if (clickCount > 2) {
                // 提示用户还差几次
                Toast.makeText(this, "再点击 ${DEVELOPER_CLICK_THRESHOLD - clickCount} 次进入开发者模式", Toast.LENGTH_SHORT).show()
            }
        }

        // 模拟初始化流程
        Handler(Looper.getMainLooper()).postDelayed({
            tvStatus.text = "正在加载抗量子安全库..."

            // 1. 安全创建NVRAM目录（Java层做，更安全）
            val nvram = File(filesDir, "euicc_nvram")
            if (!nvram.exists()) {
                val created = nvram.mkdirs()
                Log.d("PQZK", "NVRAM目录创建: $created")
            }

            tvStatus.text = "安全环境就绪"

            // 3. 延迟一秒后跳转到主页
            // 延迟1秒后跳转
            Handler(Looper.getMainLooper()).postDelayed({
                try {
                    // ✅ 修复：构建路径并传入，只调用一次
                    val nvramPath = filesDir.absolutePath + "/euicc_nvram"
                    val isRegistered = NativeLib.isRegistered(nvramPath)

                    val target = if (isRegistered == 1) {
                        MainActivity::class.java
                    } else {
                        RegisterActivity::class.java
                    }

                    startActivity(Intent(this, target))
                    finish()
                } catch (e: Exception) {
                    // 🔥 修复：Native崩溃时，强制跳注册页，保证APP不闪退
                    Log.e("PQZK", "Native判断注册状态失败，强制跳注册页", e)
                    startActivity(Intent(this, RegisterActivity::class.java))
                    finish()
                }
            }, 1000)

        }, 1500)
    }

    private fun navigateToNextScreen() {
        try {
            // 调用原生接口检查注册状态
            // 注意：isRegistered 内部会检查 pqzk_state.bin 是否存在
            val nvramPath = filesDir.absolutePath + "/euicc_nvram"
            val isRegistered = NativeLib.isRegistered(nvramPath)

            Log.d("PQZK", "设备注册状态检查: $isRegistered")

            val target = if (isRegistered == 1) {
                MainActivity::class.java
            } else {
                // 如果未注册，跳转到注册页进行人脸录入
                RegisterActivity::class.java
            }

            startActivity(Intent(this, target))
            finish() // 销毁启动页
        } catch (e: Exception) {
            Log.e("PQZK", "跳转逻辑异常: ${e.message}")
            // 万一崩溃，默认去注册页是更安全的策略
            startActivity(Intent(this, RegisterActivity::class.java))
            finish()
        }
    }

    private fun enterDeveloperMode() {
        // 1. 弹出提示
        Toast.makeText(this, "🔧 开发者调试模式已激活", Toast.LENGTH_SHORT).show()

        // 2. 修改跳转目标为 DevTestActivity
        val intent = Intent(this, DevTestActivity::class.java)

        // 3. 执行跳转
        startActivity(intent)

        // 4. 注意：通常调试模式建议保留 Splash 在后台，或者 finish 掉取决于你的习惯
        // 如果希望按返回键能回到正常流程，可以不写 finish()
        finish()
    }
}