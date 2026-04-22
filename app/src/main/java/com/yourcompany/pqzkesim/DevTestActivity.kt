package com.yourcompany.pqzkesim

import android.os.Bundle
import android.widget.*
import androidx.appcompat.app.AppCompatActivity
import kotlin.system.measureTimeMillis

class DevTestActivity : AppCompatActivity() {

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_dev_test)

        val spinner = findViewById<Spinner>(R.id.spinner_jni_methods)
        val input = findViewById<EditText>(R.id.et_jni_input)
        val btnCall = findViewById<Button>(R.id.btn_call_jni)
        val resultView = findViewById<TextView>(R.id.tv_jni_result)
        val timeView = findViewById<TextView>(R.id.tv_jni_time)

        // 配置下拉框选项 (对应协议阶段)
        val methods = arrayOf("PQC_Reg", "PQC_eUICC_Commit", "PQC_PreCompute", "PQC_GenChallenge")
        spinner.adapter = ArrayAdapter(this, android.R.layout.simple_spinner_dropdown_item, methods)

        btnCall.setOnClickListener {
            val selectedMethod = spinner.selectedItem.toString()
            val inputHex = input.text.toString()

            // 模拟 JNI 调用并统计耗时
            var resultStr = ""
            val time = measureTimeMillis {
                resultStr = try {
                    executeJniManual(selectedMethod, inputHex)
                } catch (e: Exception) {
                    "Error: ${e.message}"
                }
            }

            resultView.text = resultStr
            timeView.text = "耗时: $time ms"
        }
    }

    // 辅助方法：将 Hex 字符串转为 JNI 调用的结果
    private fun executeJniManual(method: String, hex: String): String {
        // 这里需要调用你在 MainActivity 中定义的那些 external 方法
        // 示例逻辑：
        return when(method) {
            "PQC_Reg" -> "> 执行注册...\n> 返回码: 0\n> 输出 T: ${hex.take(16)}..."
            else -> "> 接口 [$method] 调用成功\n> 响应数据已保存至 NVRAM"
        }
    }
}