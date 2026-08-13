package com.nginxscan.app.ui

import android.content.Context
import android.content.Intent
import android.net.Uri
import androidx.core.content.FileProvider
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.nginxscan.app.data.FofaAsset
import com.nginxscan.app.data.FofaClient
import com.nginxscan.app.data.ScannerEngine
import com.nginxscan.app.data.ScanResult
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.io.File

enum class ScanPhase { IDLE, FETCHING, SCANNING, DONE, ERROR }

data class ScanUiState(
    val apiKey: String = "",
    val query: String = """app="NGINX"""",
    val maxPages: Int = 5,
    val pageSize: Int = 100,
    val concurrency: Int = 20,
    val phase: ScanPhase = ScanPhase.IDLE,
    val fetchedTotal: Int = 0,
    val fetchedCount: Int = 0,
    val scannedTotal: Int = 0,
    val scannedCount: Int = 0,
    val results: List<ScanResult> = emptyList(),
    val error: String? = null,
    val statusMessage: String = "",
)

class MainViewModel : ViewModel() {

    private val _uiState = MutableStateFlow(ScanUiState())
    val uiState: StateFlow<ScanUiState> = _uiState.asStateFlow()

    private var scanJob: Job? = null

    fun setApiKey(v: String) = _uiState.update { it.copy(apiKey = v) }
    fun setQuery(v: String) = _uiState.update { it.copy(query = v) }
    fun setMaxPages(v: Int) = _uiState.update { it.copy(maxPages = v) }
    fun setPageSize(v: Int) = _uiState.update { it.copy(pageSize = v) }
    fun setConcurrency(v: Int) = _uiState.update { it.copy(concurrency = v) }

    fun startScan() {
        val s = _uiState.value
        if (s.apiKey.isBlank()) {
            _uiState.update { it.copy(error = "请先填写 FoFa API Key（FOFACLI_FOFA_KEY）") }
            return
        }
        if (s.phase == ScanPhase.SCANNING || s.phase == ScanPhase.FETCHING) return

        scanJob?.cancel()
        _uiState.update {
            it.copy(
                phase = ScanPhase.FETCHING,
                error = null,
                results = emptyList(),
                fetchedCount = 0,
                fetchedTotal = 0,
                scannedCount = 0,
                scannedTotal = 0,
                statusMessage = "正在从 FoFa 拉取资产..."
            )
        }

        scanJob = viewModelScope.launch {
            try {
                val fofa = FofaClient(s.apiKey)
                val assets = fofa.searchAll(
                    query = s.query,
                    pageSize = s.pageSize,
                    maxPages = s.maxPages,
                    onProgress = { fetched, total ->
                        _uiState.update {
                            it.copy(fetchedCount = fetched, fetchedTotal = total)
                        }
                    },
                )

                if (assets.isEmpty()) {
                    _uiState.update {
                        it.copy(phase = ScanPhase.DONE, statusMessage = "FoFa 未返回任何资产")
                    }
                    return@launch
                }

                _uiState.update {
                    it.copy(
                        phase = ScanPhase.SCANNING,
                        scannedTotal = assets.size,
                        statusMessage = "已获取 ${assets.size} 个资产，开始并发探测..."
                    )
                }

                val engine = ScannerEngine(concurrency = s.concurrency)
                val results = engine.scan(assets) { done, total, _ ->
                    _uiState.update {
                        it.copy(scannedCount = done, scannedTotal = total)
                    }
                }

                _uiState.update {
                    it.copy(
                        phase = ScanPhase.DONE,
                        results = results,
                        statusMessage = "扫描完成，共探测 ${results.size} 个目标",
                    )
                }
            } catch (e: Exception) {
                _uiState.update {
                    it.copy(
                        phase = ScanPhase.ERROR,
                        error = e.message ?: "未知错误",
                        statusMessage = "扫描失败: ${e.message?.take(100)}",
                    )
                }
            }
        }
    }

    fun stopScan() {
        scanJob?.cancel()
        _uiState.update { it.copy(phase = ScanPhase.DONE, statusMessage = "已手动停止") }
    }

    /**
     * 导出结果为 CSV 并通过分享发送
     */
    fun exportCsv(context: Context) {
        val s = _uiState.value
        if (s.results.isEmpty()) return

        val sb = StringBuilder()
        sb.append("host,ip,port,protocol,title,nginx,version,status,cve_ids,note\n")
        for (r in s.results) {
            val a = r.asset
            val cves = r.matchedCves.joinToString("|") { it.cveId }
            val line = listOf(
                a.host, a.ip, a.port, a.protocol,
                a.title.replace(",", " "),
                if (r.isNginx) "yes" else "no",
                r.nginxVersion ?: "",
                r.statusCode.toString(),
                cves,
                r.note.replace(",", " "),
            ).joinToString(",")
            sb.append(line).append("\n")
        }

        val file = File(context.cacheDir, "nginx_scan_result.csv")
        file.writeText(sb.toString())

        val uri: Uri = FileProvider.getUriForFile(
            context,
            "${context.packageName}.fileprovider",
            file,
        )
        val share = Intent(Intent.ACTION_SEND).apply {
            type = "text/csv"
            putExtra(Intent.EXTRA_STREAM, uri)
            addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
        }
        context.startActivity(Intent.createChooser(share, "导出扫描结果"))
    }

    override fun onCleared() {
        super.onCleared()
        scanJob?.cancel()
    }
}
