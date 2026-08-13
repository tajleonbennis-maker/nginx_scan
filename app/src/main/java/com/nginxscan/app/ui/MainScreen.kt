package com.nginxscan.app.ui

import androidx.compose.ui.platform.LocalContext
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.lifecycle.viewmodel.compose.viewModel
import com.nginxscan.app.data.ScanResult

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun MainScreen(vm: MainViewModel = viewModel()) {
    val state by vm.uiState.collectAsStateWithLifecycle()
    val context = LocalContext.current

    Scaffold(
        topBar = { TopAppBar(title = { Text("Nginx 资产扫描") }) },
    ) { padding ->
        Column(
            modifier = Modifier
                .padding(padding)
                .fillMaxSize()
                .verticalScroll(rememberScrollState())
                .padding(16.dp)
        ) {
            // ---- 配置区 ----
            OutlinedTextField(
                value = state.apiKey,
                onValueChange = vm::setApiKey,
                label = { Text("FoFa API Key (FOFACLI_FOFA_KEY)") },
                modifier = Modifier.fillMaxWidth(),
                singleLine = true,
            )
            Spacer(Modifier.height(8.dp))
            OutlinedTextField(
                value = state.query,
                onValueChange = vm::setQuery,
                label = { Text("FoFa 查询语句") },
                modifier = Modifier.fillMaxWidth(),
                singleLine = true,
            )
            Spacer(Modifier.height(8.dp))
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                OutlinedTextField(
                    value = state.maxPages.toString(),
                    onValueChange = { it.toIntOrNull()?.let(vm::setMaxPages) },
                    label = { Text("页数") },
                    modifier = Modifier.weight(1f),
                    singleLine = true,
                )
                OutlinedTextField(
                    value = state.pageSize.toString(),
                    onValueChange = { it.toIntOrNull()?.let(vm::setPageSize) },
                    label = { Text("每页") },
                    modifier = Modifier.weight(1f),
                    singleLine = true,
                )
                OutlinedTextField(
                    value = state.concurrency.toString(),
                    onValueChange = { it.toIntOrNull()?.let(vm::setConcurrency) },
                    label = { Text("并发") },
                    modifier = Modifier.weight(1f),
                    singleLine = true,
                )
            }

            state.error?.let { err ->
                Spacer(Modifier.height(8.dp))
                Text(
                    text = err,
                    color = MaterialTheme.colorScheme.error,
                    fontSize = 13.sp,
                )
            }

            Spacer(Modifier.height(12.dp))
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                Button(
                    onClick = vm::startScan,
                    enabled = state.phase != ScanPhase.FETCHING &&
                        state.phase != ScanPhase.SCANNING,
                    modifier = Modifier.weight(1f),
                ) {
                    Text("开始扫描")
                }
                OutlinedButton(
                    onClick = vm::stopScan,
                    enabled = state.phase == ScanPhase.FETCHING ||
                        state.phase == ScanPhase.SCANNING,
                    modifier = Modifier.weight(1f),
                ) {
                    Text("停止")
                }
                if (state.results.isNotEmpty()) {
                    OutlinedButton(onClick = { vm.exportCsv(context = context) }) {
                        Text("导出")
                    }
                }
            }

            Spacer(Modifier.height(12.dp))

            // ---- 进度区 ----
            when (state.phase) {
                ScanPhase.FETCHING -> {
                    Text("正在从 FoFa 拉取资产：${state.fetchedCount}/${state.fetchedTotal}")
                    Spacer(Modifier.height(6.dp))
                    LinearProgressIndicator(
                        progress = {
                            if (state.fetchedTotal > 0) state.fetchedCount.toFloat() / state.fetchedTotal
                            else 0f
                        },
                        modifier = Modifier.fillMaxWidth(),
                    )
                }
                ScanPhase.SCANNING -> {
                    Text("正在探测：${state.scannedCount}/${state.scannedTotal}")
                    Spacer(Modifier.height(6.dp))
                    LinearProgressIndicator(
                        progress = {
                            if (state.scannedTotal > 0) state.scannedCount.toFloat() / state.scannedTotal
                            else 0f
                        },
                        modifier = Modifier.fillMaxWidth(),
                    )
                }
                else -> {}
            }
            state.statusMessage.takeIf { it.isNotEmpty() }?.let {
                Spacer(Modifier.height(8.dp))
                Text(it, fontSize = 13.sp, color = MaterialTheme.colorScheme.primary)
            }

            Spacer(Modifier.height(12.dp))
            HorizontalDivider()

            // ---- 结果统计 ----
            if (state.results.isNotEmpty()) {
                val nginxCount = state.results.count { it.isNginx }
                val vulnCount = state.results.count { it.matchedCves.isNotEmpty() }
                Spacer(Modifier.height(8.dp))
                Text(
                    text = "共 ${state.results.size} 个目标 · Nginx ${nginxCount} · 命中漏洞 ${vulnCount}",
                    fontWeight = FontWeight.Bold,
                )
                Spacer(Modifier.height(8.dp))
            }

            // ---- 结果列表 ----
            state.results.forEach { r ->
                ResultCard(r)
                Spacer(Modifier.height(8.dp))
            }
            Spacer(Modifier.height(24.dp))
        }
    }
}

@Composable
private fun ResultCard(r: ScanResult) {
    val cardColor = when {
        r.matchedCves.isNotEmpty() -> MaterialTheme.colorScheme.errorContainer
        r.isNginx -> MaterialTheme.colorScheme.primaryContainer
        else -> MaterialTheme.colorScheme.surfaceVariant
    }
    Card(
        colors = CardDefaults.cardColors(containerColor = cardColor),
        modifier = Modifier.fillMaxWidth(),
    ) {
        Column(modifier = Modifier.padding(12.dp)) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Text(
                    text = "${r.asset.host}",
                    fontWeight = FontWeight.Bold,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis,
                    modifier = Modifier.weight(1f),
                )
                Text(
                    text = r.statusCode.toString(),
                    fontSize = 12.sp,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
            Text(
                text = "协议: ${r.asset.protocol} | 端口: ${r.asset.port}",
                fontSize = 12.sp,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            if (r.asset.title.isNotBlank()) {
                Text(
                    text = "标题: ${r.asset.title.take(80)}",
                    fontSize = 12.sp,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis,
                )
            }
            Spacer(Modifier.height(4.dp))
            HorizontalDivider()
            Spacer(Modifier.height(4.dp))

            if (r.isNginx) {
                val version = r.nginxVersion ?: "版本隐藏"
                Text(
                    text = "Nginx 版本: $version",
                    fontWeight = FontWeight.SemiBold,
                    fontFamily = FontFamily.Monospace,
                )
                if (r.serverHeader.isNotBlank()) {
                    Text(
                        text = "Server 头: ${r.serverHeader.take(60)}",
                        fontSize = 11.sp,
                        maxLines = 1,
                        overflow = TextOverflow.Ellipsis,
                        fontFamily = FontFamily.Monospace,
                    )
                }
                if (r.matchedCves.isNotEmpty()) {
                    Spacer(Modifier.height(6.dp))
                    Text("命中漏洞:", fontWeight = FontWeight.Bold, color = MaterialTheme.colorScheme.error, fontSize = 13.sp)
                    r.matchedCves.forEach { cve ->
                        Text(
                            text = "• ${cve.cveId} [${cve.severity}] ${cve.name}",
                            fontSize = 12.sp,
                            color = MaterialTheme.colorScheme.error,
                        )
                    }
                }
            } else {
                Text(
                    text = if (r.reachable) "非 Nginx 或未识别" else "不可达",
                    fontSize = 12.sp,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
            r.note.takeIf { it.isNotBlank() }?.let {
                Text(
                    text = "备注: $it",
                    fontSize = 11.sp,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    maxLines = 2,
                    overflow = TextOverflow.Ellipsis,
                )
            }
        }
    }
}
