package com.nginxscan.app.data

import com.nginxscan.app.vuln.CveDatabase
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.withContext
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.Response
import java.security.SecureRandom
import java.security.cert.X509Certificate
import java.util.concurrent.TimeUnit
import javax.net.ssl.SSLContext
import javax.net.ssl.X509TrustManager

/**
 * Nginx 版本识别扫描引擎
 */
class ScannerEngine(
    private val concurrency: Int = 20,
    private val timeoutSeconds: Long = 8,
) {
    private val client: OkHttpClient by lazy { buildClient() }

    /**
     * 并发扫描一批资产（信号量限流）
     */
    suspend fun scan(targets: List<FofaAsset>, onProgress: (done: Int, total: Int, current: ScanResult) -> Unit): List<ScanResult> =
        withContext(Dispatchers.IO) {
            val semaphore = java.util.concurrent.Semaphore(concurrency)
            val total = targets.size
            val done = java.util.concurrent.atomic.AtomicInteger(0)
            coroutineScope {
                targets.map { asset ->
                    async {
                        semaphore.acquire()
                        try {
                            val r = probe(asset)
                            val d = done.incrementAndGet()
                            onProgress(d, total, r)
                            r
                        } finally {
                            semaphore.release()
                        }
                    }
                }.awaitAll()
            }
        }

    /**
     * 探测单个资产：识别是否为 Nginx 并提取版本
     */
    private fun probe(asset: FofaAsset): ScanResult {
        val parsed = parseTarget(asset)
        if (parsed == null) {
            return ScanResult(asset = asset, reachable = false, note = "非法 host/port")
        }
        val (host, port, useHttps) = parsed
        var result = ScanResult(asset = asset)

        try {
            val resp = sendProbeRequest(host, port, useHttps)
            val code = resp.code
            val serverHeader = resp.header("Server") ?: ""
            val bodySnippet = resp.peekBody(4096).string()
            resp.close()

            val version = detectNginxVersion(serverHeader, bodySnippet)
            result = ScanResult(
                asset = asset,
                reachable = true,
                isNginx = version != null || serverHeader.contains("nginx", ignoreCase = true),
                nginxVersion = version,
                serverHeader = serverHeader,
                statusCode = code,
            )

            // 若 Server 头无版本但确为 nginx，触发默认错误页再试一次
            if (result.isNginx && version == null) {
                val forced = forceErrorPage(host, port)
                if (forced != null) {
                    result = result.copy(nginxVersion = forced, note = "版本来自错误页指纹")
                } else {
                    result = result.copy(note = "版本隐藏/未开启 server_tokens")
                }
            }
        } catch (e: Exception) {
            result = result.copy(note = "连接失败: ${e.message?.take(80)}")
        }

        // 版本命中 CVE 匹配
        val version = result.nginxVersion
        if (result.isNginx && version != null) {
            val hits = CveDatabase.match(version)
            result = result.copy(matchedCves = hits)
        }
        return result
    }

    /**
     * 发送探测请求
     */
    private fun sendProbeRequest(host: String, port: Int, useHttps: Boolean): Response {
        val scheme = if (useHttps) "https" else "http"
        val request = Request.Builder()
            .url("$scheme://$host:$port/")
            .header("User-Agent", "Mozilla/5.0 (Linux; Android 13; SM-S918B) AppleWebKit/537.36 Chrome/120.0 Safari/537.36")
            .get()
            .build()
        return client.newCall(request).execute()
    }

    /**
     * 强制触发默认错误页（畸形请求 -> 400），错误页 footer 常带版本
     */
    private fun forceErrorPage(host: String, port: Int): String? {
        return try {
            val rawSocket = java.net.Socket()
            rawSocket.connect(java.net.InetSocketAddress(host, port), (timeoutSeconds * 1000).toInt())
            rawSocket.soTimeout = (timeoutSeconds * 1000).toInt()
            val out = rawSocket.getOutputStream()
            // 故意只发送一个无效 HTTP 起始行，强制 Nginx 400
            out.write("INVALID-HTTP-METHOD / HTTP/9.9\r\nHost: $host\r\n\r\n".toByteArray())
            out.flush()
            val buf = ByteArray(8192)
            val n = rawSocket.getInputStream().read(buf)
            rawSocket.close()
            if (n <= 0) return null
            detectNginxVersion("", String(buf, 0, n))
        } catch (e: Exception) {
            null
        }
    }

    /**
     * 从 Server 头或响应体提取 nginx 版本号
     */
    private fun detectNginxVersion(serverHeader: String, body: String): String? {
        // Server: nginx/1.18.0
        val reServer = Regex("""nginx/(\d+\.\d+(?:\.\d+)?)""", RegexOption.IGNORE_CASE)
        reServer.find(serverHeader)?.let { return it.groupValues[1] }

        // 错误页中 nginx/x.y.z（新旧 Nginx 错误页格式都覆盖）
        val reBody = Regex("""nginx/(\d+\.\d+(?:\.\d+)?)""", RegexOption.IGNORE_CASE)
        // 排除掉 banner 中干扰前，只在带 angular/square 标签的错误页上下文中提取
        if (body.contains("Bad Request", ignoreCase = true) ||
            body.contains("<title>400", ignoreCase = true) ||
            body.contains("400 Bad", ignoreCase = true) ||
            body.contains("Request Entity Too Large", ignoreCase = true) ||
            body.contains("Not Found", ignoreCase = true) ||
            body.contains("client intended to send too large body", ignoreCase = true)
        ) {
            reBody.find(body)?.let { return it.groupValues[1] }
        }
        return null
    }

    /**
     * 解析目标为 (host, port, useHttps)
     * 处理 FoFa host 字段中可能带的协议前缀
     */
    private fun parseTarget(asset: FofaAsset): Triple<String, Int, Boolean>? {
        // 1. 取 host，去协议头；空则用 ip
        var host = asset.host.ifBlank { asset.ip }
        if (host.isBlank()) return null
        val originalLower = host.lowercase()
        val useHttpsFromProto = when {
            originalLower.startsWith("https://") -> { host = host.removePrefix("https://"); true }
            originalLower.startsWith("http://") -> { host = host.removePrefix("http://"); false }
            else -> asset.protocol.equals("https", ignoreCase = true)
        }

        // 2. 如果 host 自带 :port，剥出 port
        var port = asset.port.ifBlank { if (useHttpsFromProto) "443" else "80" }
        if (host.contains(":")) {
            // 排除 IPv6 情况：[::1]:80
            if (host.startsWith("[") && host.contains("]")) {
                port = host.substringAfter("]").removePrefix(":").ifBlank { port }
                host = host.substringBefore("]").removePrefix("[")
            } else {
                val tail = host.substringAfterLast(":")
                if (tail.toIntOrNull() != null) {
                    port = tail
                    host = host.substringBeforeLast(":")
                }
            }
        }
        val portInt = port.toIntOrNull() ?: return null

        // 3. 综合决定是否走 https
        val useHttps = useHttpsFromProto ||
            portInt == 443 || portInt == 8443 || portInt == 4433

        return Triple(host, portInt, useHttps)
    }

    /**
     * 忽略证书校验（扫描场景目标常为 IP 直连，证书不匹配）
     */
    private fun buildClient(): OkHttpClient {
        val trustManager = object : X509TrustManager {
            override fun checkClientTrusted(chain: Array<X509Certificate>, authType: String) {}
            override fun checkServerTrusted(chain: Array<X509Certificate>, authType: String) {}
            override fun getAcceptedIssuers(): Array<X509Certificate> = arrayOf()
        }
        val sslContext = SSLContext.getInstance("TLS")
        sslContext.init(null, arrayOf(trustManager), SecureRandom())

        return OkHttpClient.Builder()
            .connectTimeout(timeoutSeconds, TimeUnit.SECONDS)
            .readTimeout(timeoutSeconds, TimeUnit.SECONDS)
            .writeTimeout(timeoutSeconds, TimeUnit.SECONDS)
            .sslSocketFactory(sslContext.socketFactory, trustManager)
            .hostnameVerifier { _, _ -> true }
            .followRedirects(false)
            .build()
    }
}
