package com.nginxscan.app.data

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.withContext
import okhttp3.OkHttpClient
import okhttp3.Request
import org.json.JSONObject
import java.util.Base64
import java.util.concurrent.TimeUnit

/**
 * FoFa 客户端（单 Key 模式，FOFACLI_FOFA_KEY）
 * 文档：https://fofa.info/api
 */
class FofaClient(
    private val apiKey: String,
    private val timeoutSeconds: Long = 30,
) {
    private val client = OkHttpClient.Builder()
        .connectTimeout(timeoutSeconds, TimeUnit.SECONDS)
        .readTimeout(timeoutSeconds, TimeUnit.SECONDS)
        .build()

    /**
     * 分页拉取搜索全部结果
     *
     * @param query  FoFa 语法，如 app="NGINX"
     * @param pageSize 每页大小，最多 10000（vip）
     * @param maxPages 最多拉取多少页
     * @param onProgress 每页回调，参数为 (已获取条数, 总条数)
     */
    suspend fun searchAll(
        query: String,
        pageSize: Int = 100,
        maxPages: Int = 10,
        onProgress: ((fetched: Int, total: Int) -> Unit)? = null,
    ): List<FofaAsset> = withContext(Dispatchers.IO) {
        val result = mutableListOf<FofaAsset>()
        var page = 1
        var total = 0

        while (true) {
            val (assets, totalCount) = searchPage(query, page, pageSize)
            result.addAll(assets)
            total = totalCount
            onProgress?.invoke(result.size, total)

            // 到达最后一页或获取完毕
            if (assets.isEmpty() || result.size >= totalCount || page >= maxPages) break
            page++
            delay(300) // FoFa 免费版有频率限制，适度休眠
        }
        result
    }

    /**
     * 拉取单页
     */
    private fun searchPage(query: String, page: Int, pageSize: Int): Pair<List<FofaAsset>, Int> {
        val qbase64 = Base64.getEncoder().encodeToString(query.toByteArray(Charsets.UTF_8))
        val fields = listOf(
            "host", "ip", "port", "protocol", "title", "banner",
            "server", "domain", "country", "city", "lastupdatetime"
        ).joinToString(",")

        val url = "https://fofa.info/api/v1/search/all?" +
            "key=${urlEncode(apiKey)}" +
            "&qbase64=${urlEncode(qbase64)}" +
            "&size=$pageSize" +
            "&page=$page" +
            "&fields=${urlEncode(fields)}"

        val request = Request.Builder()
            .url(url)
            .header("User-Agent", "nginxscan-android/1.0")
            .get()
            .build()

        client.newCall(request).execute().use { resp ->
            if (!resp.isSuccessful) {
                throw RuntimeException("FoFa HTTP ${resp.code}: ${resp.body?.string()?.take(300)}")
            }
            val body = resp.body!!.string()
            val json = JSONObject(body)

            if (json.optBoolean("error", false)) {
                val errmsg = json.optString("errmsg", "unknown")
                throw RuntimeException("FoFa error: $errmsg")
            }

            val total = json.optInt("size", 0)
            val assets = mutableListOf<FofaAsset>()
            val results = json.optJSONArray("results") ?: return assets to total
            for (i in 0 until results.length()) {
                val row = results.optJSONArray(i) ?: continue
                fun str(idx: Int) = if (idx < row.length()) row.optString(idx) else ""
                assets.add(
                    FofaAsset(
                        host = str(0),
                        ip = str(1),
                        port = str(2),
                        protocol = str(3),
                        title = str(4),
                        banner = str(5),
                        server = str(6),
                        domain = str(7),
                        country = str(8),
                        city = str(9),
                        lastupdatetime = str(10),
                    )
                )
            }
            return assets to total
        }
    }

    private fun urlEncode(s: String): String =
        java.net.URLEncoder.encode(s, "UTF-8")
}
