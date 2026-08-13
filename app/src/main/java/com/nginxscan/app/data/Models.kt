package com.nginxscan.app.data

/**
 * FoFa 资产信息
 */
data class FofaAsset(
    val host: String,
    val ip: String,
    val port: String,
    val protocol: String,
    val title: String,
    val banner: String,
    val server: String,
    val domain: String,
    val country: String,
    val city: String,
    val lastupdatetime: String,
)

/**
 * 扫描结果
 */
data class ScanResult(
    val asset: FofaAsset,
    val reachable: Boolean = false,
    val isNginx: Boolean = false,
    val nginxVersion: String? = null,          // 识别到的版本号，null=版本隐藏/未知
    val serverHeader: String = "",              // 实际响应 Server 头
    val statusCode: Int = 0,
    val matchedCves: List<CveHit> = emptyList(),
    val note: String = "",                      // 说明，如 "版本隐藏" / "非 Nginx" 等
)

/**
 * 命中的漏洞
 */
data class CveHit(
    val cveId: String,
    val name: String,
    val description: String,
    val affectedRange: String,
    val severity: String,
)
