import asyncio
from sslyze import (
    Scanner,
    ServerNetworkLocation,
    ServerScanRequest,
    ScanCommand,
)
from sslyze.errors import ConnectionToServerFailed


async def tls_deep_analysis(host: str, port: int = 443) -> dict:
    """
    Глубокий анализ TLS через sslyze.
    Запускаем в отдельном потоке, чтобы не блокировать event loop.
    """
    return await asyncio.to_thread(_sync_scan, host, port)


def _sync_scan(host: str, port: int) -> dict:
    try:
        server_location = ServerNetworkLocation(hostname=host, port=port)
    except Exception as e:
        return {"error": f"Не удалось создать ServerNetworkLocation: {e}"}

    scanner = Scanner()
    try:
        scanner.queue_scans([ServerScanRequest(
            server_location=server_location,
            scan_commands={
                ScanCommand.CERTIFICATE_INFO,
                ScanCommand.SSL_2_0_CIPHER_SUITES,
                ScanCommand.SSL_3_0_CIPHER_SUITES,
                ScanCommand.TLS_1_0_CIPHER_SUITES,
                ScanCommand.TLS_1_1_CIPHER_SUITES,
                ScanCommand.TLS_1_2_CIPHER_SUITES,
                ScanCommand.TLS_1_3_CIPHER_SUITES,
                ScanCommand.HEARTBLEED,
                ScanCommand.ROBOT,
            },
        )])
    except Exception as e:
        return {"error": f"Ошибка очереди сканирования: {e}"}

    result_data = None
    for result in scanner.get_results():
        if result.scan_status.name == "ERROR":
            return {"error": f"Скан провалился: {getattr(result, 'connectivity_error_trace', 'unknown')}"}
        result_data = result
        break

    if result_data is None:
        return {"error": "Скан не дал результатов"}

    # Извлекаем данные
    supported_protocols = []
    weak_protocols = []
    deprecated = {"SSL_2_0", "SSL_3_0", "TLS_1_0", "TLS_1_1"}

    for cmd_enum in ScanCommand:
        if not cmd_enum.name.endswith("CIPHER_SUITES"):
            continue
        attr = cmd_enum.value.attr_name
        try:
            res = getattr(result_data.scan_result, attr, None)
            if not res or not res.is_tls_version_supported:
                continue
            version = cmd_enum.name.replace("_CIPHER_SUITES", "").replace("_", ".")
            supported_protocols.append(version)
            if cmd_enum.name in deprecated:
                weak_protocols.append(version)
        except Exception:
            continue

    # Сертификаты
    cert_info = None
    try:
        dep_res = result_data.scan_result.certificate_info
        if dep_res:
            cert_deployments = dep_res.certificate_deployments
            if cert_deployments:
                leaf = cert_deployments[0].received_certificate_chain[0]
                cert_info = {
                    "subject": leaf.subject.rfc4514_string(),
                    "issuer": leaf.issuer.rfc4514_string(),
                    "not_valid_before": str(leaf.not_valid_before_utc),
                    "not_valid_after": str(leaf.not_valid_after_utc),
                    "serial": hex(leaf.serial_number),
                    "signature_algorithm": leaf.signature_hash_algorithm.name if leaf.signature_hash_algorithm else None,
                    "public_key_size": leaf.public_key().key_size if hasattr(leaf.public_key(), "key_size") else None,
                }
    except Exception as e:
        cert_info = {"error": str(e)}

    # Heartbleed
    heartbleed = None
    try:
        hb = result_data.scan_result.heartbleed
        if hb:
            heartbleed = hb.is_vulnerable_to_heartbleed
    except Exception:
        pass

    # ROBOT
    robot = None
    try:
        rb = result_data.scan_result.robot
        if rb:
            robot = str(rb.robot_result)
    except Exception:
        pass

    issues = []
    if weak_protocols:
        issues.append(f"Устаревшие протоколы: {', '.join(weak_protocols)}")
    if heartbleed is True:
        issues.append("КРИТИЧНО: уязвим к Heartbleed")
    if robot and "VULNERABLE" in robot.upper():
        issues.append("Уязвим к ROBOT attack")

    return {
        "supported_protocols": supported_protocols,
        "weak_protocols": weak_protocols,
        "certificate": cert_info,
        "heartbleed_vulnerable": heartbleed,
        "robot": robot,
        "issues": issues,
        "safe": len(issues) == 0,
    }