def diff_scans(old: dict, new: dict) -> dict:
    """
    Сравнивает два скана и возвращает изменения.
    old/new — полные data-объекты из БД.
    """
    changes = []

    # Порты
    old_ports = {p["port"]: p["state"] for p in (old.get("ports") or [])}
    new_ports = {p["port"]: p["state"] for p in (new.get("ports") or [])}
    for port, state in new_ports.items():
        if state == "open" and old_ports.get(port) != "open":
            changes.append({"type": "port_opened", "message": f"Порт {port} открылся"})
        if state == "closed" and old_ports.get(port) == "open":
            changes.append({"type": "port_closed", "message": f"Порт {port} закрылся"})

    # Заголовки
    old_missing = set((old.get("headers") or {}).get("missing_headers", []))
    new_missing = set((new.get("headers") or {}).get("missing_headers", []))
    for h in old_missing - new_missing:
        changes.append({"type": "header_added", "message": f"Заголовок {h} добавлен ✅"})
    for h in new_missing - old_missing:
        changes.append({"type": "header_removed", "message": f"Заголовок {h} пропал ⚠️"})

    # SSL
    old_ssl = old.get("ssl") or {}
    new_ssl = new.get("ssl") or {}
    if old_ssl.get("valid") != new_ssl.get("valid"):
        if new_ssl.get("valid"):
            changes.append({"type": "ssl_ok", "message": "SSL стал валидным ✅"})
        else:
            changes.append({"type": "ssl_bad", "message": "SSL перестал быть валидным ⚠️"})
    if old_ssl.get("not_after") != new_ssl.get("not_after"):
        changes.append({"type": "ssl_changed",
                        "message": f"SSL-сертификат обновлён: {new_ssl.get('not_after')}"})

    # Поддомены
    old_subs = set((old.get("subdomains") or {}).get("subdomains", []))
    new_subs = set((new.get("subdomains") or {}).get("subdomains", []))
    for s in new_subs - old_subs:
        changes.append({"type": "subdomain_new", "message": f"Новый поддомен: {s}"})
    for s in old_subs - new_subs:
        changes.append({"type": "subdomain_gone", "message": f"Поддомен исчез: {s}"})

    # Sensitive files
    old_files = {f["path"] for f in (old.get("sensitive_files") or {}).get("found", [])}
    new_files = {f["path"] for f in (new.get("sensitive_files") or {}).get("found", [])}
    for f in new_files - old_files:
        changes.append({"type": "sensitive_new", "message": f"⚠️ Новый публичный файл: {f}"})
    for f in old_files - new_files:
        changes.append({"type": "sensitive_fixed", "message": f"Файл {f} закрыт ✅"})

    # Score
    old_score = (old.get("risk_score") or {}).get("score")
    new_score = (new.get("risk_score") or {}).get("score")
    if old_score is not None and new_score is not None and old_score != new_score:
        arrow = "📈" if new_score > old_score else "📉"
        changes.append({
            "type": "score_changed",
            "message": f"Оценка: {old_score} → {new_score} {arrow}"
        })

    return {
        "changes": changes,
        "count": len(changes),
    }