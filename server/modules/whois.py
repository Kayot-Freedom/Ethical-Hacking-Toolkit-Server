def whois_lookup(host: str) -> dict:
    try:
        import whois
        w = whois.whois(host)
        return {
            "registrar": w.registrar,
            "creation_date": str(w.creation_date),
            "expiration_date": str(w.expiration_date),
            "name_servers": w.name_servers,
        }
    except Exception as e:
        return {"error": str(e)}