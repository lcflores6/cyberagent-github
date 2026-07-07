import csv
import io
from datetime import datetime

import httpx

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

# Timeout para evitar que una fuente externa lenta bloquee el sistema
TIMEOUT_SEGUNDOS = 10.0


async def consultar_cve(keyword: str, resultados_max: int = 5) -> dict:
    """
    Consulta la API publica de NVD para buscar CVEs relacionados con
    una palabra clave (ej. 'sql injection', 'phishing', 'buffer overflow').

    Incluye validacion de certificado SSL/TLS para prevenir ataques
    Man-in-the-Middle: httpx verifica el certificado del servidor
    por defecto (verify=True), rechazando conexiones con certificados
    invalidos o suplantados.
    """
    parametros = {
        "keywordSearch": keyword,
        "resultsPerPage": resultados_max,
    }

    try:
        async with httpx.AsyncClient(
            timeout=TIMEOUT_SEGUNDOS,
            verify=True,  # Verificacion de certificado SSL: previene MITM
        ) as client:
            respuesta = await client.get(NVD_API_URL, params=parametros)
            respuesta.raise_for_status()
            datos = respuesta.json()
    except httpx.TimeoutException:
        return {"error": "Tiempo de espera agotado al consultar NVD", "cves": []}
    except httpx.HTTPStatusError as error:
        return {"error": f"Error HTTP de NVD: {error.response.status_code}", "cves": []}
    except httpx.RequestError as error:
        return {"error": f"Error de conexion (posible problema de red o certificado): {str(error)}", "cves": []}

    cves_encontrados = []
    for item in datos.get("vulnerabilities", []):
        cve_data = item.get("cve", {})
        cve_id = cve_data.get("id", "N/D")
        descripciones = cve_data.get("descriptions", [])
        descripcion_en = next(
            (d["value"] for d in descripciones if d.get("lang") == "en"),
            "Sin descripcion disponible",
        )
        cves_encontrados.append({
            "cve_id": cve_id,
            "descripcion": descripcion_en,
            "fecha_publicacion": cve_data.get("published", "N/D"),
        })

    return {
        "keyword_buscada": keyword,
        "total_resultados": len(cves_encontrados),
        "cves": cves_encontrados,
        "consultado_en": datetime.utcnow().isoformat(),
    }


def exportar_cves_a_csv(datos_cve: dict) -> str:
    """
    Convierte los resultados de CVEs a formato CSV (como texto),
    listo para descargar o guardar en archivo.
    """
    buffer = io.StringIO()
    escritor = csv.writer(buffer)
    escritor.writerow(["cve_id", "descripcion", "fecha_publicacion"])

    for cve in datos_cve.get("cves", []):
        escritor.writerow([
            cve.get("cve_id", ""),
            cve.get("descripcion", ""),
            cve.get("fecha_publicacion", ""),
        ])

    return buffer.getvalue()