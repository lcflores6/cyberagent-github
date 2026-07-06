import re

PATRONES_SOSPECHOSOS = [
    r"ignora.*instrucciones",
    r"olvida.*reglas",
    r"sin\s+restricciones",
    r"sin\s+filtros",
    r"eres\s+DAN",
    r"contrasena",
    r"clave\s+privada",
    r"acceso\s+total",
    r"acceso\s+root",
    r"token\s+de\s+acceso",
]


def analisis_de_patrones(texto: str) -> list:
    """Capa 1: analisis de patrones con expresiones regulares."""
    texto_normalizado = texto.lower()
    coincidencias = []
    for patron in PATRONES_SOSPECHOSOS:
        if re.search(patron, texto_normalizado):
            coincidencias.append(patron)
    return coincidencias


def validar_contexto(intent: str, confianza: float, coincidencias_patrones: list) -> str:
    """Capa 3: combina la senal semantica (Rasa) con la senal de patrones."""
    intents_riesgo_alto = {
        "intento_inyeccion_prompt",
        "intento_ingenieria_social",
        "solicitud_info_sensible",
    }
    intents_riesgo_medio = {"ofuscacion_lenguaje"}

    if intent in intents_riesgo_alto and confianza >= 0.5:
        return "alto"
    if coincidencias_patrones:
        return "alto"
    if intent in intents_riesgo_medio:
        return "medio"
    if intent in {"saludo", "despedida", "consulta_normal"}:
        return "ninguno"
    return "desconocido"