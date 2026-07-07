from fastapi import FastAPI
from pydantic import BaseModel
import httpx

from app.services.pipeline_seguridad import analisis_de_patrones, validar_contexto
from app.services.asesor_gemini import consultar_asesor
app = FastAPI(
    title="Agente de Ciberseguridad",
    description="Webhook con pipeline de seguridad para deteccion de amenazas",
    version="1.0.0"
)

RASA_NLU_URL = "http://localhost:5005/model/parse"

MENSAJES_RESPUESTA = {
    "saludo": "Hola, soy el asistente de ciberseguridad. ¿En qué puedo ayudarte?",
    "despedida": "Hasta luego. Mantente seguro.",
    "consulta_normal": "Estoy procesando tu consulta de seguridad.",
    "intento_inyeccion_prompt": "⚠️ Se detectó un posible intento de inyección de instrucciones.",
    "intento_ingenieria_social": "⚠️ Este mensaje presenta patrones de ingeniería social.",
    "solicitud_info_sensible": "⚠️ No puedo compartir credenciales ni información sensible.",
    "ofuscacion_lenguaje": "⚠️ Se detectó un posible intento de evasión de filtros.",
}

MENSAJE_RIESGO_ALTO_GENERICO = "⚠️ Este mensaje fue marcado como riesgo alto por el pipeline de seguridad."


class MensajeEntrada(BaseModel):
    texto: str
    usuario_id: str = "anonimo"

class ConsultaAsesor(BaseModel):
    pregunta: str
    texto_original: str = ""
    intent_detectado: str = ""
    nivel_riesgo: str = ""
    coincidencias_patrones: list = []

@app.get("/")
def raiz():
    return {"estado": "activo", "servicio": "Agente de Ciberseguridad"}


@app.get("/health")
def health_check():
    return {"status": "ok"}


@app.post("/webhook/mensaje")
async def recibir_mensaje(mensaje: MensajeEntrada):
    # Capa 1: analisis de patrones
    coincidencias = analisis_de_patrones(mensaje.texto)

    # Capa 2: evaluacion semantica (Rasa NLU)
    async with httpx.AsyncClient() as client:
        respuesta_rasa = await client.post(
            RASA_NLU_URL,
            json={"text": mensaje.texto}
        )
    datos_nlu = respuesta_rasa.json()
    intent = datos_nlu.get("intent", {}).get("name", "desconocido")
    confianza = datos_nlu.get("intent", {}).get("confidence", 0.0)

    # Capa 3: validacion de contexto (combina las dos senales anteriores)
    nivel_riesgo = validar_contexto(intent, confianza, coincidencias)

    mensaje_respuesta = MENSAJES_RESPUESTA.get(intent, MENSAJE_RIESGO_ALTO_GENERICO)
    if nivel_riesgo == "alto" and intent not in MENSAJES_RESPUESTA:
        mensaje_respuesta = MENSAJE_RIESGO_ALTO_GENERICO

    return {
        "usuario_id": mensaje.usuario_id,
        "texto_original": mensaje.texto,
        "pipeline_seguridad": {
            "analisis_de_patrones": {
                "coincidencias_encontradas": coincidencias,
                "cantidad": len(coincidencias),
            },
            "evaluacion_semantica": {
                "intent_detectado": intent,
                "confianza": round(confianza, 4),
            },
            "validacion_de_contexto": {
                "nivel_riesgo_final": nivel_riesgo,
            },
        },
        "respuesta": mensaje_respuesta,
    }

@app.post("/asesor/consulta")
async def consultar_asesor_seguridad(consulta: ConsultaAsesor):
    contexto = {
        "texto_original": consulta.texto_original,
        "intent_detectado": consulta.intent_detectado,
        "nivel_riesgo": consulta.nivel_riesgo,
        "coincidencias_patrones": consulta.coincidencias_patrones,
    }

    respuesta_asesor = consultar_asesor(consulta.pregunta, contexto)

    return {
        "pregunta": consulta.pregunta,
        "respuesta_asesor": respuesta_asesor,
    }