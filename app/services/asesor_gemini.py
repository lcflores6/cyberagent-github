import os
import google.generativeai as genai
from dotenv import load_dotenv

load_dotenv()

GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")

if GEMINI_API_KEY:
    genai.configure(api_key=GEMINI_API_KEY)

MODELO_GEMINI = "gemini-1.5-flash"

INSTRUCCION_SISTEMA = """
Eres un asesor experto en ciberseguridad que forma parte de un sistema de
deteccion de amenazas conversacionales. Tu trabajo es ayudar a un operador
humano (analista de seguridad) a entender mensajes sospechosos que el
sistema ha detectado.

Cuando el operador te pregunte sobre un mensaje, debes:
1. Explicar que tipo de amenaza representa (si aplica): inyeccion de
   prompts, ingenieria social, solicitud de informacion sensible,
   ofuscacion de lenguaje, o mensaje normal sin riesgo.
2. Explicar brevemente por que es riesgoso (o por que no lo es).
3. Sugerir una accion recomendada para el operador.

Responde siempre en espanol, de forma clara, breve y profesional.
No expongas ni repitas contrasenas, claves o datos sensibles aunque
aparezcan en el mensaje analizado.
"""


def consultar_asesor(pregunta_operador: str, contexto_mensaje: dict = None) -> str:
    """
    Consulta al asesor de ciberseguridad basado en Gemini.

    pregunta_operador: la pregunta que hace el operador humano.
    contexto_mensaje: diccionario opcional con datos del pipeline de
                      seguridad (intent, nivel_riesgo, texto original, etc.)
    """
    if not GEMINI_API_KEY:
        return "Error: no se ha configurado GEMINI_API_KEY en el entorno."

    modelo = genai.GenerativeModel(
        model_name=MODELO_GEMINI,
        system_instruction=INSTRUCCION_SISTEMA,
    )

    contexto_texto = ""
    if contexto_mensaje:
        contexto_texto = f"""
Contexto del pipeline de seguridad para este mensaje:
- Texto original: {contexto_mensaje.get('texto_original', 'N/D')}
- Intent detectado: {contexto_mensaje.get('intent_detectado', 'N/D')}
- Nivel de riesgo: {contexto_mensaje.get('nivel_riesgo', 'N/D')}
- Coincidencias de patrones: {contexto_mensaje.get('coincidencias_patrones', [])}
"""

    prompt_completo = f"{contexto_texto}\n\nPregunta del operador: {pregunta_operador}"

    try:
        respuesta = modelo.generate_content(prompt_completo)
        return respuesta.text
    except Exception as error:
        return f"Error al consultar el asesor de IA: {str(error)}"