import os
import weaviate
from weaviate.classes.init import Auth
from weaviate.classes.config import Configure, Property, DataType
from weaviate.classes.query import MetadataQuery
from dotenv import load_dotenv

load_dotenv()

WEAVIATE_URL = os.getenv("WEAVIATE_URL")
WEAVIATE_API_KEY = os.getenv("WEAVIATE_API_KEY")

NOMBRE_COLECCION = "VulnerabilidadCVE"


def obtener_cliente():
    """Crea y retorna un cliente conectado a Weaviate Cloud."""
    return weaviate.connect_to_weaviate_cloud(
        cluster_url=WEAVIATE_URL,
        auth_credentials=Auth.api_key(WEAVIATE_API_KEY),
    )


def crear_coleccion_si_no_existe():
    """Crea la coleccion (esquema) de vulnerabilidades si no existe."""
    client = obtener_cliente()
    try:
        if not client.collections.exists(NOMBRE_COLECCION):
            client.collections.create(
                name=NOMBRE_COLECCION,
                properties=[
                    Property(name="cve_id", data_type=DataType.TEXT),
                    Property(name="descripcion", data_type=DataType.TEXT),
                    Property(name="fecha_publicacion", data_type=DataType.TEXT),
                ],
                vectorizer_config=Configure.Vectorizer.text2vec_weaviate(),
            )
            return True
        return False
    finally:
        client.close()


def indexar_cves(lista_cves: list) -> int:
    """
    Inserta una lista de CVEs (obtenidos de threat_intelligence.py)
    en la base de datos vectorial de Weaviate para busqueda semantica.
    """
    crear_coleccion_si_no_existe()
    client = obtener_cliente()
    try:
        coleccion = client.collections.get(NOMBRE_COLECCION)
        contador = 0
        with coleccion.batch.dynamic() as batch:
            for cve in lista_cves:
                batch.add_object(properties={
                    "cve_id": cve.get("cve_id", ""),
                    "descripcion": cve.get("descripcion", ""),
                    "fecha_publicacion": cve.get("fecha_publicacion", ""),
                })
                contador += 1
        return contador
    finally:
        client.close()


def buscar_semanticamente(consulta: str, limite: int = 3) -> list:
    """
    Busca vulnerabilidades por similitud semantica (no por palabra exacta).
    Por ejemplo, buscar 'robo de datos' puede encontrar CVEs sobre
    'exfiltracion de informacion' aunque no compartan las mismas palabras.
    """
    client = obtener_cliente()
    try:
        if not client.collections.exists(NOMBRE_COLECCION):
            return []

        coleccion = client.collections.get(NOMBRE_COLECCION)
        resultados = coleccion.query.near_text(
            query=consulta,
            limit=limite,
            return_metadata=MetadataQuery(distance=True),
        )

        salida = []
        for objeto in resultados.objects:
            salida.append({
                "cve_id": objeto.properties.get("cve_id"),
                "descripcion": objeto.properties.get("descripcion"),
                "fecha_publicacion": objeto.properties.get("fecha_publicacion"),
                "distancia_semantica": objeto.metadata.distance,
            })
        return salida
    finally:
        client.close()