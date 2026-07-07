from fastapi import WebSocket
from typing import List
import json
from datetime import datetime


class GestorConexionesWebSocket:
    """Administra las conexiones WebSocket activas del dashboard."""

    def __init__(self):
        self.conexiones_activas: List[WebSocket] = []

    async def conectar(self, websocket: WebSocket):
        await websocket.accept()
        self.conexiones_activas.append(websocket)

    def desconectar(self, websocket: WebSocket):
        if websocket in self.conexiones_activas:
            self.conexiones_activas.remove(websocket)

    async def emitir_alerta(self, datos_alerta: dict):
        """Envia una alerta a todos los dashboards conectados."""
        mensaje = json.dumps({
            **datos_alerta,
            "timestamp": datetime.utcnow().isoformat(),
        })
        conexiones_caidas = []
        for conexion in self.conexiones_activas:
            try:
                await conexion.send_text(mensaje)
            except Exception:
                conexiones_caidas.append(conexion)

        for conexion in conexiones_caidas:
            self.desconectar(conexion)


gestor_websocket = GestorConexionesWebSocket()