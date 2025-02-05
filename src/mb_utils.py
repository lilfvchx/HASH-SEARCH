"""
Módulo para interactuar con la API de MalwareBazaar.

Este módulo contiene funciones para consultar y procesar datos de malware desde la plataforma MalwareBazaar. Aquí podrás obtener información detallada sobre muestras de malware y extraer datos útiles para análisis de inteligencia de amenazas (CTI).
"""

import requests
from fastapi import HTTPException
import os


MB_API_URL = "https://mb-api.abuse.ch/api/v1/"
MB_API_KEY = os.getenv("MALWARE_BAZAAR_API_KEY")  


def extract_mb_cti(mb_data: dict):
    """
    Extrae y estructura información CTI relevante de la respuesta de MalwareBazaar.
    
    Argumentos:
        mb_data (dict): Datos crudos obtenidos de la API de MalwareBazaar.
    
    Retorna:
        dict: Un diccionario con la información estructurada, incluyendo detalles del archivo, hashes y resultados del análisis.
    
    Excepciones:
        HTTPException: Se lanza si no se encuentran datos o se produce un error durante la consulta.
    """
    if mb_data.get("query_status") != "ok" or not mb_data.get("data"):
        raise HTTPException(status_code=404, detail="Archivo no encontrado en MalwareBazaar o no hay datos disponibles")

    data = mb_data["data"][0]

    cti_data = {
        "source": "MalwareBazaar",
        "file_info": {
            "hashes": {
                "sha256": data.get("sha256_hash", "Not found"),
                "sha1": data.get("sha1_hash", "Not found"),
                "md5": data.get("md5_hash", "Not found"),
                "imphash": data.get("imphash", "Not found"),
                "tlsh": data.get("tlsh",    "Not found"),
            },
            "first_seen": data.get("first_seen", "Not found"),
            "last_seen": data.get("last_seen", "Not found"),
            "file_name": data.get("file_name", "Not found"),
            "file_size": data.get("file_size", "Not found"),
            "file_type": data.get("file_type", "Not found"),
        },
        "analysis": {
            "writenon": data.get("trid", []),
            "signature": data.get("signature", "Not found"),
            "tags": data.get("tags", []),
            "delivery_method": data.get("delivery_method", "Not found"),
            "comments": data.get("comment", "Not found"),
            "vendor_intel": data.get("vendor_intel", {})
        },

    }

    return cti_data


def get_malwarebazaar_data(file_hash: str):
    """
    Consulta la API de MalwareBazaar para obtener información sobre un archivo basado en su hash.
    
    Argumentos:
        file_hash (str): El hash del archivo que deseas consultar (MD5, SHA1 o SHA256).
    
    Retorna:
        dict: La respuesta JSON con la información detallada del malware.
    
    Excepciones:
        requests.exceptions.HTTPError: Se lanza en caso de error al comunicarse con la API.
    """
    headers = {
        "Auth-Key": MB_API_KEY
    }
    data = {
        "query": "get_info",
        "hash": file_hash
    }
    response = requests.post(MB_API_URL, headers=headers, data=data)
    response.raise_for_status()
    import logging
    logging.info(response.json())
    return response.json()
