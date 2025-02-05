"""
Módulo de utilidades para interactuar con la API de VirusTotal.

Este módulo contiene funciones diseñadas para facilitar la consulta y el procesamiento de información sobre malware. Aca podrás obtener datos de MITRE ATT&CK, análisis de comportamiento y comentarios de la comunidad.
"""

import requests
import os
from fastapi import FastAPI, HTTPException, Query

# Configuración de la API de VirusTotal
VT_API_URL = "https://www.virustotal.com/api/v3/files/"
VT_API_KEY = os.getenv("VIRUSTOTAL_API_KEY")

def get_vt_mitre_attack(file_hash: str):
    """
    Obtiene datos del marco MITRE ATT&CK desde VirusTotal para un hash específico.
    
    Argumentos:
        file_hash (str): El hash del archivo que deseas consultar.
    
    Retorna:
        dict: Un diccionario con la información de MITRE ATT&CK.
    
    Excepciones:
        requests.exceptions.HTTPError: Se lanza si hay algún error al comunicarse con la API.
    """
    headers = {"accept": "application/json", "x-apikey": VT_API_KEY}
    response = requests.get(f"{VT_API_URL}{file_hash}/behaviour_mitre_trees", headers=headers)
    response.raise_for_status()
    return response.json()

def get_vt_behavior_summary(file_hash: str):
    """
    Obtiene el resumen del análisis de comportamiento desde VirusTotal.
    
    Argumentos:
        file_hash (str): El hash del archivo que deseas consultar.
    
    Retorna:
        dict: Un diccionario con el resumen del comportamiento.
    
    Excepciones:
        requests.exceptions.HTTPError: Se lanza en caso de error al comunicarse con la API.
    """
    headers = {"accept": "application/json", "x-apikey": VT_API_KEY}
    response = requests.get(f"{VT_API_URL}{file_hash}/behaviour_summary", headers=headers)
    response.raise_for_status()
    return response.json()

def get_vt_comments(file_hash: str):
    """
    Recupera hasta 10 comentarios recientes de la comunidad en VirusTotal para el archivo consultado.
    
    Argumentos:
        file_hash (str): El hash del archivo que deseas consultar.
    
    Retorna:
        dict: Un diccionario con los comentarios de la comunidad.
    
    Excepciones:
        requests.exceptions.HTTPError: Se lanza en caso de error durante la consulta.
    """
    headers = {"accept": "application/json", "x-apikey": VT_API_KEY}
    response = requests.get(f"{VT_API_URL}{file_hash}/comments?limit=10", headers=headers)
    response.raise_for_status()
    return response.json()

def get_virustotal_data(file_hash: str):
    """
    Obtiene información general de VirusTotal sobre el archivo especificado.
    
    Argumentos:
        file_hash (str): El hash del archivo que deseas consultar.
    
    Retorna:
        dict: Un diccionario con la información general del archivo.
    
    Excepciones:
        requests.exceptions.HTTPError: Se lanza si ocurre un error al comunicarse con la API.
    """
    headers = {
        "accept": "application/json",
        "x-apikey": VT_API_KEY
    }
    response = requests.get(f"{VT_API_URL}{file_hash}", headers=headers)
    response.raise_for_status()
    return response.json()

def extract_vt_cti(vt_data: dict, vt_mitre: dict = None, vt_behavior: dict = None, vt_comments: dict = None):
    """
    Procesa y organiza la información de CTI obtenida de VirusTotal en un formato claro y comprensible.
    
    Combina datos básicos del archivo, resultados de detección, información de MITRE ATT&CK, análisis de comportamiento y comentarios de la comunidad.
    
    Argumentos:
        vt_data (dict): Datos principales obtenidos de VirusTotal.
        vt_mitre (dict, opcional): Información del marco MITRE ATT&CK.
        vt_behavior (dict, opcional): Resumen del análisis de comportamiento.
        vt_comments (dict, opcional): Comentarios de la comunidad.
    
    Retorna:
        dict: Un diccionario con la información estructurada de CTI.
    
    Excepciones:
        HTTPException: Se lanza si no se encuentra la información necesaria en VirusTotal.
    """
    if "data" not in vt_data or "attributes" not in vt_data["data"]:
        raise HTTPException(
            status_code=404, 
            detail="Archivo no encontrado en VirusTotal o no hay atributos disponibles"
        )

    data = vt_data["data"] 
    attributes = data["attributes"]

    cti_data = {
        "source": "VirusTotal",
        "file_info": {
            "hashes": {
                "md5": attributes.get("md5", "Not found"),
                "sha1": attributes.get("sha1", "Not found"),
                "sha256": attributes.get("sha256", "Not found"),
                "authentihash": attributes.get("authentihash", "Not found"),
                "imphash": attributes.get("pe_info", {}).get("imphash", "Not found"),
                "ssdeep": attributes.get("ssdeep", "Not found"),
            },
            "names": attributes.get("names", []),
            "magic": attributes.get("magic", "Not found"),
            "file_type_tags": attributes.get("type_tags", []),
            "tags": attributes.get("tags", []),
            "times_submitted": attributes.get("times_submitted", "Not found"),
            "first_submission_date": attributes.get("first_submission_date", "Not found"),
            "last_submission_date": attributes.get("last_submission_date", "Not found"),
            "size": attributes.get("size", "Not found"),
        },
        "analysis": {
            "detections": [],
            "stats": attributes.get("last_analysis_stats", {}),
            "threat_classification": attributes.get("popular_threat_classification", {}),
            "sigma_rules": attributes.get("sigma_analysis_results", []),
            "crowdsourced_ids_results": attributes.get("crowdsourced_ids_results", []),
            "sandbox_verdicts": attributes.get("sandbox_verdicts", [])
        },
        "reputation": attributes.get("reputation", {}),
        "signature_info": attributes.get("signature_info", {}),
        "packers": attributes.get("packers", {}),
    }

    for engine, result in attributes.get("last_analysis_results", {}).items():
        cti_data["analysis"]["detections"].append({
            "engine_name": engine,
            "category": result.get("category"),
            "result": result.get("result")
        })

    # MITRE ATT&CK Framework
    cti_data['analysis']['mitre_attack'] = []
    if vt_mitre and 'data' in vt_mitre:
        for sandbox, tactics in vt_mitre['data'].items():
            mitre_entry = {
                'sandbox': sandbox,
                'tactics': []
            }
            for tactic in tactics.get('tactics', []):
                tactic_entry = {
                    'id': tactic['id'],
                    'name': tactic['name'],
                    'techniques': []
                }
                for technique in tactic.get('techniques', []):
                    tech_entry = {
                        'id': technique['id'],
                        'name': technique['name'],
                        'signatures': [
                            {'severity': sig['severity'], 'description': sig['description']}
                            for sig in technique.get('signatures', [])
                        ]
                    }
                    tactic_entry['techniques'].append(tech_entry)
                mitre_entry['tactics'].append(tactic_entry)
            cti_data['analysis']['mitre_attack'].append(mitre_entry)

    # Behavioral Analysis
    cti_data['behavior'] = {}
    if vt_behavior and 'data' in vt_behavior:
        behavior = vt_behavior['data']
        cti_data['behavior'] = {
            'files_opened': behavior.get('files_opened', []),
            'registry_keys': behavior.get('registry_keys_opened', []),
            'mutexes': list(set(behavior.get('mutexes_created', []) + behavior.get('mutexes_opened', []))),
            'processes': [p['name'] for p in behavior.get('processes_tree', [])],
            'network_indicators': behavior.get('text_highlighted', [])
        }

    # Community Comments
    cti_data['comments'] = []
    if vt_comments and 'data' in vt_comments:
        for comment in vt_comments['data']:
            attrs = comment.get('attributes', {})
            cti_data['comments'].append({
                'date': attrs.get('date'),
                'tags': attrs.get('tags', []),
                'text': attrs.get('text'),
                'abuse_votes': attrs.get('votes', {}).get('abuse', 0)
            })

    return cti_data
