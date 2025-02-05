# Importaciones necesarias
from fastapi import FastAPI, HTTPException, Query
from fastapi.responses import Response
import requests
import pandas as pd
from io import BytesIO
from dotenv import load_dotenv 
from src.vt_utils import get_vt_mitre_attack, get_vt_behavior_summary, get_vt_comments, get_virustotal_data, extract_vt_cti
from src.mb_utils import get_malwarebazaar_data, extract_mb_cti
from src.utils import file_hash_checker
import openpyxl

# Inicialización de la aplicación
load_dotenv()
app = FastAPI(
    title="Malware Bazaar & VirusTotal API",
    description="API para búsqueda de hash en múltiples fuentes",
    version="1.0.0"
)

@app.get("/cti/{file_hash}")
async def get_cti(file_hash: str, format: str = Query(None, enum=['csv', 'excel'])):
    """
Busca información sobre un hash en VirusTotal y MalwareBazaar util para CTI (Cyber Threat Intelligence) y, opcionalmente, permite descargarla en formato Excel/CSV o visualizarla en json.  

Este endpoint consulta las API de VirusTotal y MalwareBazaar para recopilar datos de inteligencia de amenazas sobre un hash de archivo específico. La información puede devolverse en formato JSON o descargarse como CSV/Excel.  

### Argumentos:  
- **file_hash (str):** El hash del archivo a consultar (MD5, SHA-1 o SHA-256).  
- **format (str, opcional):** Formato de salida ('csv' o 'excel'). Si es `None`, devuelve JSON.  

### Retorna:  
**Union[Dict, Response]:**  
- Si `format` es `None`: Un diccionario con los datos de CTI de ambas fuentes.  
- Si `format` es `'csv'`: Respuesta de descarga de archivo CSV.  
- Si `format` es `'excel'`: Respuesta de descarga de archivo Excel.  

### Excepciones:  
- **HTTPException:**  
  - `404`: Si el archivo no se encuentra en ninguno de los servicios.  
  - Otros códigos de estado: Para errores de comunicación con la API.  
  - `500`: Para errores internos de procesamiento.  

### Ejemplo de uso:  
```
GET /cti/a1b2c3d4...
GET /cti/a1b2c3d4...?format=csv
GET /cti/a1b2c3d4...?format=excel
```
    """
    
    # Obtención y procesamiento de datos de VirusTotal
    try:
        await file_hash_checker(file_hash)
        # Recopilación de diferentes tipos de datos de VirusTotal
        vt_data = get_virustotal_data(file_hash)         # Información general
        vt_mitre = get_vt_mitre_attack(file_hash)        # Datos MITRE ATT&CK
        vt_behavior = get_vt_behavior_summary(file_hash)  # Resumen de comportamiento
        vt_comments = get_vt_comments(file_hash)          # Comentarios de la comunidad
        
        vt_cti = extract_vt_cti(vt_data, vt_mitre, vt_behavior, vt_comments)
    except requests.exceptions.HTTPError as e:
        # Manejo de errores específicos de VirusTotal
        if e.response.status_code == 404:
            vt_cti = {"source": "VirusTotal", "error": "Archivo no encontrado en VirusTotal"}
        else:
            raise HTTPException(status_code=e.response.status_code, detail=f"Error al consultar VirusTotal: {e}")
    except Exception as e:
            raise HTTPException(status_code=500, detail=f"Error interno al procesar datos de VirusTotal: {e}")

    # Obtención y procesamiento de datos de MalwareBazaar
    try:
        mb_data = get_malwarebazaar_data(file_hash)
        
        mb_cti = extract_mb_cti(mb_data)
    except requests.exceptions.HTTPError as e:
        # Manejo de errores específicos de MalwareBazaar
        if e.response.status_code == 404:
            mb_cti = {"source": "MalwareBazaar", "error": "Archivo no encontrado en MalwareBazaar"}
        else:
            raise HTTPException(status_code=e.response.status_code, detail=f"Error al consultar MalwareBazaar: {e}")
    except Exception as e:
            raise HTTPException(status_code=500, detail=f"Error interno al procesar datos de MalwareBazaar: {e}")

    if format in ('csv', 'excel'):
        # Preparación de datos para exportación
        # Aplanamiento de datos de VirusTotal
        vt_flat = {
            'hashes': f"{vt_cti['file_info']['hashes']['md5']}|{vt_cti['file_info']['hashes']['sha256']}",
            'detections': "\n".join([f"{d['engine_name']}: {d['result']}" for d in vt_cti['analysis']['detections']]),
            'mitre_techniques': "\n".join(
                [f"{t['id']} - {t['name']}" 
                 for m in vt_cti['analysis']['mitre_attack'] 
                 for t in m['tactics'] 
                 for tech in t['techniques']]),
            'behavior_indicators': "\n".join(
                vt_cti['behavior'].get('files_opened', []) +
                vt_cti['behavior'].get('registry_keys', []) +
                vt_cti['behavior'].get('mutexes', [])),
            'comments': "\n".join([f"{c['date']}: {c['text']}" for c in vt_cti.get('comments', [])])
        }
        
        # Creación del DataFrame de VirusTotal
        vt_df = pd.DataFrame([vt_flat])
        vt_df['source'] = 'VirusTotal'

        # Aplanamiento de datos de MalwareBazaar
        mb_flat = {
            'hashes': f"{mb_cti['file_info']['hashes']['md5']}|{mb_cti['file_info']['hashes']['sha256']}",
            'file_name': mb_cti['file_info']['file_name'],
            'file_type': mb_cti['file_info']['file_type'],
            'first_seen': mb_cti['file_info']['first_seen'],
            'signature': mb_cti['analysis']['signature'],
            'tags': ", ".join(mb_cti['analysis']['tags'])
        }
        
        # Creación del DataFrame de MalwareBazaar y combinación
        mb_df = pd.DataFrame([mb_flat])
        mb_df['source'] = 'MalwareBazaar'
        
        combined_df = pd.concat([vt_df, mb_df], ignore_index=True)

        if format == 'csv':
            # Exportación a CSV
            csv = combined_df.to_csv(index=False)
            return Response(
                content=csv,
                media_type='text/csv',
                headers={'Content-Disposition': f'attachment; filename={file_hash}_threat_intel.csv'}
            )
        else:  # Excel
            # Exportación a Excel con múltiples hojas
            output = BytesIO()
            with pd.ExcelWriter(output, engine='openpyxl') as writer:
                # Hoja 1: Indicadores Clave
                combined_df.to_excel(writer, sheet_name='Indicadores Clave', index=False)
                
                # Hoja 2: MITRE ATT&CK - Técnicas y tácticas identificadas
                mitre_data = []
                for m in vt_cti.get('analysis', {}).get('mitre_attack', []):
                    for tactic in m.get('tactics', []):
                        for tech in tactic.get('techniques', []):
                            mitre_data.append({
                                'sandbox': m['sandbox'],
                                'tactic': tactic['name'],
                                'technique_id': tech['id'],
                                'technique': tech['name'],
                                'severities': ", ".join([s['severity'] for s in tech.get('signatures', [])])
                            })
                if mitre_data:
                    pd.DataFrame(mitre_data).to_excel(writer, sheet_name='MITRE ATT&CK', index=False)
                
                # Hoja 3: Comportamiento - Actividades observadas del malware
                behavior_data = pd.DataFrame({
                    'Tipo': ['Archivos', 'Registro', 'Mutexes', 'Procesos', 'Red'],
                    'Valores': [
                        "\n".join(vt_cti.get('behavior', {}).get('files_opened', [])),
                        "\n".join(vt_cti.get('behavior', {}).get('registry_keys', [])),
                        "\n".join(vt_cti.get('behavior', {}).get('mutexes', [])),
                        "\n".join(vt_cti.get('behavior', {}).get('processes', [])),
                        "\n".join(vt_cti.get('behavior', {}).get('network_indicators', []))
                    ]
                })
                behavior_data.to_excel(writer, sheet_name='Comportamiento', index=False)
                
                # Hoja 4: Detecciones - Resultados de motores antivirus
                detections_data = []
                for detection in vt_cti.get('analysis', {}).get('detections', []):
                    detections_data.append({
                        'Motor': detection['engine_name'],
                        'Categoría': detection['category'],
                        'Resultado': detection['result']
                    })
                if detections_data:
                    pd.DataFrame(detections_data).to_excel(writer, sheet_name='Detecciones AV', index=False)
                
                # Hoja 5: Comentarios - Información de la comunidad
                comments_data = []
                for comment in vt_cti.get('comments', []):
                    comments_data.append({
                        'Fecha': comment['date'],
                        'Tags': ", ".join(comment.get('tags', [])),
                        'Texto': comment['text'],
                        'Votos negativos': comment['abuse_votes']
                    })
                if comments_data:
                    pd.DataFrame(comments_data).to_excel(writer, sheet_name='Comentarios', index=False)

            # Preparación y envío del archivo Excel
            output.seek(0)
            return Response(
                content=output.getvalue(),
                media_type='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
                headers={'Content-Disposition': f'attachment; filename={file_hash}_threat_intel.xlsx'}
            )
    else:
        # Retorno de datos en formato JSON si no se especifica formato
        return {"virustotal": vt_cti, "malwarebazaar": mb_cti}