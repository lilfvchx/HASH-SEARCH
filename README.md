# CTI Data Aggregator API

API REST que agrega datos de inteligencia de amenazas (CTI) de múltiples fuentes (VirusTotal y MalwareBazaar) para un hash de archivo específico.

## Requisitos Previos

- Docker y Docker Compose
- O Python 3.11+ (para ejecución local)

## Configuración

1. Clonar el repositorio
2. Crear archivo `.env` en la raíz del proyecto:
```
VT_API_KEY=your_virustotal_api_key
MB_API_KEY=your_malwarebazaar_api_key
```

## Ejecución

### Usando Docker (Recomendado)

1. Construir y ejecutar con Docker Compose:
```bash
docker compose up --build
```

2. Para detener la aplicación:
```bash
docker compose down
```

### Ejecución Local (Alternativa)

1. Crear entorno virtual:
```bash
python -m venv venv
source venv/bin/activate  # Linux/Mac
.\venv\Scripts\activate   # Windows
```

2. Instalar dependencias:
```bash
pip install -r requirements.txt
```

3. Ejecutar la aplicación:
```bash
uvicorn main:app --reload
```

## Uso de la API

La API estará disponible en: http://localhost:8000

### Documentación
- Swagger UI: http://localhost:8000/docs
- ReDoc: http://localhost:8000/redoc

### Endpoint Principal

GET `/cti/{file_hash}`
- Parámetros:
  - `file_hash`: Hash del archivo (MD5, SHA-1, SHA-256)
  - `format`: (opcional) 'csv' o 'excel' para descarga de reporte

Ejemplo:
```bash
curl http://localhost:8000/cti/YOUR_HASH_HERE
curl http://localhost:8000/cti/YOUR_HASH_HERE?format=excel
```

## Características

- Consulta a VirusTotal y MalwareBazaar
- Extracción de datos CTI relevantes:
  - Información de archivo (hashes, nombres, tamaños)
  - Detecciones de antivirus
  - Análisis MITRE ATT&CK
  - Comportamiento del malware
  - Comentarios de la comunidad
- Exportación de resultados en múltiples formatos:
  - JSON (formato predeterminado)
  - CSV
  - Excel (con múltiples hojas organizadas por tipo de dato)

## Instalación

1. Clonar el repositorio :
```bash
git clone https://github.com/lilfvchx/VT-MB-Search
cd VT-MB-SEARCH
```

2. Crear y activar entorno virtual:
```bash
python -m venv venv
source venv/bin/activate  # Linux/Mac
venv\Scripts\activate     # Windows
```

3. Instalar dependencias:
```bash
pip install -r requirements.txt
```

4. Configurar variables de entorno:
Crear archivo `.env` con las siguientes variables:
```
VIRUSTOTAL_API_KEY=your_vt_api_key
MALWARE_BAZAAR_API_KEY=your_mb_api_key
```

## Uso

1. Iniciar el servidor:
```bash
uvicorn main:app --reload
```

2. Acceder al endpoint principal:
```
GET /cti/{file_hash}
```

### Parámetros

- `file_hash`: Hash MD5, SHA-1 o SHA-256 del archivo
- `format` (opcional): Formato de salida ('csv' o 'excel') si no es especificado, se devuelve JSON

### Ejemplos

Consulta básica (retorna JSON):
```
GET /cti/44d88612fea8a8f36de82e1278abb02f
```

Exportar a CSV:
```
GET /cti/44d88612fea8a8f36de82e1278abb02f?format=csv
```

Exportar a Excel:
```
GET /cti/44d88612fea8a8f36de82e1278abb02f?format=excel
```

## Estructura del Proyecto

```
MELI/
├── main.py           # Punto de entrada y rutas de la API
├── requirements.txt  # Dependencias del proyecto
├── src/
│   ├── vt_utils.py    # Utilidades para VirusTotal
│   ├── mb_utils.py    # Utilidades para MalwareBazaar
│   └── utils.py       # Utilidades generales
└── .env             # Variables de entorno (no incluido en repo)
```

## Documentación API

La documentación completa de la API está disponible en:
```
http://localhost:8000/docs
```

## Dependencias Principales

- FastAPI: Framework web moderno y rápido
- Requests: Cliente HTTP para Python
- Pandas: Manipulación y análisis de datos
- python-dotenv: Manejo de variables de entorno
