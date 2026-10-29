from flask import Flask, request, jsonify
import json
import logging
from datetime import datetime

app = Flask(__name__)

# Configuración de logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('/app/logs/backend_audit.log'),
        logging.StreamHandler()
    ]
)

@app.route('/audit', methods=['POST'])
def backend_audit():
    """Recibe eventos de auditoría del backend MinIO"""
    try:
        data = request.get_json()
        
        # Log eventos críticos de seguridad
        if 'failed' in str(data).lower() or 'error' in str(data).lower():
            logging.critical(f"BACKEND SECURITY EVENT: {json.dumps(data, indent=2)}")
        else:
            logging.info(f"Backend audit event: {data.get('eventName', 'unknown')}")
        
        return jsonify({'status': 'backend_audit_received'}), 200
        
    except Exception as e:
        logging.error(f"Error processing backend audit: {e}")
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080)