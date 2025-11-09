import json
import re
from datetime import datetime

def extraer_iocs(texto):
    """Extraer Indicadores de Compromiso (IOCs) del texto"""
    iocs = {
        'urls': set(),
        'domains': set(),
        'ips': set(),
        'hashes': set(),
        'emails': set()
    }
    
    # URLs
    urls = re.findall(r'https?://[^\s<>"{}|\\^`\[\]]+', texto)
    iocs['urls'].update(urls)
    
    # Dominios
    domains = re.findall(r'[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', texto)
    for domain in domains:
        if 'http' not in domain and len(domain) > 4:
            iocs['domains'].add(domain)
    
    # IPs
    ips = re.findall(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b', texto)
    iocs['ips'].update(ips)
    
    # Hashes (MD5, SHA1, SHA256)
    hashes = re.findall(r'\b[a-fA-F0-9]{32}\b', texto)  # MD5
    hashes.extend(re.findall(r'\b[a-fA-F0-9]{40}\b', texto))  # SHA1
    hashes.extend(re.findall(r'\b[a-fA-F0-9]{64}\b', texto))  # SHA256
    iocs['hashes'].update(hashes)
    
    # Emails
    emails = re.findall(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b', texto)
    iocs['emails'].update(emails)
    
    return iocs

def analizar_apt29_completo():
    # Cargar el archivo STIX
    with open('threat-actor--04147f1f-1c1a-450d-a4e6-2902bf821355.CLEAR.STIX.json', 'r', encoding='utf-8') as f:
        datos = json.load(f)
    
    # Estructuras para recolectar información
    resultados = {
        'aliases': set(),
        'malware': set(),
        'vulnerabilidades': set(),
        'campañas': [],
        'iocs': {'urls': set(), 'domains': set(), 'ips': set(), 'hashes': set(), 'emails': set()},
        'ttps': set(),
        'motivaciones': set(),
        'sectores_objetivo': set(),
        'actores_relacionados': set(),
        'descripciones': []
    }
    
    for objeto in datos['objects']:
        contenido = str(objeto.get('content', '')) + str(objeto.get('description', '')) + str(objeto.get('name', ''))
        
        if 'APT29' in contenido.upper():
            # Extraer IOCs
            iocs_objeto = extraer_iocs(contenido)
            for tipo, valores in iocs_objeto.items():
                resultados['iocs'][tipo].update(valores)
            
            # Extraer TTPs
            if 'phishing' in contenido.lower():
                resultados['ttps'].add('Spear Phishing')
            if 'spray' in contenido.lower():
                resultados['ttps'].add('Password Spray Attack')
            if 'RDP' in contenido:
                resultados['ttps'].add('RDP Exploitation')
            if 'backdoor' in contenido.lower():
                resultados['ttps'].add('Backdoor Installation')
            if 'credential' in contenido.lower():
                resultados['ttps'].add('Credential Theft')
            if 'lateral' in contenido.lower():
                resultados['ttps'].add('Lateral Movement')
            if 'persistence' in contenido.lower() or 'persistent' in contenido.lower():
                resultados['ttps'].add('Persistence')
            if 'supply chain' in contenido.lower():
                resultados['ttps'].add('Supply Chain Attack')
            
            # Extraer motivaciones
            if 'espionage' in contenido.lower() or 'intelligence' in contenido.lower():
                resultados['motivaciones'].add('Cyber Espionage')
            if 'political' in contenido.lower():
                resultados['motivaciones'].add('Political Intelligence')
            if 'vaccine' in contenido.lower() or 'covid' in contenido.lower():
                resultados['motivaciones'].add('Health Sector Intelligence')
            if 'government' in contenido.lower():
                resultados['motivaciones'].add('Government Targeting')
            if 'diplomatic' in contenido.lower():
                resultados['motivaciones'].add('Diplomatic Intelligence')
            
            # Extraer sectores objetivo
            if 'government' in contenido.lower():
                resultados['sectores_objetivo'].add('Government')
            if 'defense' in contenido.lower():
                resultados['sectores_objetivo'].add('Defense')
            if 'academia' in contenido.lower() or 'university' in contenido.lower():
                resultados['sectores_objetivo'].add('Academia')
            if 'NGO' in contenido or 'non-governmental' in contenido.lower():
                resultados['sectores_objetivo'].add('NGOs')
            if 'IT' in contenido or 'technology' in contenido.lower():
                resultados['sectores_objetivo'].add('Technology')
            if 'health' in contenido.lower() or 'medical' in contenido.lower():
                resultados['sectores_objetivo'].add('Healthcare')
            if 'diplomat' in contenido.lower():
                resultados['sectores_objetivo'].add('Diplomatic Missions')
        
        # Procesar tipos específicos de objetos
        if objeto['type'] == 'note':
            contenido_nota = objeto.get('content', '')
            if 'APT29' in contenido_nota.upper():
                # Extraer aliases
                if 'aka' in contenido_nota.lower():
                    partes = contenido_nota.split('aka')[-1].split(')')[0]
                    alias_list = [alias.strip() for alias in partes.split(',')]
                    resultados['aliases'].update(alias_list)
        
        elif objeto['type'] == 'malware':
            nombre = objeto.get('name', '')
            descripcion = objeto.get('description', '')
            if 'APT29' in descripcion.upper():
                resultados['malware'].add(nombre)
        
        elif objeto['type'] == 'vulnerability':
            nombre = objeto.get('name', '')
            descripcion = objeto.get('description', '')
            if 'APT29' in str(descripcion).upper():
                resultados['vulnerabilidades'].add(nombre)
        
        elif objeto['type'] == 'report':
            nombre = objeto.get('name', '')
            descripcion = objeto.get('description', '')
            if 'APT29' in str(descripcion).upper():
                resultados['campañas'].append(nombre)
        
        elif objeto['type'] == 'identity':
            nombre = objeto.get('name', '')
            if nombre and 'APT29' not in nombre.upper():
                resultados['actores_relacionados'].add(nombre)

    # Generar reporte
    fecha_actual = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    reporte = f"""
{'='*80}
INFORME COMPLETO DE INTELIGENCIA SOBRE AMENAZAS - APT29
{'='*80}
Fecha de generación: {fecha_actual}
Archivo analizado: threat-actor--04147f1f-1c1a-450d-a4e6-2902bf821355.CLEAR.STIX.json
Total de objetos STIX analizados: {len(datos['objects'])}

{'='*80}
ACTOR DE AMENAZA: APT29 (MIDNIGHT BLIZZARD)
{'='*80}
• Aliases identificados: {len(resultados['aliases'])}
• Motivaciones: {len(resultados['motivaciones'])}
• Sectores objetivo: {len(resultados['sectores_objetivo'])}

ALIASES:
{chr(10).join(['  • ' + alias for alias in sorted(resultados['aliases']) if alias and len(alias) > 2])}

MOTIVACIONES:
{chr(10).join(['  • ' + mot for mot in sorted(resultados['motivaciones'])])}

SECTORES OBJETIVO:
{chr(10).join(['  • ' + sector for sector in sorted(resultados['sectores_objetivo'])])}

{'='*80}
TTPs (TÁCTICAS, TÉCNICAS Y PROCEDIMIENTOS)
{'='*80}
Total de TTPs identificados: {len(resultados['ttps'])}

TÉCNICAS:
{chr(10).join(['  • ' + ttps for ttps in sorted(resultados['ttps'])])}

{'='*80}
MALWARE Y HERRAMIENTAS
{'='*80}
Total de familias de malware: {len(resultados['malware'])}

MALWARE:
{chr(10).join(['  • ' + malware for malware in sorted(resultados['malware'])])}

VULNERABILIDADES EXPLOTADAS:
{chr(10).join(['  • ' + vuln for vuln in sorted(resultados['vulnerabilidades'])])}

{'='*80}
CAMPAÑAS Y OPERACIONES
{'='*80}
Total de campañas documentadas: {len(resultados['campañas'])}

CAMPAÑAS:
{chr(10).join(['  • ' + camp for camp in sorted(resultados['campañas'])])}

{'='*80}
IOCs (INDICADORES DE COMPROMISO)
{'='*80}
• URLs: {len(resultados['iocs']['urls'])}
• Dominios: {len(resultados['iocs']['domains'])}
• IPs: {len(resultados['iocs']['ips'])}
• Hashes: {len(resultados['iocs']['hashes'])}
• Emails: {len(resultados['iocs']['emails'])}

URLs RELACIONADAS (primeras 10):
{chr(10).join(['  • ' + url for url in sorted(list(resultados['iocs']['urls'])[:10])])}

DOMINIOS SOSPECHOSOS (primeros 10):
{chr(10).join(['  • ' + domain for domain in sorted(list(resultados['iocs']['domains'])[:10])])}

IPs IDENTIFICADAS:
{chr(10).join(['  • ' + ip for ip in sorted(resultados['iocs']['ips'])])}

HASHES MALICIOSOS:
{chr(10).join(['  • ' + hash_val for hash_val in sorted(list(resultados['iocs']['hashes'])[:5])])}

{'='*80}
RESUMEN ESTADÍSTICO
{'='*80}
• Total objetos STIX analizados: {len(datos['objects'])}
• Aliases del actor: {len(resultados['aliases'])}
• TTPs identificados: {len(resultados['ttps'])}
• Familias de malware: {len(resultados['malware'])}
• Vulnerabilidades: {len(resultados['vulnerabilidades'])}
• Campañas documentadas: {len(resultados['campañas'])}
• IOCs extraídos: {sum(len(iocs) for iocs in resultados['iocs'].values())}
• Motivaciones: {len(resultados['motivaciones'])}
• Sectores objetivo: {len(resultados['sectores_objetivo'])}
{'='*80}
"""

    # Guardar en archivo
    nombre_archivo_salida = f"reporte_completo_APT29_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
    
    with open(nombre_archivo_salida, 'w', encoding='utf-8') as f:
        f.write(reporte)
    
    # Mostrar en pantalla
    print(reporte)
    print(f"Reporte completo guardado en: {nombre_archivo_salida}")

if __name__ == "__main__":
    analizar_apt29_completo()