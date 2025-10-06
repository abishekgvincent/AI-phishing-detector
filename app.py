import os
import requests
import urllib.parse
from flask import Flask, request, jsonify
from flask_cors import CORS
from dotenv import load_dotenv
import re
from check_phishing import check_url

# Load environment variables
load_dotenv()

app = Flask(__name__)
CORS(app)

# Load API configuration from environment
WHOIS_API_KEY = os.getenv('WHOIS_API_KEY')
WHOIS_ENDPOINT = os.getenv('WHOIS_ENDPOINT')
APIFLASH_API_KEY = os.getenv('APIFLASH_API_KEY')
APIFLASH_ENDPOINT = os.getenv('APIFLASH_ENDPOINT')

def extract_domain_from_url(url):
    """Extract root domain from URL"""
    try:
        # Remove protocol if present
        if url.startswith(('http://', 'https://')):
            url = url.split('://', 1)[1]

        # Remove www. prefix if present
        if url.startswith('www.'):
            url = url[4:]

        # Remove path and query parameters
        url = url.split('/')[0].split('?')[0].split('#')[0]

        # Remove port if present
        url = url.split(':')[0]

        return url.lower()
    except Exception:
        return None

def format_date(date_string):
    """Format ISO date string to readable format"""
    if not date_string:
        return 'N/A'

    try:
        # Handle various date formats that might come from WHOIS API
        from datetime import datetime

        # Try common date formats
        formats = [
            '%Y-%m-%dT%H:%M:%SZ',
            '%Y-%m-%dT%H:%M:%S.%fZ',
            '%Y-%m-%d',
            '%m/%d/%Y',
            '%d/%m/%Y'
        ]

        for fmt in formats:
            try:
                dt = datetime.strptime(date_string.split('T')[0], fmt.split('T')[0])
                return dt.strftime('%B %d, %Y')
            except ValueError:
                continue

        return date_string
    except Exception:
        return date_string

def generate_screenshot_url(url):
    """Generate ApiFlash screenshot URL for the given website"""
    try:
        if not APIFLASH_API_KEY or not APIFLASH_ENDPOINT:
            return None

        # Ensure URL has protocol
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url

        # Construct ApiFlash request URL with parameters
        params = {
            'access_key': APIFLASH_API_KEY,
            'url': url,
            'full_page': 'true',
            'format': 'png',
            'width': 1200,
            'height': 800,
            'delay': 3  # Wait 3 seconds for page to load
        }

        # Build query string
        query_string = '&'.join([f"{key}={urllib.parse.quote(str(value))}" for key, value in params.items()])
        screenshot_url = f"{APIFLASH_ENDPOINT}?{query_string}"

        return screenshot_url

    except Exception as e:
        print(f"Screenshot URL generation error: {str(e)}")
        return None

@app.route('/api/analyze', methods=['POST'])
def analyze_url():
    """Analyze URL for phishing and get WHOIS domain information"""
    try:
        data = request.get_json()

        if not data or 'url' not in data:
            return jsonify({'error': 'URL is required'}), 400

        url = data['url'].strip()
        if not url:
            return jsonify({'error': 'URL cannot be empty'}), 400

        # Extract domain from URL
        domain = extract_domain_from_url(url)
        if not domain:
            return jsonify({'error': 'Invalid URL format'}), 400


        model_result=check_url(url)

        # Get WHOIS information
        whois_details = None
        if WHOIS_API_KEY and WHOIS_ENDPOINT:
            try:
                # Make request to WHOIS API
                # WhoisXML API uses different format - no headers needed, API key as parameter
                params = {
                    'apiKey': WHOIS_API_KEY,
                    'domainName': domain,
                    'outputFormat': 'JSON'
                }

                response = requests.get(WHOIS_ENDPOINT, params=params, timeout=10)

                if response.status_code == 200:
                    whois_data = response.json()

                    # Extract relevant WHOIS information from WhoisXML API response
                    whois_record = whois_data.get('WhoisRecord', {})
                    registry_data = whois_record.get('registryData', {})

                    # Extract dates from registryData first, then fallback to top-level
                    creation_date = (registry_data.get('createdDate', '') or
                                   registry_data.get('createdDateNormalized', '') or
                                   whois_record.get('creationDate', '') or
                                   whois_record.get('createdDate', ''))

                    expires_date = (registry_data.get('expiresDate', '') or
                                  registry_data.get('expiresDateNormalized', '') or
                                  whois_record.get('expiresDate', '') or
                                  whois_record.get('expirationDate', ''))

                    # Extract registrar information
                    registrar = (whois_record.get('registrarName', '') or
                                registry_data.get('registrarName', '') or
                                (whois_record.get('registrar', {}).get('name', '') if isinstance(whois_record.get('registrar'), dict) else '') or
                                str(whois_record.get('registrar', '')) if whois_record.get('registrar') else '')

                    # Extract registrant organization from registryData
                    registrant_org = ''
                    registrant = registry_data.get('registrant', {})
                    if isinstance(registrant, dict):
                        registrant_org = (registrant.get('organization', '') or
                                        registrant.get('org', '') or
                                        registrant.get('organizationName', ''))
                    else:
                        registrant_org = str(registrant) if registrant else ''

                    # Fallback to top-level registrant if not found in registryData
                    if not registrant_org:
                        top_registrant = whois_record.get('registrant', {})
                        if isinstance(top_registrant, dict):
                            registrant_org = (top_registrant.get('organization', '') or
                                            top_registrant.get('org', '') or
                                            top_registrant.get('organizationName', ''))
                        else:
                            registrant_org = str(top_registrant) if top_registrant else ''

                    whois_details = {
                        'domain_name': domain,
                        'created_date': format_date(creation_date) if creation_date else 'N/A',
                        'expires_date': format_date(expires_date) if expires_date else 'N/A',
                        'registrar': registrar if registrar else 'N/A',
                        'registrant_org': registrant_org if registrant_org else 'Privacy Protected'
                    }

                    # Handle privacy protection
                    if not whois_details['registrant_org'] or whois_details['registrant_org'].lower() in ['whois privacy', 'privacy protection', 'redacted']:
                        whois_details['registrant_org'] = 'Privacy Protected'

                else:
                    # Fallback WHOIS data if API fails
                    whois_details = {
                        'domain_name': domain,
                        'created_date': 'N/A',
                        'expires_date': 'N/A',
                        'registrar': 'N/A',
                        'registrant_org': 'Privacy Protected'
                    }

            except Exception as e:
                print(f"WHOIS API error: {str(e)}")
                # Fallback WHOIS data
                whois_details = {
                    'domain_name': domain,
                    'created_date': 'N/A',
                    'expires_date': 'N/A',
                    'registrar': 'N/A',
                    'registrant_org': 'Privacy Protected'
                }
        else:
            # Fallback WHOIS data when API credentials not available
            whois_details = {
                'domain_name': domain,
                'created_date': 'N/A',
                'expires_date': 'N/A',
                'registrar': 'N/A',
                'registrant_org': 'Privacy Protected'
            }

        # Generate screenshot URL
        screenshot_url = generate_screenshot_url(url)

        # Return combined response
        response_data = {
            'model_result': model_result,
            'whois_details': whois_details,
            'screenshot_url': screenshot_url
        }

        return jsonify(response_data)

    except Exception as e:
        return jsonify({'error': f'Analysis failed: {str(e)}'}), 500

@app.route('/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    return jsonify({'status': 'healthy', 'message': 'Phishing Detection API is running'})

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
