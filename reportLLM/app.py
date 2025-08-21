#!/usr/bin/env python3
"""
Shield4U LLM Report Service
Flask REST API service for AI-powered security report generation
"""

import os
import json
import logging
from datetime import datetime
from flask import Flask, request, jsonify
import requests
from reportLLM import generate_security_report

# Initialize Flask app
app = Flask(__name__)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

@app.route('/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    return jsonify({
        'status': 'healthy',
        'service': 'llm-report',
        'timestamp': datetime.now().isoformat(),
        'version': '1.0.0'
    })

@app.route('/generate-report', methods=['POST'])
def generate_report():
    """
    Generate security report from scan results
    
    Expected JSON payload:
    {
        "parent_guid": "uuid-string",
        "scan_results": [...],  # List of Nuclei scan results
        "crawl_results": [...], # Original crawl results
        "target_url": "https://example.com",
        "analysis_summary": "LLM analysis summary"
    }
    
    Returns:
    {
        "success": true,
        "parent_guid": "uuid-string",
        "report": {
            "executive_summary": "...",
            "technical_details": "...",
            "recommendations": "...",
            "full_report": "..."
        }
    }
    """
    try:
        # Parse request data
        data = request.get_json()
        if not data:
            return jsonify({
                'success': False,
                'error': 'No JSON data provided'
            }), 400
            
        parent_guid = data.get('parent_guid')
        scan_results = data.get('scan_results', [])
        crawl_results = data.get('crawl_results', [])
        target_url = data.get('target_url')
        analysis_summary = data.get('analysis_summary', '')
        
        if not parent_guid:
            return jsonify({
                'success': False,
                'error': 'Missing required field: parent_guid'
            }), 400
            
        logger.info(f"Generating report for {parent_guid} with {len(scan_results)} scan results")
        
        # Prepare input data for report generation
        report_input = {
            'parent_guid': parent_guid,
            'target_url': target_url,
            'scan_results': scan_results,
            'crawl_results': crawl_results,
            'analysis_summary': analysis_summary,
            'scan_timestamp': datetime.now().isoformat()
        }
        
        # Generate the security report
        try:
            report = generate_security_report(report_input)
            
            logger.info(f"Report generated successfully for {parent_guid}")
            
            # Store the report in the database via controller
            report_stored = _store_report_in_database(parent_guid, report, target_url)
            
            if not report_stored:
                logger.warning(f"Failed to store report in database for {parent_guid}")
            
            return jsonify({
                'success': True,
                'parent_guid': parent_guid,
                'report': report,
                'scan_results_count': len(scan_results),
                'crawl_results_count': len(crawl_results),
                'generated_at': datetime.now().isoformat(),
                'report_stored': report_stored
            })
            
        except Exception as report_error:
            logger.error(f"Report generation error for {parent_guid}: {str(report_error)}")
            return jsonify({
                'success': False,
                'parent_guid': parent_guid,
                'error': f'Report generation failed: {str(report_error)}'
            }), 500
            
    except Exception as e:
        logger.error(f"Request processing error: {str(e)}")
        return jsonify({
            'success': False,
            'error': f'Request processing failed: {str(e)}'
        }), 500

@app.route('/status', methods=['GET'])
def service_status():
    """Get service status and configuration"""
    try:
        # Check if OpenAI API key is configured
        openai_configured = bool(os.getenv('OPENAI_API_KEY'))
        
        return jsonify({
            'service': 'llm-report',
            'status': 'running',
            'openai_configured': openai_configured,
            'version': '1.0.0',
            'timestamp': datetime.now().isoformat()
        })
    except Exception as e:
        return jsonify({
            'service': 'llm-report',
            'status': 'error',
            'error': str(e),
            'timestamp': datetime.now().isoformat()
        }), 500

def _store_report_in_database(parent_guid, report, target_url):
    """Store the generated report in the database via controller"""
    try:
        controller_url = os.getenv('CONTROLLER_URL', 'http://controller:5000')
        
        # Prepare report data for storage
        report_data = {
            'parent_guid': parent_guid,
            'title': f'Security Assessment Report - {target_url}',
            'executive_summary': report.get('executive_summary', ''),
            'vulnerability_summary': report.get('vulnerability_summary', {}),
            'detailed_findings': report.get('detailed_findings', []),
            'recommendations': report.get('recommendations', []),
            'scan_metadata': {
                'target_url': target_url,
                'generated_at': datetime.now().isoformat(),
                'report_content': report
            }
        }
        
        response = requests.post(
            f"{controller_url}/api/v1/internal/reports/store",
            json=report_data,
            timeout=30
        )
        
        if response.status_code == 200:
            logger.info(f"Successfully stored report in database for {parent_guid}")
            return True
        else:
            logger.error(f"Failed to store report: HTTP {response.status_code}")
            return False
            
    except Exception as e:
        logger.error(f"Error storing report in database: {str(e)}")
        return False

if __name__ == '__main__':
    # Configure host and port
    host = os.getenv('FLASK_HOST', '0.0.0.0')
    port = int(os.getenv('FLASK_PORT', 5004))
    debug = os.getenv('FLASK_DEBUG', 'False').lower() == 'true'
    
    logger.info(f"Starting LLM Report Service on {host}:{port}")
    logger.info(f"OpenAI configured: {bool(os.getenv('OPENAI_API_KEY'))}")
    
    app.run(
        host=host,
        port=port,
        debug=debug,
        threaded=True
    )