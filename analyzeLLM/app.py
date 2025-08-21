#!/usr/bin/env python3
"""
Shield4U LLM Analysis Service
Flask REST API service for AI-powered vulnerability analysis
"""

import os
import json
import logging
from datetime import datetime
from flask import Flask, request, jsonify
from analyzeLLM import main as analyze_main, findings_to_nuclei_yaml

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
        'service': 'llm-analysis',
        'timestamp': datetime.now().isoformat(),
        'version': '1.0.0'
    })

@app.route('/analyze', methods=['POST'])
def analyze_crawl_result():
    """
    Analyze single crawl result and generate Nuclei YAML templates
    
    Expected JSON payload:
    {
        "task_guid": "uuid-string",
        "parent_guid": "uuid-string",
        "crawl_result": {...}  # Single crawl result object
    }
    
    Returns:
    {
        "success": true,
        "task_guid": "uuid-string",
        "parent_guid": "uuid-string", 
        "analysis": "analysis text",
        "yaml_templates": "nuclei yaml content",
        "templates_count": 5
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
            
        task_guid = data.get('task_guid')
        parent_guid = data.get('parent_guid')
        crawl_result = data.get('crawl_result', {})
        
        if not task_guid or not parent_guid or not crawl_result:
            return jsonify({
                'success': False,
                'error': 'Missing required fields: task_guid, parent_guid, crawl_result'
            }), 400
            
        logger.info(f"Starting analysis for task {task_guid} (parent: {parent_guid})")
        
        # analyzeLLM expects single crawl result as the report object
        target_url = crawl_result.get('url', '')
        
        # Call the main analyzeLLM function
        try:
            # Use crawl_result directly as the report object with additional fields
            report_obj = crawl_result.copy()
            report_obj.update({
                'target_url': target_url,
                'parent_guid': parent_guid
            })
            
            # Run analysis pipeline
            pipeline_result = analyze_main(report_obj=report_obj)
            
            # Generate YAML templates
            yaml_content = findings_to_nuclei_yaml(
                pipeline_result,
                base_id_prefix=f"shield4u-{parent_guid[:8]}",
                author="Shield4U"
            )
            
            analysis_result = pipeline_result.get('summary', 'Analysis completed')
            
            # Count templates in YAML content
            template_count = yaml_content.count('id:') if yaml_content else 0
            
            logger.info(f"Analysis completed for {parent_guid}: {template_count} templates generated")
            
            return jsonify({
                'success': True,
                'task_guid': task_guid,
                'parent_guid': parent_guid,
                'analysis': analysis_result,
                'yaml_templates': yaml_content,
                'templates_count': template_count,
                'timestamp': datetime.now().isoformat()
            })
            
        except Exception as analysis_error:
            logger.error(f"Analysis error for {parent_guid}: {str(analysis_error)}")
            return jsonify({
                'success': False,
                'task_guid': task_guid,
                'parent_guid': parent_guid,
                'error': f'Analysis failed: {str(analysis_error)}'
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
            'service': 'llm-analysis',
            'status': 'running',
            'openai_configured': openai_configured,
            'version': '1.0.0',
            'timestamp': datetime.now().isoformat()
        })
    except Exception as e:
        return jsonify({
            'service': 'llm-analysis',
            'status': 'error',
            'error': str(e),
            'timestamp': datetime.now().isoformat()
        }), 500

if __name__ == '__main__':
    # Configure host and port
    host = os.getenv('FLASK_HOST', '0.0.0.0')
    port = int(os.getenv('FLASK_PORT', 5003))
    debug = os.getenv('FLASK_DEBUG', 'False').lower() == 'true'
    
    logger.info(f"Starting LLM Analysis Service on {host}:{port}")
    logger.info(f"OpenAI configured: {bool(os.getenv('OPENAI_API_KEY'))}")
    
    app.run(
        host=host,
        port=port,
        debug=debug,
        threaded=True
    )