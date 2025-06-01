import os
import logging
from flask import Flask, request, jsonify, render_template
from flask_cors import CORS
from scam_detector import ScamDetector

# Configure logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

# Create Flask app
app = Flask(__name__)
app.secret_key = os.environ.get("SESSION_SECRET", "dev-secret-key-change-in-production")

# Enable CORS for all routes
CORS(app)

# Initialize scam detector
scam_detector = ScamDetector()

@app.route('/')
def index():
    """Serve the main page with API testing interface"""
    return render_template('index.html')

@app.route('/check', methods=['POST'])
def check_scam():
    """
    Check if a UPI transaction message contains scam patterns
    
    Expected JSON payload:
    {
        "text": "Your transaction text here"
    }
    
    Returns:
    {
        "is_scam": true/false,
        "matched_keywords": ["keyword1", "keyword2"],
        "matched_patterns": ["pattern1", "pattern2"],
        "confidence_score": 0.0-1.0,
        "text": "original text"
    }
    """
    try:
        # Validate request content type
        if not request.is_json:
            logger.warning("Request received without JSON content type")
            return jsonify({
                "error": "Content-Type must be application/json",
                "is_scam": False
            }), 400
        
        # Get JSON data
        data = request.get_json()
        
        # Validate required fields
        if not data or 'text' not in data:
            logger.warning("Request missing required 'text' field")
            return jsonify({
                "error": "Missing required field 'text'",
                "is_scam": False
            }), 400
        
        transaction_text = data['text']
        
        # Validate text input
        if not isinstance(transaction_text, str):
            logger.warning("Text field is not a string")
            return jsonify({
                "error": "Field 'text' must be a string",
                "is_scam": False
            }), 400
        
        if len(transaction_text.strip()) == 0:
            logger.warning("Empty text provided")
            return jsonify({
                "error": "Text cannot be empty",
                "is_scam": False
            }), 400
        
        if len(transaction_text) > 10000:  # Reasonable limit
            logger.warning("Text too long")
            return jsonify({
                "error": "Text too long (max 10000 characters)",
                "is_scam": False
            }), 400
        
        # Log the check request
        logger.info(f"Checking text for scam patterns: {transaction_text[:100]}...")
        
        # Perform scam detection
        result = scam_detector.check_text(transaction_text)
        
        # Log the result
        if result['is_scam']:
            logger.warning(f"Scam detected! Matched patterns: {result['matched_patterns']}")
        else:
            logger.info("No scam patterns detected")
        
        return jsonify(result), 200
        
    except Exception as e:
        logger.error(f"Error processing request: {str(e)}")
        return jsonify({
            "error": "Internal server error",
            "is_scam": False
        }), 500

@app.route('/patterns', methods=['GET'])
def get_patterns():
    """Get list of all scam patterns for debugging/monitoring"""
    try:
        patterns = scam_detector.get_all_patterns()
        return jsonify({
            "patterns": patterns,
            "total_count": len(patterns)
        }), 200
    except Exception as e:
        logger.error(f"Error retrieving patterns: {str(e)}")
        return jsonify({
            "error": "Internal server error"
        }), 500

@app.route('/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    return jsonify({
        "status": "healthy",
        "service": "UPI Scam Detector API"
    }), 200

@app.errorhandler(404)
def not_found(error):
    """Handle 404 errors"""
    return jsonify({
        "error": "Endpoint not found"
    }), 404

@app.errorhandler(405)
def method_not_allowed(error):
    """Handle 405 errors"""
    return jsonify({
        "error": "Method not allowed"
    }), 405

if __name__ == '__main__':
    logger.info("Starting UPI Scam Detector API on port 5000")
    app.run(host='0.0.0.0', port=5000, debug=True)
