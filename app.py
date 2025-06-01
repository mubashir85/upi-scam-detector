import os
import logging
from flask import Flask, request, jsonify, render_template
from flask_cors import CORS
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import DeclarativeBase
from werkzeug.middleware.proxy_fix import ProxyFix
from scam_detector import ScamDetector

# Configure logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

class Base(DeclarativeBase):
    pass

db = SQLAlchemy(model_class=Base)

# Create Flask app
app = Flask(__name__)
app.secret_key = os.environ.get("SESSION_SECRET", "dev-secret-key-change-in-production")
app.wsgi_app = ProxyFix(app.wsgi_app, x_proto=1, x_host=1)

# Configure the database
app.config["SQLALCHEMY_DATABASE_URI"] = os.environ.get("DATABASE_URL")
app.config["SQLALCHEMY_ENGINE_OPTIONS"] = {
    "pool_recycle": 300,
    "pool_pre_ping": True,
}

# Initialize the app with the extension
db.init_app(app)

# Enable CORS for all routes
CORS(app)

# Initialize scam detector
scam_detector = ScamDetector()

with app.app_context():
    # Import models here to ensure they are registered
    from models import ScamCheck, ScamPattern, Analytics
    # Create all database tables
    db.create_all()
    logger.info("Database tables created successfully")

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
        
        # Store the result in database
        try:
            from models import ScamCheck
            scam_check = ScamCheck(
                message_text=transaction_text,
                is_scam=result['is_scam'],
                confidence_score=result['confidence_score'],
                matched_keywords=result['matched_keywords'],
                matched_patterns=result['matched_patterns'],
                categories=result['categories'],
                ip_address=request.remote_addr,
                user_agent=request.headers.get('User-Agent')
            )
            db.session.add(scam_check)
            db.session.commit()
            logger.info(f"Saved scam check result with ID: {scam_check.id}")
        except Exception as e:
            logger.error(f"Failed to save to database: {str(e)}")
            # Continue without failing the request
        
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

@app.route('/analytics', methods=['GET'])
def get_analytics():
    """Get analytics about scam checks"""
    try:
        from models import ScamCheck
        from sqlalchemy import func
        
        # Get total checks
        total_checks = db.session.query(func.count(ScamCheck.id)).scalar()
        
        # Get scam count
        scam_count = db.session.query(func.count(ScamCheck.id)).filter(ScamCheck.is_scam == True).scalar()
        
        # Get average confidence score
        avg_confidence = db.session.query(func.avg(ScamCheck.confidence_score)).scalar()
        
        # Get top categories
        from sqlalchemy import text
        category_query = text("""
            SELECT category, COUNT(*) as count 
            FROM (
                SELECT jsonb_array_elements_text(categories) as category
                FROM scam_check 
                WHERE is_scam = true AND categories IS NOT NULL
            ) t
            GROUP BY category 
            ORDER BY count DESC 
            LIMIT 5
        """)
        
        top_categories = []
        try:
            result = db.session.execute(category_query)
            top_categories = [{"category": row[0], "count": row[1]} for row in result]
        except Exception as e:
            logger.warning(f"Could not fetch category analytics: {e}")
        
        return jsonify({
            "total_checks": total_checks or 0,
            "scam_detected": scam_count or 0,
            "scam_percentage": round((scam_count / total_checks * 100), 2) if total_checks > 0 else 0,
            "avg_confidence_score": round(float(avg_confidence), 3) if avg_confidence else 0,
            "top_categories": top_categories
        }), 200
        
    except Exception as e:
        logger.error(f"Error retrieving analytics: {str(e)}")
        return jsonify({
            "error": "Internal server error"
        }), 500

@app.route('/history', methods=['GET'])
def get_history():
    """Get recent scam check history"""
    try:
        from models import ScamCheck
        
        # Get limit from query params (default 10, max 100)
        limit = min(int(request.args.get('limit', 10)), 100)
        
        # Get recent checks
        checks = db.session.query(ScamCheck)\
            .order_by(ScamCheck.created_at.desc())\
            .limit(limit)\
            .all()
        
        return jsonify({
            "history": [check.to_dict() for check in checks],
            "count": len(checks)
        }), 200
        
    except Exception as e:
        logger.error(f"Error retrieving history: {str(e)}")
        return jsonify({
            "error": "Internal server error"
        }), 500

@app.route('/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    try:
        # Test database connection
        from sqlalchemy import text
        db.session.execute(text("SELECT 1"))
        db_status = "connected"
    except Exception as e:
        logger.error(f"Database connection failed: {e}")
        db_status = "disconnected"
    
    return jsonify({
        "status": "healthy",
        "service": "UPI Scam Detector API",
        "database": db_status
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
