from datetime import datetime
from sqlalchemy import func
from flask_sqlalchemy import SQLAlchemy

# Import the db instance from app
from app import db

class ScamCheck(db.Model):
    """Model to store scam check results"""
    id = db.Column(db.Integer, primary_key=True)
    message_text = db.Column(db.Text, nullable=False)
    is_scam = db.Column(db.Boolean, nullable=False)
    confidence_score = db.Column(db.Float, nullable=False)
    matched_keywords = db.Column(db.JSON)  # Store as JSON array
    matched_patterns = db.Column(db.JSON)  # Store as JSON array
    categories = db.Column(db.JSON)  # Store as JSON array
    ip_address = db.Column(db.String(45))  # IPv6 compatible
    user_agent = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    
    def __repr__(self):
        return f'<ScamCheck {self.id}: {"SCAM" if self.is_scam else "SAFE"}>'
    
    def to_dict(self):
        """Convert to dictionary for JSON serialization"""
        return {
            'id': self.id,
            'message_text': self.message_text,
            'is_scam': self.is_scam,
            'confidence_score': self.confidence_score,
            'matched_keywords': self.matched_keywords or [],
            'matched_patterns': self.matched_patterns or [],
            'categories': self.categories or [],
            'ip_address': self.ip_address,
            'user_agent': self.user_agent,
            'created_at': self.created_at.isoformat() if self.created_at else None
        }

class ScamPattern(db.Model):
    """Model to store scam patterns for dynamic management"""
    id = db.Column(db.Integer, primary_key=True)
    category = db.Column(db.String(100), nullable=False)
    pattern = db.Column(db.Text, nullable=False)
    description = db.Column(db.Text)
    is_active = db.Column(db.Boolean, default=True, nullable=False)
    created_by = db.Column(db.String(100))  # For future user management
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Add indexes for better query performance
    __table_args__ = (
        db.Index('idx_category_active', 'category', 'is_active'),
    )
    
    def __repr__(self):
        return f'<ScamPattern {self.id}: {self.category}>'
    
    def to_dict(self):
        """Convert to dictionary for JSON serialization"""
        return {
            'id': self.id,
            'category': self.category,
            'pattern': self.pattern,
            'description': self.description,
            'is_active': self.is_active,
            'created_by': self.created_by,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None
        }

class Analytics(db.Model):
    """Model to store analytics data"""
    id = db.Column(db.Integer, primary_key=True)
    date = db.Column(db.Date, nullable=False)
    total_checks = db.Column(db.Integer, default=0)
    scam_detected = db.Column(db.Integer, default=0)
    avg_confidence_score = db.Column(db.Float, default=0.0)
    top_categories = db.Column(db.JSON)  # Store top categories as JSON
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Unique constraint on date to prevent duplicates
    __table_args__ = (
        db.UniqueConstraint('date', name='uq_analytics_date'),
    )
    
    def __repr__(self):
        return f'<Analytics {self.date}: {self.total_checks} checks>'
    
    def to_dict(self):
        """Convert to dictionary for JSON serialization"""
        return {
            'id': self.id,
            'date': self.date.isoformat() if self.date else None,
            'total_checks': self.total_checks,
            'scam_detected': self.scam_detected,
            'scam_percentage': round((self.scam_detected / self.total_checks * 100), 2) if self.total_checks > 0 else 0,
            'avg_confidence_score': round(self.avg_confidence_score, 3) if self.avg_confidence_score else 0,
            'top_categories': self.top_categories or [],
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None
        }