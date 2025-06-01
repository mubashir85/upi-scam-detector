# UPI Scam Detector API

A Flask-based REST API that detects scam patterns in UPI transaction messages using advanced keyword and pattern matching. The application includes both a REST API backend and a web interface for easy testing.

## Features

- **Scam Detection**: Identifies common scam patterns in UPI messages
- **Multiple Categories**: Detects 8 different types of scams including:
  - KYC verification scams
  - Prize and lottery scams
  - Job offer scams
  - Investment and trading scams
  - Phishing attempts
  - Urgency tactics
  - Fake payment notifications
  - Suspicious requests
- **Confidence Scoring**: Provides confidence scores for detections
- **Web Interface**: User-friendly testing interface
- **REST API**: Clean JSON API for integration
- **Database Storage**: PostgreSQL database for storing results and analytics
- **Analytics**: Real-time analytics on scam detection patterns

## Quick Start

### Running the Application

1. **Start the server:**
   ```bash
   python main.py
   ```
   Or use the provided workflow:
   ```bash
   gunicorn --bind 0.0.0.0:5000 --reuse-port --reload main:app
   ```

2. **Access the application:**
   - Web Interface: `http://localhost:5000`
   - API Endpoint: `http://localhost:5000/check`

### Testing the Application

#### Using the Web Interface

1. Open `http://localhost:5000` in your browser
2. Enter a UPI message in the text area
3. Click "Check for Scams" to analyze the message
4. View detailed results including:
   - Scam detection status
   - Confidence score
   - Matched keywords
   - Scam categories
   - Technical pattern details

#### Sample Messages for Testing

**Scam Messages (should be detected):**
- `"Urgent KYC update required! Your account will be blocked. Verify now: link.com"`
- `"Congratulations! You won 50 lakh rupees in our lucky draw. Claim your prize now!"`
- `"Work from home job offer! Earn 5000 per day. No investment required. Easy money guaranteed!"`

**Legitimate Messages (should be safe):**
- `"Your UPI transaction of Rs.500 to John Doe is successful. Transaction ID: 123456789"`
- `"Payment received from ABC Company for invoice #INV001. Amount: Rs.10,000"`
- `"Monthly salary credited to your account. Amount: Rs.25,000"`

## API Reference

### POST /check

Check a UPI message for scam patterns.

**Request:**
```json
{
  "text": "Your UPI transaction message here"
}
```

**Response:**
```json
{
  "is_scam": true,
  "matched_keywords": ["urgent kyc", "verify now"],
  "matched_patterns": ["\\burgent\\s+kyc\\b", "\\bverify\\s+now\\b"],
  "confidence_score": 0.8,
  "text": "original message text",
  "categories": ["kyc_scams", "phishing_scams"]
}
```

### GET /patterns

Get all available scam patterns for debugging.

**Response:**
```json
{
  "patterns": {
    "kyc_scams": ["pattern1", "pattern2"],
    "prize_scams": ["pattern3", "pattern4"]
  },
  "total_count": 50
}
```

### GET /analytics

Get analytics about scam detection patterns.

**Response:**
```json
{
  "total_checks": 150,
  "scam_detected": 45,
  "scam_percentage": 30.0,
  "avg_confidence_score": 0.75,
  "top_categories": [
    {"category": "kyc_scams", "count": 15},
    {"category": "prize_scams", "count": 12}
  ]
}
```

### GET /history

Get recent scam check history (supports `?limit=N` parameter).

**Response:**
```json
{
  "history": [
    {
      "id": 1,
      "message_text": "Urgent KYC update required",
      "is_scam": true,
      "confidence_score": 0.8,
      "categories": ["kyc_scams"],
      "created_at": "2024-01-01T12:00:00"
    }
  ],
  "count": 1
}
```

### GET /health

Health check endpoint with database status.

**Response:**
```json
{
  "status": "healthy",
  "service": "UPI Scam Detector API",
  "database": "connected"
}
```

## Testing with cURL

### Check a message for scams:
```bash
curl -X POST http://localhost:5000/check \
  -H "Content-Type: application/json" \
  -d '{"text": "Urgent KYC update required! Verify now."}'
```

### Get all patterns:
```bash
curl http://localhost:5000/patterns
```

### Health check:
```bash
curl http://localhost:5000/health
```

## Project Structure

```
├── app.py              # Main Flask application
├── main.py             # Application entry point
├── scam_detector.py    # Scam detection logic
├── templates/
│   └── index.html      # Web interface
├── static/
│   ├── script.js       # Frontend JavaScript
│   └── style.css       # Custom styles
└── README.md           # This file
```

## Dependencies

- Flask - Web framework
- Flask-CORS - Cross-origin resource sharing
- Gunicorn - WSGI HTTP server
- Python 3.11+

## How It Works

1. **Pattern Matching**: Uses regex patterns to identify scam keywords and phrases
2. **Categorization**: Groups patterns into different scam types
3. **Confidence Scoring**: Calculates confidence based on:
   - Number of patterns matched
   - Number of categories involved
   - Message length
4. **Real-time Analysis**: Processes messages instantly via API

## Error Handling

The API includes comprehensive error handling:
- Invalid JSON requests
- Missing required fields
- Empty messages
- Server errors

All errors return appropriate HTTP status codes and descriptive error messages.

## Security Features

- Input validation and sanitization
- Request size limits
- Content-type validation
- Error message sanitization

## Future Enhancements

- Machine learning-based detection
- Real-time pattern updates
- User feedback integration
- Batch processing capabilities
- Custom pattern addition via API

## Contributing

1. Fork the repository
2. Create a feature branch
3. Add your improvements
4. Test thoroughly
5. Submit a pull request

## License

This project is open source and available under the MIT License.