# UPI Scam Detector

A simple Flask-based web application that detects scam patterns in UPI transaction messages. The app analyzes text messages and alerts users about potential scams using keyword matching.

## Features

- **Real-time Scam Detection**: Identifies suspicious keywords and phrases
- **Multiple Scam Categories**: Detects KYC scams, fake prizes, job offers, phishing attempts
- **Confidence Scoring**: Provides confidence levels for detections
- **User-friendly Interface**: Clean web interface for easy testing
- **Database Storage**: Stores all checks and provides analytics
- **REST API**: JSON API for integration with other applications

## Tech Stack

- **Backend**: Python, Flask, PostgreSQL
- **Frontend**: HTML, CSS, JavaScript, Bootstrap
- **Detection**: Regex pattern matching
- **Database**: PostgreSQL with SQLAlchemy

## Quick Start

### Prerequisites

- Python 3.11 or higher
- PostgreSQL database (automatically configured in Replit)

### Installation & Setup

1. **Install dependencies:**
   ```bash
   pip install flask flask-cors flask-sqlalchemy gunicorn psycopg2-binary
   ```

2. **Run the application:**
   ```bash
   python main.py
   ```
   
   Or using Gunicorn:
   ```bash
   gunicorn --bind 0.0.0.0:5000 --reload main:app
   ```

3. **Open the application:**
   - Navigate to `http://localhost:5000` in your browser
   - The web interface will load automatically

## How to Use

### Web Interface
1. Enter a UPI message in the text area
2. Click "Check for Scams" to analyze the message
3. View results showing scam detection status and confidence score
4. Try the sample messages provided for quick testing

### API Usage
Send POST requests to `/check` endpoint:

```bash
curl -X POST http://localhost:5000/check \
  -H "Content-Type: application/json" \
  -d '{"text": "Urgent KYC update required! Verify now."}'
```

Response:
```json
{
  "is_scam": true,
  "matched_keywords": ["urgent kyc", "verify now"],
  "confidence_score": 0.8,
  "categories": ["kyc_scams", "phishing_scams"]
}
```

## Sample Test Messages

**Scam Messages (will be detected):**
- "Urgent KYC update required! Your account will be blocked."
- "Congratulations! You won 50 lakh rupees. Claim your prize now!"
- "Work from home job offer! Earn 5000 per day. No investment required."

**Safe Messages (will not be detected):**
- "Your UPI transaction of Rs.500 to John Doe is successful."
- "Payment received from ABC Company for invoice #INV001."

## API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/check` | POST | Check a message for scam patterns |
| `/analytics` | GET | Get detection statistics |
| `/history` | GET | Get recent check history |
| `/patterns` | GET | Get all scam patterns |
| `/health` | GET | Health check with database status |

## Project Structure

```
├── main.py           # Application entry point
├── app.py            # Flask application and routes
├── scam_detector.py  # Scam detection logic
├── models.py         # Database models
├── templates/
│   └── index.html    # Web interface
├── static/
│   ├── script.js     # Frontend JavaScript
│   └── style.css     # Custom styles
└── README.md         # This file
```

## Detection Categories

The app detects 8 types of scams:
- **KYC Scams**: "urgent kyc", "account blocked"
- **Prize Scams**: "won prize", "congratulations"
- **Job Scams**: "work from home", "easy money"
- **Investment Scams**: "double money", "guaranteed profit"
- **Phishing**: "verify now", "click here"
- **Urgency Tactics**: "limited time", "expires today"
- **Fake Payments**: "money credited", "refund processed"
- **Suspicious Requests**: "share otp", "send money"

## Database Features

- Automatic storage of all scam checks
- Analytics dashboard showing detection patterns
- History tracking with IP addresses and timestamps
- Category-wise scam statistics

## Contributing

1. Fork the repository
2. Add new scam patterns to `scam_detector.py`
3. Test thoroughly with various message types
4. Submit a pull request

## License

This project is open source and available under the MIT License.

---

**Note**: This tool is designed to help identify potential scams but should not be the only method used for security. Always verify suspicious messages through official channels.