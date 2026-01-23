# How to Run the AI Security Scanner

## Prerequisites

1. **Python 3.8+** - For the backend
2. **Node.js 18+** - For the frontend
3. **Git** - For cloning repositories to scan

## Backend Setup

```bash
cd backend

# Create virtual environment (optional but recommended)
python -m venv venv
.\venv\Scripts\activate  # Windows
# source venv/bin/activate  # Linux/Mac

# Install dependencies
pip install -r requirements.txt

# Run the backend server
uvicorn main:app --reload --port 8000
```

The backend will be available at: http://localhost:8000

API Documentation: http://localhost:8000/docs

## Frontend Setup

```bash
cd frontend

# Install dependencies
npm install

# Run the development server
npm run dev
```

The frontend will be available at: http://localhost:5173

## Using the Application

1. Open http://localhost:5173 in your browser
2. Click "Start Scanning"
3. Enter a GitHub repository URL (e.g., `https://github.com/owner/repo`)
4. Optionally add a GitHub token for private repos
5. Click "Scan Repository"
6. View the security scan results

## Available API Endpoints

### Basic Scanning
- `POST /scan` - Scan a repository
- `GET /health` - Health check
- `WS /ws/scan` - WebSocket for real-time scan progress

### Garak LLM Security (new!)
- `POST /api/v1/garak/scan/comprehensive` - Full LLM security scan
- `POST /api/v1/garak/analyze/prompt` - Analyze prompts for attacks
- `POST /api/v1/garak/analyze/response` - Analyze LLM responses
- `POST /api/v1/garak/scan/jailbreak` - Scan for jailbreak patterns
- `POST /api/v1/garak/scan/encoding` - Scan for encoding attacks
- `POST /api/v1/garak/scan/latent` - Scan for latent injections
- `POST /api/v1/garak/scan/malware` - Scan for malware patterns
- `GET /api/v1/garak/payloads` - Get attack payloads for testing
- `GET /api/v1/garak/health` - Garak service health

### ML Security
- `POST /api/v1/scan/serialization` - Scan for unsafe serialization
- `POST /api/v1/scan/backdoor` - Detect model backdoors
- `POST /api/v1/scan/extraction` - Check extraction risk
- `GET /api/v1/explain/{type}` - Get vulnerability explanations

## Environment Variables

### Backend (.env)
```
GITHUB_TOKEN=your_github_token  # Optional, for private repos
GEMINI_API_KEY=your_gemini_key  # Optional, for AI explanations
```

### Frontend (.env)
```
VITE_API_URL=  # Leave empty for Vite proxy (dev), or set backend URL for production
VITE_WS_URL=   # Leave empty for auto-detect
```

## Tech Stack

- **Backend**: FastAPI, Python
- **Frontend**: React, TypeScript, Vite, Tailwind CSS
- **Security**: Garak LLM vulnerability scanning, ML security analysis
