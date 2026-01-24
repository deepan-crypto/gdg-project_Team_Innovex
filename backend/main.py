from fastapi import FastAPI, HTTPException, WebSocket, UploadFile, File
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from datetime import datetime
import json
import os
import asyncio
import tempfile
import shutil
from pathlib import Path
from dotenv import load_dotenv
from services.github_service import GitHubService
from services.report_generator import ReportGenerator
from services.model_analyzer import ModelAnalyzer
from scanners.prompt_injection import PromptInjectionScanner
from scanners.secrets_scanner import SecretsScanner
from scanners.sql_xss_scanner import SQLXSSScanner
from scanners.dependency_scanner import DependencyScanner
from routes.ml_security import router as ml_router
from routes.garak_security import router as garak_router

# Load environment variables
load_dotenv()

# Environment configuration
ENVIRONMENT = os.getenv("ENVIRONMENT", "development")
FRONTEND_URL = os.getenv("FRONTEND_URL", "http://localhost:5173")
PORT = int(os.getenv("PORT", 8000))

app = FastAPI(
    title="Security Scanning Platform",
    docs_url="/docs" if ENVIRONMENT == "development" else None,
    redoc_url="/redoc" if ENVIRONMENT == "development" else None,
)

# Configure CORS for production
allowed_origins = [
    "http://localhost:3000",
    "http://localhost:5173",
]

# Add frontend URL from environment
if FRONTEND_URL:
    allowed_origins.append(FRONTEND_URL)

# In production, you might want to be more restrictive
if ENVIRONMENT == "production":
    # Add your production frontend URLs here
    production_origins = os.getenv("ALLOWED_ORIGINS", "").split(",")
    allowed_origins.extend([origin.strip() for origin in production_origins if origin.strip()])

app.add_middleware(
    CORSMiddleware,
    allow_origins=allowed_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.get("/")
async def root():
    """Root endpoint - API info"""
    return {
        "name": "Security Scanning Platform API",
        "version": "1.0.0",
        "status": "running",
        "docs": "/docs" if ENVIRONMENT == "development" else "Disabled in production",
        "endpoints": {
            "health": "/health",
            "scan": "/scan",
            "upload_model": "/upload-model",
            "websocket": "/ws/scan"
        }
    }

class ScanRequest(BaseModel):
    repo_url: str
    github_token: str = None

class ScanResponse(BaseModel):
    scan_id: str
    repo_url: str
    timestamp: str
    results: dict
    report_path: str

class ModelUploadResponse(BaseModel):
    model_id: str
    model_type: str
    framework: str
    is_safe: bool
    metadata: dict
    message: str
    scan_eligibility: bool

# Store active scans for WebSocket
active_scans = {}

@app.post("/scan")
async def scan_repository(request: ScanRequest):
    """
    Scan a GitHub repository for security vulnerabilities.
    """
    try:
        github_service = GitHubService(request.github_token)
        repo_data = github_service.fetch_repo(request.repo_url)
        
        if not repo_data:
            raise HTTPException(status_code=400, detail="Failed to fetch repository")
        
        # Run all scanners
        results = {
            "prompt_injection": PromptInjectionScanner.scan(repo_data),
            "secrets": SecretsScanner.scan(repo_data),
            "sql_xss": SQLXSSScanner.scan(repo_data),
            "dependencies": DependencyScanner.scan(repo_data)
        }
        
        report_generator = ReportGenerator()
        scan_id, report_path = report_generator.generate(request.repo_url, results)
        
        return ScanResponse(
            scan_id=scan_id,
            repo_url=request.repo_url,
            timestamp=datetime.now().isoformat(),
            results=results,
            report_path=report_path
        )
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.websocket("/ws/scan")
async def websocket_scan(websocket: WebSocket):
    """WebSocket endpoint for real-time scan updates"""
    await websocket.accept()
    try:
        while True:
            data = await websocket.receive_json()
            
            if data.get("action") == "start_scan":
                repo_url = data.get("repo_url")
                github_token = data.get("github_token")
                
                await websocket.send_json({"status": "Connecting to GitHub...", "progress": 10})
                
                try:
                    github_service = GitHubService(github_token)
                    
                    await websocket.send_json({"status": "Fetching repository...", "progress": 20})
                    repo_data = github_service.fetch_repo(repo_url)
                    
                    if not repo_data:
                        await websocket.send_json({"error": "Failed to fetch repository. Check if the URL is correct and the repository is accessible."})
                        continue
                    
                    # Log files fetched for debugging
                    files_count = len(repo_data.get("files", {}))
                    print(f"Fetched {files_count} files from repository")
                    
                    if files_count == 0:
                        await websocket.send_json({"error": "No files fetched from repository. Check repository access permissions."})
                        continue
                    
                    # Run scanners with progress updates
                    await websocket.send_json({"status": f"Scanning {files_count} files for prompt injection...", "progress": 30})
                    prompt_injection = PromptInjectionScanner.scan(repo_data)
                    print(f"Prompt injection scan found {prompt_injection.get('count', 0)} issues")
                    
                    await websocket.send_json({"status": "Scanning for secrets...", "progress": 50})
                    secrets = SecretsScanner.scan(repo_data)
                    print(f"Secrets scan found {secrets.get('count', 0)} issues")
                    
                    await websocket.send_json({"status": "Scanning for SQL/XSS...", "progress": 70})
                    sql_xss = SQLXSSScanner.scan(repo_data)
                    print(f"SQL/XSS scan found {sql_xss.get('count', 0)} issues")
                    
                    await websocket.send_json({"status": "Scanning dependencies...", "progress": 85})
                    dependencies = DependencyScanner.scan(repo_data)
                    print(f"Dependency scan found {dependencies.get('count', 0)} issues")
                    
                    results = {
                        "prompt_injection": prompt_injection,
                        "secrets": secrets,
                        "sql_xss": sql_xss,
                        "dependencies": dependencies
                    }
                    
                    await websocket.send_json({"status": "Generating report...", "progress": 95})
                    
                    report_generator = ReportGenerator()
                    scan_id, report_path = report_generator.generate(repo_url, results)
                    
                    await websocket.send_json({
                        "status": "Scan complete!",
                        "progress": 100,
                        "scan_id": scan_id,
                        "results": results,
                        "timestamp": datetime.now().isoformat()
                    })
                
                except Exception as e:
                    try:
                        await websocket.send_json({"error": str(e)})
                    except:
                        pass
    
    except Exception as e:
        print(f"WebSocket error: {e}")
    finally:
        try:
            await websocket.close()
        except RuntimeError:
            # Connection already closed
            pass

@app.post("/upload-model", response_model=ModelUploadResponse)
async def upload_model(file: UploadFile = File(...)):
    """
    Upload and analyze ML model files.
    
    Features:
    - Automatic framework detection (PyTorch, TensorFlow, ONNX, etc.)
    - Static inspection (NO execution)
    - Metadata extraction (layers, shapes, parameters)
    - Malicious code detection
    - Safe sandbox for scanning
    """
    try:
        # Validate file
        if not file.filename:
            raise HTTPException(status_code=400, detail="No file provided")
        
        # Create temp directory for this upload
        temp_dir = tempfile.mkdtemp(prefix="model_upload_")
        temp_file_path = os.path.join(temp_dir, file.filename)
        
        try:
            # Save uploaded file
            with open(temp_file_path, "wb") as f:
                contents = await file.read()
                f.write(contents)
            
            # Analyze model
            analyzer = ModelAnalyzer()
            analysis = analyzer.analyze(temp_file_path)
            
            model_id = analysis["model_id"]
            
            return ModelUploadResponse(
                model_id=model_id,
                model_type=analysis["model_type"],
                framework=analysis["framework"],
                is_safe=analysis["is_safe"],
                metadata=analysis["metadata"],
                message=analysis["message"],
                scan_eligibility=analysis["scan_eligible"]
            )
        
        finally:
            # Clean up temp directory
            if os.path.exists(temp_dir):
                shutil.rmtree(temp_dir)
    
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Model analysis failed: {str(e)}")

@app.get("/health")
async def health_check():
    """Health check endpoint"""
    return {"status": "healthy"}

@app.get("/scan/{scan_id}")
async def get_scan_report(scan_id: str):
    """Retrieve a previous scan report"""
    try:
        report_path = f"./scan_reports/{scan_id}.json"
        if os.path.exists(report_path):
            with open(report_path) as f:
                return json.load(f)
        raise HTTPException(status_code=404, detail="Scan report not found")
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

app.include_router(ml_router)
app.include_router(garak_router)

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=PORT,
        reload=ENVIRONMENT == "development"
    )
