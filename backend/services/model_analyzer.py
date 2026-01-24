import os
import pickle
import struct
import json
import uuid
import zipfile
import io
from pathlib import Path
from typing import Dict, Any, Tuple

class ModelAnalyzer:
    """
    Analyze ML model files safely without execution.
    
    SECURITY FOCUS:
    - No pickle.load() - pickle can execute arbitrary code!
    - Static inspection only
    - Detect malicious pickle instructions
    - Framework auto-detection
    - Extract metadata safely
    """
    
    FRAMEWORK_SIGNATURES = {
        "pytorch": {
            "extensions": [".pt", ".pth"],
            "magic_bytes": b"PK\x03\x04",  # ZIP-like for PyTorch
            "header_markers": [b"protocol", b"torch"],
        },
        "tensorflow": {
            "extensions": [".pb", ".h5", ".savedmodel"],
            "magic_bytes": b"\x08\x03\x12",  # TensorFlow proto
            "header_markers": [b"tensorflow", b"keras"],
        },
        "onnx": {
            "extensions": [".onnx"],
            "magic_bytes": b"ONNX",
            "header_markers": [b"ONNX"],
        },
        "sklearn": {
            "extensions": [".joblib", ".pkl", ".pickle"],
            "magic_bytes": b"\x80",  # Pickle protocol marker
            "header_markers": [b"sklearn"],
        },
        "huggingface": {
            "extensions": [".safetensors"],
            "magic_bytes": b"\x00\x00\x00",  # SafeTensors format
            "header_markers": [b"safetensors"],
        }
    }
    
    DANGEROUS_PICKLE_INSTRUCTIONS = [
        b"os.system",
        b"subprocess",
        b"__import__",
        b"eval",
        b"exec",
        b"compile",
        b"open(",
        b"system",
    ]
    
    def __init__(self):
        self.model_id = str(uuid.uuid4())
    
    def analyze(self, file_path: str) -> Dict[str, Any]:
        """
        Analyze model file and extract metadata.
        
        Returns:
        {
            'model_id': unique_id,
            'framework': detected_framework,
            'model_type': type_of_model,
            'is_safe': safety_assessment,
            'metadata': extracted_metadata,
            'message': human_readable_message,
            'scan_eligible': can_be_scanned
        }
        """
        file_path = Path(file_path)
        
        if not file_path.exists():
            return self._error_response("File not found")
        
        # Get file info
        file_size = file_path.stat().st_size
        file_ext = file_path.suffix.lower()
        file_name = file_path.name
        
        # Check file size (reject huge files)
        if file_size > 2 * 1024 * 1024 * 1024:  # 2GB limit
            return self._error_response("File too large (>2GB)")
        
        # Detect framework
        framework = self._detect_framework(file_path)
        
        if framework is None:
            return self._error_response("Unknown model framework")
        
        # Analyze based on framework
        if framework == "pytorch":
            return self._analyze_pytorch(file_path)
        elif framework == "tensorflow":
            return self._analyze_tensorflow(file_path)
        elif framework == "onnx":
            return self._analyze_onnx(file_path)
        elif framework == "sklearn":
            return self._analyze_sklearn(file_path)
        elif framework == "huggingface":
            return self._analyze_huggingface(file_path)
        else:
            return self._error_response(f"Unsupported framework: {framework}")
    
    def _detect_framework(self, file_path: Path) -> str:
        """
        Detect model framework without executing code.
        """
        try:
            # Read first few bytes
            with open(file_path, "rb") as f:
                header = f.read(512)
            
            file_ext = file_path.suffix.lower()
            
            # Check magic bytes and headers
            for framework, config in self.FRAMEWORK_SIGNATURES.items():
                # Check extension
                if file_ext in config["extensions"]:
                    return framework
                
                # Check magic bytes
                if header.startswith(config["magic_bytes"]):
                    return framework
                
                # Check header markers
                for marker in config["header_markers"]:
                    if marker in header:
                        return framework
            
            return None
        
        except Exception as e:
            print(f"Detection error: {e}")
            return None
    
    def _analyze_pytorch(self, file_path: Path) -> Dict[str, Any]:
        """
        Analyze PyTorch model (.pt, .pth files).
        Uses zipfile to inspect without unpickling.
        """
        try:
            metadata = {
                "framework": "PyTorch",
                "file_size_mb": file_path.stat().st_size / (1024 * 1024),
                "layer_count": 0,
                "input_shape": None,
                "output_shape": None,
                "parameter_count": 0,
                "model_architecture": "Unknown"
            }
            
            is_safe = True
            
            # PyTorch .pt files are ZIP archives
            try:
                with zipfile.ZipFile(file_path, 'r') as z:
                    file_list = z.namelist()
                    
                    # Look for manifest or metadata
                    if 'data.pkl' in file_list:
                        # Check for malicious pickle instructions
                        data_pkl = z.read('data.pkl')
                        is_safe = not self._contains_dangerous_pickle(data_pkl)
                    
                    # Count files as proxy for layer count
                    metadata["layer_count"] = len([f for f in file_list if f.startswith('data/')])
            except zipfile.BadZipFile:
                # Might be raw pickle file
                with open(file_path, 'rb') as f:
                    content = f.read(10000)
                    is_safe = not self._contains_dangerous_pickle(content)
            
            return {
                "model_id": self.model_id,
                "framework": "PyTorch",
                "model_type": "Neural Network",
                "is_safe": is_safe,
                "metadata": metadata,
                "message": (
                    "✅ PyTorch model loaded safely (static inspection)" if is_safe
                    else "⚠️ WARNING: Potential malicious code detected in model"
                ),
                "scan_eligible": is_safe
            }
        
        except Exception as e:
            return self._error_response(f"PyTorch analysis failed: {str(e)}")
    
    def _analyze_tensorflow(self, file_path: Path) -> Dict[str, Any]:
        """Analyze TensorFlow model (SavedModel, .pb, .h5)"""
        try:
            metadata = {
                "framework": "TensorFlow",
                "file_size_mb": file_path.stat().st_size / (1024 * 1024),
                "layer_count": 0,
                "input_shape": None,
                "output_shape": None,
                "parameter_count": 0,
                "has_serving_default": False
            }
            
            # Check if it's a SavedModel directory
            if file_path.is_dir():
                saved_model_file = file_path / "saved_model.pb"
                if saved_model_file.exists():
                    metadata["has_serving_default"] = True
                    # Count assets as layer proxy
                    assets_dir = file_path / "assets"
                    if assets_dir.exists():
                        metadata["layer_count"] = len(list(assets_dir.iterdir()))
            
            elif file_path.suffix == ".h5":
                # HDF5 files - check header
                with open(file_path, 'rb') as f:
                    header = f.read(100)
                    # HDF5 signature
                    if header.startswith(b'\x89HDF'):
                        metadata["model_type"] = "Keras"
            
            elif file_path.suffix == ".pb":
                # Protobuf file - check for suspicious patterns
                with open(file_path, 'rb') as f:
                    content = f.read(5000)
                    if b"__import__" in content or b"os.system" in content:
                        return self._error_response(
                            "Malicious code detected in TensorFlow model"
                        )
            
            return {
                "model_id": self.model_id,
                "framework": "TensorFlow",
                "model_type": "Neural Network",
                "is_safe": True,
                "metadata": metadata,
                "message": "✅ TensorFlow model ready for scanning",
                "scan_eligible": True
            }
        
        except Exception as e:
            return self._error_response(f"TensorFlow analysis failed: {str(e)}")
    
    def _analyze_onnx(self, file_path: Path) -> Dict[str, Any]:
        """Analyze ONNX model format (safest!)"""
        try:
            metadata = {
                "framework": "ONNX",
                "file_size_mb": file_path.stat().st_size / (1024 * 1024),
                "layer_count": 0,
                "input_nodes": [],
                "output_nodes": [],
                "operators": [],
                "opset_version": None
            }
            
            # ONNX format is text-based and safe
            # Read protobuf structure (no code execution)
            try:
                import onnx
                model = onnx.load(file_path, load_external_data=False)
                
                metadata["opset_version"] = model.opset_import[0].version if model.opset_import else None
                metadata["layer_count"] = len(model.graph.node)
                
                # Extract input/output info
                metadata["input_nodes"] = [
                    {"name": inp.name, "shape": self._extract_shape(inp)}
                    for inp in model.graph.input
                ]
                metadata["output_nodes"] = [
                    {"name": out.name, "shape": self._extract_shape(out)}
                    for out in model.graph.output
                ]
                metadata["operators"] = list(set([node.op_type for node in model.graph.node]))
            
            except ImportError:
                # ONNX not installed, but we can still read the file structure
                with open(file_path, 'rb') as f:
                    header = f.read(100)
                    if b"ONNX" in header:
                        metadata["valid_onnx"] = True
            
            return {
                "model_id": self.model_id,
                "framework": "ONNX",
                "model_type": "Neural Network",
                "is_safe": True,
                "metadata": metadata,
                "message": "✅ ONNX is safest format - ready for scanning",
                "scan_eligible": True
            }
        
        except Exception as e:
            return self._error_response(f"ONNX analysis failed: {str(e)}")
    
    def _analyze_sklearn(self, file_path: Path) -> Dict[str, Any]:
        """Analyze scikit-learn model (joblib or pickle)"""
        try:
            metadata = {
                "framework": "scikit-learn",
                "file_size_mb": file_path.stat().st_size / (1024 * 1024),
                "model_type": "Unknown",
                "is_pickled": file_path.suffix in [".pkl", ".pickle"]
            }
            
            is_safe = True
            
            # Check for malicious pickle code
            with open(file_path, 'rb') as f:
                content = f.read(10000)
                is_safe = not self._contains_dangerous_pickle(content)
                
                # Try to identify model type from pickle header
                if b"RandomForest" in content:
                    metadata["model_type"] = "Random Forest"
                elif b"SVC" in content:
                    metadata["model_type"] = "Support Vector Machine"
                elif b"LogisticRegression" in content:
                    metadata["model_type"] = "Logistic Regression"
                elif b"Pipeline" in content:
                    metadata["model_type"] = "Pipeline"
            
            return {
                "model_id": self.model_id,
                "framework": "scikit-learn",
                "model_type": metadata["model_type"],
                "is_safe": is_safe,
                "metadata": metadata,
                "message": (
                    "✅ scikit-learn model safe to scan" if is_safe
                    else "⚠️ Model contains suspicious pickle instructions"
                ),
                "scan_eligible": is_safe
            }
        
        except Exception as e:
            return self._error_response(f"scikit-learn analysis failed: {str(e)}")
    
    def _analyze_huggingface(self, file_path: Path) -> Dict[str, Any]:
        """Analyze Hugging Face SafeTensors format (very safe!)"""
        try:
            metadata = {
                "framework": "Hugging Face",
                "file_size_mb": file_path.stat().st_size / (1024 * 1024),
                "tensor_count": 0,
                "data_types": [],
                "shapes": {}
            }
            
            # SafeTensors is JSON + binary (no code)
            with open(file_path, 'rb') as f:
                # Read header size (first 8 bytes)
                header_size_bytes = f.read(8)
                if len(header_size_bytes) == 8:
                    header_size = int.from_bytes(header_size_bytes, 'little')
                    header_json = f.read(header_size)
                    
                    try:
                        header = json.loads(header_json)
                        metadata["tensor_count"] = len(header)
                        
                        # Extract tensor info
                        for name, info in header.items():
                            if isinstance(info, dict):
                                metadata["shapes"][name] = info.get("shape", [])
                                dtype = info.get("dtype", "unknown")
                                if dtype not in metadata["data_types"]:
                                    metadata["data_types"].append(dtype)
                    except json.JSONDecodeError:
                        pass
            
            return {
                "model_id": self.model_id,
                "framework": "Hugging Face",
                "model_type": "Transformer",
                "is_safe": True,
                "metadata": metadata,
                "message": "✅ SafeTensors is safest format - no code execution possible",
                "scan_eligible": True
            }
        
        except Exception as e:
            return self._error_response(f"Hugging Face analysis failed: {str(e)}")
    
    def _contains_dangerous_pickle(self, data: bytes) -> bool:
        """
        Scan pickle data for dangerous instructions without unpickling.
        
        WHY THIS IS CRITICAL:
        pickle.load() can execute arbitrary Python code!
        A malicious pickle file can:
        - Run shell commands
        - Delete files
        - Steal credentials
        - Install malware
        
        SOLUTION: Static inspection only
        """
        for dangerous_instruction in self.DANGEROUS_PICKLE_INSTRUCTIONS:
            if dangerous_instruction in data:
                return True
        
        return False
    
    def _extract_shape(self, tensor_proto) -> list:
        """Extract shape from ONNX tensor"""
        try:
            if hasattr(tensor_proto, 'type') and hasattr(tensor_proto.type, 'tensor_type'):
                shape = tensor_proto.type.tensor_type.shape
                return [d.dim_value for d in shape.dim]
        except:
            pass
        return None
    
    def _error_response(self, message: str) -> Dict[str, Any]:
        """Generate error response"""
        return {
            "model_id": self.model_id,
            "framework": "Unknown",
            "model_type": "Unknown",
            "is_safe": False,
            "metadata": {"error": message},
            "message": f"❌ {message}",
            "scan_eligible": False
        }
