import requests
import base64
from urllib.parse import urlparse
import re

class GitHubService:
    """
    Service to interact with GitHub API.
    Handles both public and private repositories.
    """
    
    def __init__(self, token=None):
        self.token = token
        self.base_url = "https://api.github.com"
        self.headers = {"Accept": "application/vnd.github.v3.raw"}
        
        if token:
            self.headers["Authorization"] = f"token {token}"
    
    def parse_repo_url(self, url):
        """Extract owner and repo name from GitHub URL"""
        # Handle both https://github.com/owner/repo and github.com/owner/repo
        match = re.search(r'github\.com[:/]([^/]+)/([^/]+?)(?:\.git)?/?$', url)
        if match:
            return match.group(1), match.group(2)
        raise ValueError("Invalid GitHub repository URL")
    
    def fetch_repo(self, repo_url):
        """
        Fetch all files from repository.
        Returns dict with file paths and contents.
        """
        try:
            owner, repo = self.parse_repo_url(repo_url)
            
            # Get repository contents recursively
            files = {}
            self._fetch_directory(owner, repo, "", files)
            
            return {
                "owner": owner,
                "repo": repo,
                "url": repo_url,
                "files": files
            }
        except Exception as e:
            print(f"Error fetching repository: {e}")
            return None
    
    def _fetch_directory(self, owner, repo, path, files_dict):
        """Recursively fetch all files in repository"""
        url = f"{self.base_url}/repos/{owner}/{repo}/contents/{path}"
        
        try:
            response = requests.get(url, headers=self.headers, timeout=10)
            
            if response.status_code == 404:
                return
            
            response.raise_for_status()
            contents = response.json()
            
            # Handle single file vs directory
            if not isinstance(contents, list):
                contents = [contents]
            
            for item in contents:
                if item["type"] == "file":
                    # Fetch file content
                    file_content = self._fetch_file_content(
                        owner, repo, item["path"]
                    )
                    if file_content is not None:
                        files_dict[item["path"]] = {
                            "content": file_content,
                            "name": item["name"]
                        }
                elif item["type"] == "dir" and not item["name"].startswith("."):
                    # Recurse into subdirectories (skip hidden dirs)
                    self._fetch_directory(
                        owner, repo, item["path"], files_dict
                    )
        except Exception as e:
            print(f"Error fetching directory {path}: {e}")
    
    def _fetch_file_content(self, owner, repo, path):
        """Fetch content of a single file"""
        url = f"{self.base_url}/repos/{owner}/{repo}/contents/{path}"
        
        try:
            response = requests.get(url, headers=self.headers, timeout=5)
            
            if response.status_code != 200:
                return None
            
            data = response.json()
            
            # Decode base64 content
            if "content" in data:
                return base64.b64decode(data["content"]).decode("utf-8", errors="ignore")
            
            return None
        except Exception as e:
            print(f"Error fetching file {path}: {e}")
            return None
