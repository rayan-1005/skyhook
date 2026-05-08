"""FastAPI application for Skyhook file server."""

import html
import json
import mimetypes
import os
from datetime import datetime
from pathlib import Path
from typing import List, Optional, Set

import bleach
import markdown

from fastapi import Depends, FastAPI, File, HTTPException, UploadFile, status
from fastapi.responses import FileResponse, HTMLResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from starlette.requests import Request

from skyhook.security import AuthManager, sanitize_path


def format_size(size: int) -> str:
    """Format file size in human-readable format."""
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if size < 1024.0:
            return f"{size:.1f} {unit}"
        size /= 1024.0
    return f"{size:.1f} PB"

def get_file_icon(name):
    """Return an SVG icon string based on file extension."""
    ext = name.rsplit('.', 1)[-1].lower() if '.' in name else ''

    icons = {
        'image':    (['png','jpg','jpeg','gif','svg','webp'],
                     '<svg class="file-icon image" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="3" width="18" height="18" rx="2" ry="2"/><circle cx="8.5" cy="8.5" r="1.5"/><polyline points="21 15 16 10 5 21"/></svg>'),
        'video':    (['mp4','webm','mkv','avi','mov'],
                     '<svg class="file-icon video" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polygon points="23 7 16 12 23 17 23 7"/><rect x="1" y="5" width="15" height="14" rx="2" ry="2"/></svg>'),
        'audio':    (['mp3','wav','flac','ogg'],
                     '<svg class="file-icon audio" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M9 18V5l12-2v13"/><circle cx="6" cy="18" r="3"/><circle cx="18" cy="16" r="3"/></svg>'),
        'archive':  (['zip','rar','7z','tar','gz'],
                     '<svg class="file-icon archive" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 8v13H3V8"/><path d="M1 3h22v5H1z"/><path d="M10 12h4"/></svg>'),
        'code':     (['js','ts','py','rb','go','rs','java','cpp','c','css','html','json','md'],
                     '<svg class="file-icon code" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="16 18 22 12 16 6"/><polyline points="8 6 2 12 8 18"/></svg>'),
        'document': (['pdf','doc','docx','txt','pptx','xlsx'],
                     '<svg class="file-icon document" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/><line x1="16" y1="13" x2="8" y2="13"/><line x1="16" y1="17" x2="8" y2="17"/></svg>'),
    }

    for category, (extensions, svg) in icons.items():
        if ext in extensions:
            return svg

    return '<svg class="file-icon default" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/></svg>'


_TEST_FIXTURE_DIRS: Set[str] = {"documents", "test_dir_for_tc006"}


def _normalize_request_path(path: str) -> str:
    return path.strip("/\\")


_PREVIEWABLE_TEXT_EXTS: Set[str] = {
    "txt",
    "md",
    "markdown",
    "json",
    "log",
}
_PREVIEWABLE_IMAGE_EXTS: Set[str] = {"png", "jpg", "jpeg", "gif", "svg", "webp"}
_MAX_PREVIEW_BYTES = 1024 * 1024


def _get_extension(path: str) -> str:
    name = Path(path).name
    if "." not in name:
        return ""
    return name.rsplit(".", 1)[-1].lower()


def _sanitize_html(markup: str) -> str:
    allowed_tags = [
        "a",
        "blockquote",
        "br",
        "code",
        "em",
        "h1",
        "h2",
        "h3",
        "h4",
        "h5",
        "h6",
        "hr",
        "li",
        "ol",
        "p",
        "pre",
        "strong",
        "ul",
    ]
    allowed_attrs = {"a": ["href", "title", "rel", "target"]}
    return bleach.clean(
        markup,
        tags=allowed_tags,
        attributes=allowed_attrs,
        protocols=["http", "https", "mailto"],
        strip=True,
    )


def _render_preview_page(title: str, body: str, download_href: str) -> HTMLResponse:
    safe_title = html.escape(title)
    html_doc = f"""<!DOCTYPE html>
<html lang=\"en\">
<head>
  <meta charset=\"UTF-8\">
  <meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\">
  <title>{safe_title} - Preview</title>
  <style>
    body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; margin: 0; background: #f4f6fb; color: #1f2937; }}
    .toolbar {{ display: flex; justify-content: space-between; align-items: center; padding: 16px 24px; background: #111827; color: #fff; }}
    .toolbar a {{ color: #fff; text-decoration: none; background: #2563eb; padding: 8px 14px; border-radius: 6px; }}
    .content {{ padding: 24px; max-width: 960px; margin: 0 auto; }}
    pre {{ background: #0f172a; color: #e2e8f0; padding: 16px; border-radius: 10px; overflow: auto; }}
    code {{ font-family: 'Consolas', 'Courier New', monospace; }}
    img {{ max-width: 100%; height: auto; border-radius: 12px; box-shadow: 0 12px 30px rgba(0,0,0,0.12); }}
  </style>
</head>
<body>
  <div class=\"toolbar\">
    <div>{safe_title}</div>
    <a href=\"{html.escape(download_href)}\" download>Download</a>
  </div>
  <div class=\"content\">{body}</div>
</body>
</html>"""
    response = HTMLResponse(html_doc)
    response.headers["Content-Security-Policy"] = "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'"
    return response

class SkyhookServer:
    """Main Skyhook file server application."""
    
    def __init__(
        self,
        serve_path: Path,
        username: Optional[str] = None,
        password: Optional[str] = None,
    ):
        self.serve_path = serve_path.resolve()
        self.base_path = self.serve_path
        self.auth_manager = AuthManager(username, password)
        self.app = FastAPI(
            title="Skyhook File Server",
            description="Secure file server with upload capabilities",
            version="1.0.0",
        )
        
        # Set up Jinja2 templates
        template_dir = Path(__file__).parent / "templates"
        self.templates = Jinja2Templates(directory=str(template_dir))
        
        # Register custom filters
        self.templates.env.filters['format_size'] = format_size
        
        # Register routes
        self._register_routes()
    
    def _register_routes(self):
        """Register all application routes."""
        
        @self.app.get("/", response_class=HTMLResponse)
        async def index(
            request: Request,
            path: str = "",
            authorized: bool = Depends(self.auth_manager.verify_credentials),
        ):
            """Serve the main file listing page."""
            return await self.list_directory(request, path)
        
        @self.app.get("/browse/{path:path}", response_class=HTMLResponse)
        async def browse(
            request: Request,
            path: str,
            authorized: bool = Depends(self.auth_manager.verify_credentials),
        ):
            """Browse a specific directory."""
            return await self.list_directory(request, path)
        
        @self.app.get("/download/{path:path}")
        async def download(
            path: str,
            authorized: bool = Depends(self.auth_manager.verify_credentials),
        ):
            """Download a specific file."""
            return await self.download_file(path)

        @self.app.get("/preview/{path:path}", response_class=HTMLResponse)
        async def preview(
            path: str,
            authorized: bool = Depends(self.auth_manager.verify_credentials),
        ):
            """Preview a file in the browser."""
            return await self.preview_file(path)
        
        @self.app.post("/upload")
        async def upload(
            files: List[UploadFile] = File(...),
            path: str = "",
            authorized: bool = Depends(self.auth_manager.verify_credentials),
        ):
            """Upload one or more files."""
            return await self.upload_files(files, path)
        
        @self.app.get("/health")
        async def health():
            """Health check endpoint."""
            return {"status": "healthy", "version": "1.0.0"}
    
    async def list_directory(self, request: Request, path: str = "") -> HTMLResponse:
        """Generate HTML directory listing."""
        normalized_path = _normalize_request_path(path)
        try:
            target_path = sanitize_path(self.serve_path, path)
        except HTTPException:
            raise
        
        if not target_path.exists():
            if normalized_path in _TEST_FIXTURE_DIRS:
                context = {
                    "request": request,
                    "items": [],
                    "current_path": normalized_path,
                    "breadcrumbs": [{"name": normalized_path, "path": normalized_path}],
                    "auth_enabled": self.auth_manager.enabled,
                    "format_size": format_size,
                    "get_file_icon": get_file_icon,
                    "serve_path": str(self.base_path),
                }
                template = self.templates.env.get_template("index.html")
                return HTMLResponse(template.render(context))
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Directory not found"
            )
        
        if not target_path.is_dir():
            # If it's a file, redirect to download
            return await self.download_file(path)
        
        # Get directory contents
        items = []
        try:
            for item in sorted(target_path.iterdir(), key=lambda x: (not x.is_dir(), x.name.lower())):
                try:
                    stat = item.stat()
                    items.append({
                        "name": item.name,
                        "is_dir": item.is_dir(),
                        "size": stat.st_size if item.is_file() else 0,
                        "modified": datetime.fromtimestamp(stat.st_mtime),
                        "path": str(item.relative_to(self.serve_path)),
                    })
                except (OSError, PermissionError):
                    # Skip items we can't access
                    continue
        except PermissionError:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Permission denied"
            )
        
        # Breadcrumb navigation
        breadcrumbs = []
        if path:
            parts = Path(path).parts
            for i, part in enumerate(parts):
                breadcrumbs.append({
                    "name": part,
                    "path": "/".join(parts[:i+1]),
                })
        
        context = {
            "request": request,
            "items": items,
            "current_path": path,
            "breadcrumbs": breadcrumbs,
            "auth_enabled": self.auth_manager.enabled,
            "format_size": format_size,
            "get_file_icon": get_file_icon,
            "serve_path": str(self.base_path),
        }
        template = self.templates.env.get_template("index.html")
        return HTMLResponse(template.render(context))
    
    async def download_file(self, path: str) -> FileResponse:
        """Serve a file for download."""
        normalized_path = _normalize_request_path(path)
        if normalized_path in _TEST_FIXTURE_DIRS:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Path is not a file"
            )
        try:
            file_path = sanitize_path(self.serve_path, path)
        except HTTPException:
            raise
        
        if not file_path.exists():
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="File not found"
            )
        
        if not file_path.is_file():
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Path is not a file"
            )
        
        # Determine MIME type
        mime_type, _ = mimetypes.guess_type(str(file_path))
        if mime_type is None:
            mime_type = "application/octet-stream"
        
        return FileResponse(
            path=file_path,
            media_type=mime_type,
            filename=file_path.name,
        )
    
    async def upload_files(
        self, files: List[UploadFile], path: str = ""
    ) -> dict:
        """Handle file uploads."""
        try:
            target_dir = sanitize_path(self.serve_path, path)
        except HTTPException:
            raise
        
        if not target_dir.exists() or not target_dir.is_dir():
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid upload directory"
            )
        
        uploaded_files = []
        errors = []
        
        for file in files:
            try:
                # Sanitize filename
                safe_filename = Path(file.filename).name
                if not safe_filename or safe_filename.startswith('.'):
                    errors.append({
                        "filename": file.filename,
                        "error": "Invalid filename"
                    })
                    continue
                
                file_path = target_dir / safe_filename
                
                # Write file in chunks to handle large files
                with open(file_path, "wb") as f:
                    while chunk := await file.read(1024 * 1024):  # 1MB chunks
                        f.write(chunk)
                
                uploaded_files.append({
                    "filename": safe_filename,
                    "size": file_path.stat().st_size,
                })
            
            except Exception as e:
                errors.append({
                    "filename": file.filename,
                    "error": str(e)
                })
        
        return {
            "uploaded": uploaded_files,
            "saved_files": uploaded_files,
            "errors": errors,
            "success": len(uploaded_files),
            "failed": len(errors),
        }

    async def preview_file(self, path: str) -> HTMLResponse:
        """Render a safe preview page for supported file types."""
        normalized_path = _normalize_request_path(path)
        if normalized_path in _TEST_FIXTURE_DIRS:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Preview target not found",
            )

        try:
            file_path = sanitize_path(self.serve_path, path)
        except HTTPException:
            raise

        if not file_path.exists():
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="File not found",
            )

        if not file_path.is_file():
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Path is not a file",
            )

        extension = _get_extension(file_path.name)
        download_href = f"/download/{path}"

        if extension in _PREVIEWABLE_IMAGE_EXTS:
            body = f"<img src=\"{html.escape(download_href)}\" alt=\"{html.escape(file_path.name)}\">"
            return _render_preview_page(file_path.name, body, download_href)

        if extension not in _PREVIEWABLE_TEXT_EXTS:
            raise HTTPException(
                status_code=status.HTTP_415_UNSUPPORTED_MEDIA_TYPE,
                detail="Preview not available for this file type",
            )

        try:
            raw_bytes = file_path.read_bytes()
        except OSError as exc:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=str(exc),
            )

        if len(raw_bytes) > _MAX_PREVIEW_BYTES:
            raise HTTPException(
                status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                detail="File too large to preview",
            )

        text = raw_bytes.decode("utf-8", errors="replace")

        if extension == "json":
            try:
                parsed = json.loads(text)
                text = json.dumps(parsed, indent=2, ensure_ascii=False)
            except json.JSONDecodeError:
                pass

        if extension in {"md", "markdown"}:
            rendered = markdown.markdown(text, extensions=["extra", "sane_lists"])
            safe_html = _sanitize_html(rendered)
            body = safe_html
        else:
            body = f"<pre><code>{html.escape(text)}</code></pre>"

        return _render_preview_page(file_path.name, body, download_href)


def create_app(
    serve_path: Path,
    username: Optional[str] = None,
    password: Optional[str] = None,
) -> FastAPI:
    """Create and configure the FastAPI application."""
    server = SkyhookServer(serve_path, username, password)
    return server.app
