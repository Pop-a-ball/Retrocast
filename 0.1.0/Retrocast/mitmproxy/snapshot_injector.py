"""
Snapshot Injector - injects website styling from local snapshots
into internet packets intercepted by WinDivert.

Snapshot Structure:
  Snapshots/
    ├── Wikipedia_files/
    │   ├── Wikipedia.html (main HTML file)
    │   ├── 2013/
    │   │   ├── CSS, JS, images (2013 snapshot)
    │   ├── 2015/
    │   │   ├── CSS, JS, images (2015 snapshot)

Behavior:
1. Checks website domain against folders in Snapshots/
2. Checks snapshot year in subfolders
3. Injects styling from snapshot into WinDivert packets
"""

from mitmproxy import http
import os
import logging
import re
from pathlib import Path
from urllib.parse import urlparse
from datetime import datetime

log = logging.getLogger('snapshot_injector')

# ============ LOGGING SETUP ============
def setup_file_logging():
    """Setup file logging for snapshot injector."""
    try:
        log_dir = os.getcwd()
        log_file = os.path.join(log_dir, 'snapshot_injector.log')
        
        file_handler = logging.FileHandler(log_file, encoding='utf-8')
        file_handler.setLevel(logging.DEBUG)
        
        formatter = logging.Formatter(
            '%(asctime)s [%(levelname)s] %(name)s: %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
        file_handler.setFormatter(formatter)
        log.addHandler(file_handler)
        log.setLevel(logging.DEBUG)
        
        log.info(f'Snapshot Injector initialized. Log file: {log_file}')
    except Exception as e:
        print(f'Failed to setup file logging: {e}')

setup_file_logging()

# ============ SNAPSHOT LOADER ============
class SnapshotLoader:
    """Loads snapshots from local Snapshots folder."""
    
    def __init__(self):
        """Initialize snapshot loader."""
        addon_dir = os.path.dirname(__file__)
        self.snapshots_dir = os.path.join(addon_dir, 'Snapshots')
        self.target_year = self._load_target_year()
        log.info(f'SnapshotLoader initialized. Snapshots dir: {self.snapshots_dir}')
        log.info(f'Target year: {self.target_year}')
    
    def _load_target_year(self):
        """Load target year from threshold.txt."""
        threshold_path = os.path.join(os.path.dirname(__file__), '..', 'deployment', 'threshold.txt')
        try:
            if os.path.exists(threshold_path):
                with open(threshold_path, 'r', encoding='utf-8') as f:
                    lines = f.readlines()
                    # File format: line 1 = flag (0/1), line 2 = date
                    if len(lines) >= 2:
                        date_str = lines[1].strip()
                        # Extract year from ISO format (2025-01-13T...)
                        year = date_str.split('-')[0]
                        log.info(f'Loaded target year from threshold.txt: {year}')
                        return year
        except Exception as e:
            log.warning(f'Failed to load target year: {e}')
        
        # Fallback to current year
        return str(datetime.now().year)
    
    def _make_snapshot_folder_name(self, domain, path=''):
        """
        Generate snapshot folder name from domain and path.
        
        Format: domain-path_files (/ replaced with -)
        Examples:
          en.wikipedia.org + /wiki/Main_Page → en.wikipedia.org-wiki-Main_Page_files
          en.wikipedia.org + / → en.wikipedia.org-_files
        """
        # Clean path: remove leading /
        if path.startswith('/'):
            path = path[1:]
        
        # Replace / with -
        path = path.replace('/', '-')
        
        # Create folder name
        if path:
            folder_name = f"{domain}-{path}_files"
        else:
            folder_name = f"{domain}-_files"
        
        return folder_name
    
    def _find_matching_folder(self, domain, path=''):
        """
        Find matching snapshot folder in Snapshots directory.
        
        Tries exact match first, then fuzzy matching by domain.
        """
        # Attempt 1: exact match with full path
        folder_name = self._make_snapshot_folder_name(domain, path)
        folder_path = os.path.join(self.snapshots_dir, folder_name)
        
        log.debug(f'Looking for snapshot folder: {folder_name}')
        
        if os.path.exists(folder_path):
            log.debug(f'Found exact match: {folder_name}')
            return folder_path
        
        # Attempt 2: search by domain (any path)
        domain_prefix = f"{domain}-"
        for item in os.listdir(self.snapshots_dir):
            if item.lower().startswith(domain_prefix.lower()) and item.endswith('_files'):
                full_path = os.path.join(self.snapshots_dir, item)
                if os.path.isdir(full_path):
                    log.debug(f'Found fuzzy match for domain {domain}: {item}')
                    return full_path
        
        log.warning(f'No snapshot folder found for {domain}{path}')
        return None
    
    def get_snapshot_html(self, domain, path=''):
        """
        Get snapshot HTML for domain and path.
        
        Args:
            domain: e.g., 'en.wikipedia.org'
            path: e.g., '/wiki/Main_Page'
        
        Returns:
            HTML content or None if not found
        """
        site_dir = self._find_matching_folder(domain, path)
        
        if not site_dir:
            log.warning(f'Snapshot directory not found for {domain}{path}')
            return None
        
        log.debug(f'Found snapshot directory: {site_dir}')
        
        # Look for HTML file in folder
        html_path = self._find_snapshot_file(site_dir)
        
        if html_path and os.path.exists(html_path):
            try:
                with open(html_path, 'r', encoding='utf-8', errors='ignore') as f:
                    html = f.read()
                    log.info(f'Loaded snapshot for {domain}{path} from {html_path} ({len(html)} bytes)')
                    return html
            except Exception as e:
                log.error(f'Failed to read snapshot file {html_path}: {e}')
        
        return None
    
    
    def _find_snapshot_file(self, site_dir):
        """Find snapshot HTML file in directory or year subdirectory."""
        # First check the target year subdirectory
        year_dir = os.path.join(site_dir, self.target_year)
        if os.path.exists(year_dir):
            log.debug(f'Checking year directory: {year_dir}')
            for fname in os.listdir(year_dir):
                if fname.endswith('.html'):
                    return os.path.join(year_dir, fname)
        
        # Then check the root site_dir folder
        for fname in os.listdir(site_dir):
            if fname.endswith('.html'):
                return os.path.join(site_dir, fname)
        
        log.warning(f'No HTML file found in {site_dir} or year subdirectory {year_dir}')
        return None
    
    def get_snapshot_resources_dir(self, domain, path=''):
        """
        Get path to resources directory for domain and path.
        
        Returns:
            Path to resources directory or None
        """
        site_dir = self._find_matching_folder(domain, path)
        
        if site_dir and os.path.exists(site_dir):
            return site_dir
        
        return None

# ============ ADDON CLASS ============
loader = SnapshotLoader()

class SnapshotInjectorAddon:
    """Addon that injects snapshot HTML/CSS into intercepted responses."""
    
    def request(self, flow: http.HTTPFlow):
        """Intercept requests for snapshot resources (CSS, JS, images)."""
        try:
            host = getattr(flow.request, 'host', None)
            if not host:
                return
            
            # Get resource path
            path = flow.request.path
            
            # Check file extension (only for resources, not HTML)
            resource_extensions = ('.css', '.js', '.png', '.jpg', '.jpeg', '.gif', '.svg', '.woff', '.woff2', '.ttf', '.eot')
            if not any(path.lower().endswith(ext) for ext in resource_extensions):
                return
            
            # Check if snapshot exists for this domain
            # Use empty path because all resources are in one snapshot folder
            # (e.g., en.wikipedia.org-wiki-Main_Page_files)
            resources_dir = loader.get_snapshot_resources_dir(host, '')
            if not resources_dir:
                return
            
            # Find local resource file
            # Path can be /path/to/resource.css or /wiki/load.php?...
            local_file = self._find_resource_file(resources_dir, path)
            
            if local_file and os.path.exists(local_file):
                # Send local file instead of server request
                try:
                    with open(local_file, 'rb') as f:
                        content = f.read()
                    
                    # Determine Content-Type
                    content_type = self._get_content_type(local_file)
                    
                    # Create response with local file
                    flow.response = http.Response.make(
                        200,
                        content,
                        {"Content-Type": content_type, "Cache-Control": "max-age=31536000"}
                    )
                    
                    log.info(f'[RESOURCE] Served local file for {host}{path} ({len(content)} bytes)')
                except Exception as e:
                    log.error(f'[RESOURCE] Error serving local file {local_file}: {e}')
        
        except Exception as e:
            log.error(f'[RESOURCE] Error in request handler: {e}')
    
    def _find_resource_file(self, resources_dir, path):
        """Find local resource file matching the request path."""
        # Get base filename from path
        basename = os.path.basename(path)
        
        # Remove query parameters (load.php?lang=en&...)
        if '?' in basename:
            basename = basename.split('?')[0]
        
        # Search for file in resources_dir
        for root, dirs, files in os.walk(resources_dir):
            for fname in files:
                if fname.lower() == basename.lower():
                    return os.path.join(root, fname)
        
        # Try direct path
        direct_path = os.path.join(resources_dir, basename)
        if os.path.exists(direct_path):
            return direct_path
        
        return None
    
    def _get_content_type(self, filepath):
        """Determine Content-Type from file extension."""
        ext = os.path.splitext(filepath)[1].lower()
        content_types = {
            '.css': 'text/css',
            '.js': 'application/javascript',
            '.png': 'image/png',
            '.jpg': 'image/jpeg',
            '.jpeg': 'image/jpeg',
            '.gif': 'image/gif',
            '.svg': 'image/svg+xml',
            '.woff': 'font/woff',
            '.woff2': 'font/woff2',
            '.ttf': 'font/ttf',
            '.eot': 'application/vnd.ms-fontobject',
        }
        return content_types.get(ext, 'application/octet-stream')
    
    def response(self, flow: http.HTTPFlow):
        """Process HTTP response and inject snapshot if needed."""
        if flow.response is None:
            return
        
        try:
            host = getattr(flow.request, 'host', None)
            path = getattr(flow.request, 'path', '')
            
            # Check content type (HTML only)
            content_type = flow.response.headers.get('content-type', '').lower()
            
            # Skip if not HTML (even if server says text/html)
            non_html_extensions = ('.css', '.js', '.png', '.jpg', '.jpeg', '.gif', '.svg', 
                                   '.woff', '.woff2', '.ttf', '.eot', '.php', '.json', '.xml')
            if any(path.lower().endswith(ext) for ext in non_html_extensions):
                return
            
            if not content_type.startswith('text/html'):
                return
            
            log.debug(f'Processing HTML response from {host}: {flow.request.pretty_url}')
            
            # Get snapshot for this domain and path
            snapshot_html = loader.get_snapshot_html(host, path)
            
            if snapshot_html:
                log.info(f'[INJECT] Injecting snapshot for {host}{path}')
                try:
                    from bs4 import BeautifulSoup
                    
                    # Parse current HTML
                    current_soup = BeautifulSoup(flow.response.text, 'html.parser')
                    snapshot_soup = BeautifulSoup(snapshot_html, 'html.parser')
                    
                    # Replace <head> with old one (CSS, JS, meta tags)
                    if current_soup.head and snapshot_soup.head:
                        current_soup.head.replace_with(snapshot_soup.head)
                        log.info(f'[INJECT] Replaced <head> from snapshot')
                    
                    # Update HTML in response
                    flow.response.text = str(current_soup)
                    log.info(f'[INJECT] Snapshot injected successfully for {host}')
                
                except ImportError:
                    # Fallback to regex
                    log.warning('[INJECT] BeautifulSoup not available, using regex')
                    old_head = re.search(r'<head[^>]*>.*?</head>', snapshot_html, re.DOTALL | re.IGNORECASE)
                    
                    if old_head:
                        current_head = re.search(r'<head[^>]*>.*?</head>', flow.response.text, re.DOTALL | re.IGNORECASE)
                        if current_head:
                            flow.response.text = (
                                flow.response.text[:current_head.start()] + 
                                old_head.group(0) + 
                                flow.response.text[current_head.end():]
                            )
                            log.info(f'[INJECT] Snapshot injected (regex) for {host}')
                
                except Exception as e:
                    log.error(f'[INJECT] Error injecting snapshot: {type(e).__name__}: {e}')
            
            else:
                log.debug(f'No snapshot found for {host}')
        
        except Exception as e:
            log.error(f'[INJECT] Unexpected error in response handler: {type(e).__name__}: {e}')

addons = [SnapshotInjectorAddon()]
