"""
Crawls a target site to discover in-scope URLs and forms.
Stays within the same origin to avoid accidentally probing third-party hosts.
"""

import re
import time
from collections import deque
from urllib.parse import urljoin, urlparse, urldefrag, parse_qs

import requests
from bs4 import BeautifulSoup


class Crawler:
    def __init__(self, base_url: str, session: requests.Session, max_pages: int = 100, delay: float = 0.2):
        parsed = urlparse(base_url)
        self.origin = f"{parsed.scheme}://{parsed.netloc}"
        self.base_url = base_url
        self.session = session
        self.max_pages = max_pages
        self.delay = delay

        self.visited: set[str] = set()
        # Each entry: {"url": str, "params": dict, "method": "GET"|"POST", "data": dict}
        self.endpoints: list[dict] = []

    def _same_origin(self, url: str) -> bool:
        return urlparse(url).netloc == urlparse(self.origin).netloc

    def _normalize(self, url: str) -> str:
        url, _ = urldefrag(url)
        return url.rstrip("/") or "/"

    def _extract_links(self, soup: BeautifulSoup, page_url: str) -> list[str]:
        links = []
        for tag in soup.find_all("a", href=True):
            href = tag["href"]
            if href.startswith("javascript:") or href.startswith("mailto:"):
                continue
            full = urljoin(page_url, href)
            full = self._normalize(full)
            if self._same_origin(full):
                links.append(full)
        return links

    def _extract_forms(self, soup: BeautifulSoup, page_url: str) -> list[dict]:
        forms = []
        for form in soup.find_all("form"):
            action = form.get("action", "")
            method = form.get("method", "get").upper()
            action_url = self._normalize(urljoin(page_url, action)) if action else page_url

            if not self._same_origin(action_url):
                continue

            fields: dict[str, str] = {}
            for inp in form.find_all(["input", "textarea", "select"]):
                name = inp.get("name")
                if not name:
                    continue
                value = inp.get("value", "test")
                fields[name] = value

            forms.append({"url": action_url, "method": method, "data": fields, "params": {}})
        return forms

    def _record_url_params(self, url: str) -> None:
        parsed = urlparse(url)
        params = parse_qs(parsed.query, keep_blank_values=True)
        flat = {k: v[0] for k, v in params.items()}
        base = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
        if flat:
            self.endpoints.append({"url": base, "method": "GET", "params": flat, "data": {}})

    def crawl(self) -> list[dict]:
        start = self._normalize(self.base_url)
        queue: deque[str] = deque([start])
        queued: set[str] = {start}

        while queue and len(self.visited) < self.max_pages:
            url = queue.popleft()
            if url in self.visited:
                continue
            self.visited.add(url)

            try:
                resp = self.session.get(url, timeout=10, allow_redirects=True)
            except requests.RequestException:
                continue

            time.sleep(self.delay)

            self._record_url_params(url)

            ct = resp.headers.get("Content-Type", "")
            if "html" not in ct:
                continue

            soup = BeautifulSoup(resp.text, "html.parser")

            for link in self._extract_links(soup, url):
                if link not in self.visited and link not in queued:
                    queued.add(link)
                    queue.append(link)

            for form in self._extract_forms(soup, url):
                self.endpoints.append(form)

        # Also add bare visited URLs (no params) so other checks (CORS, etc.) see them
        for url in self.visited:
            self.endpoints.append({"url": url, "method": "GET", "params": {}, "data": {}})

        return self.endpoints
