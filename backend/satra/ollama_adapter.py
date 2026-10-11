import hashlib
import json
import time
from typing import AsyncGenerator, Dict, Any, Optional
import httpx

from backend.satra.settings import load_settings


class OllamaClient:
    def __init__(self, endpoint: Optional[str] = None, model: Optional[str] = None):
        settings = load_settings()
        self.endpoint = (endpoint or settings.ollama_endpoint).rstrip("/")
        self.model = model or settings.model_name
        self.client = httpx.AsyncClient(timeout=60.0)

    async def is_available(self) -> bool:
        try:
            r = await self.client.get(f"{self.endpoint}/api/tags", timeout=3.0)
            if r.status_code == 200:
                tags = r.json()
                models = [m.get("name") for m in tags.get("models", [])]
                return any(self.model in m or m in self.model for m in models)
        except Exception:
            return False
        return False

    async def generate_completion_stream(
        self, prompt: str, system: Optional[str] = None, temperature: float = 0.0
    ) -> AsyncGenerator[str, None]:
        payload = {
            "model": self.model,
            "prompt": prompt,
            "stream": True,
            "options": {
                "temperature": temperature,
                "num_predict": 1024,
            },
        }
        if system:
            payload["system"] = system

        async with self.client.stream(
            "POST", f"{self.endpoint}/api/generate", json=payload
        ) as response:
            response.raise_for_status()
            async for line in response.aiter_lines():
                if line:
                    data = json.loads(line)
                    yield data.get("response", "")
                    if data.get("done", False):
                        break

    async def generate_structured(
        self, prompt: str, system: Optional[str] = None, temperature: float = 0.0
    ) -> Dict[str, Any]:
        start = time.perf_counter()
        prompt_hash = hashlib.sha256(prompt.encode("utf-8")).hexdigest()

        payload = {
            "model": self.model,
            "prompt": prompt,
            "stream": False,
            "format": "json",
            "options": {
                "temperature": temperature,
                "num_predict": 1024,
            },
        }
        if system:
            payload["system"] = system

        try:
            r = await self.client.post(f"{self.endpoint}/api/generate", json=payload)
            r.raise_for_status()
            data = r.json()
            raw_text = data.get("response", "{}")
            structured = json.loads(raw_text)
            elapsed_ms = round((time.perf_counter() - start) * 1000, 2)
            return {
                "available": True,
                "model": self.model,
                "prompt_fingerprint": prompt_hash,
                "latency_ms": elapsed_ms,
                "tokens_evaluated": data.get("eval_count", 0),
                "data": structured,
            }
        except Exception as e:
            elapsed_ms = round((time.perf_counter() - start) * 1000, 2)
            return {
                "available": False,
                "model": self.model,
                "prompt_fingerprint": prompt_hash,
                "latency_ms": elapsed_ms,
                "error": str(e),
                "data": {},
            }
