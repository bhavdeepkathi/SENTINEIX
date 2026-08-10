import os
import json
from typing import List, Dict, Any
from openai import AsyncOpenAI


class LLMClient:
    def __init__(self):
        self.api_key = os.getenv("LLM_API_KEY", "")
        self.base_url = os.getenv("LLM_BASE_URL", "https://api.openai.com/v1")
        self.model = os.getenv("LLM_MODEL", "gpt-4o-mini")
        self.client = AsyncOpenAI(api_key=self.api_key, base_url=self.base_url)

    async def chat_completion(self, messages: List[Dict[str, str]], temperature: float = 0.2) -> str:
        """Return the assistant message content."""
        response = await self.client.chat.completions.create(
            model=self.model,
            messages=messages,
            temperature=temperature,
        )
        return response.choices[0].message.content.strip()


llm_client = LLMClient()