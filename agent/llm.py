"""Choose the LLM from .env, so the provider is a one-line switch (ADR 0006).

LLM_PROVIDER=groq    (default) free hosted tier, open-weight model
LLM_PROVIDER=ollama  fully local; needs `pip install langchain-ollama` and a running Ollama
LLM_MODEL            optional; overrides the provider's default model
"""

import os

from dotenv import load_dotenv

load_dotenv()

DEFAULT_MODELS = {
    "groq": "openai/gpt-oss-20b",
    "ollama": "llama3.1",
}


def _provider():
    # `or "groq"`: an empty value (LLM_PROVIDER= in .env) also means "use the default".
    return (os.environ.get("LLM_PROVIDER") or "groq").lower().strip()


def _model(provider):
    return (os.environ.get("LLM_MODEL") or "").strip() or DEFAULT_MODELS.get(provider, "?")


def get_llm():
    """Return a LangChain chat model for the configured provider."""
    provider = _provider()
    if provider not in DEFAULT_MODELS:
        raise ValueError(f"Unknown LLM_PROVIDER {provider!r}. Use one of {sorted(DEFAULT_MODELS)}.")
    model = _model(provider)

    if provider == "groq":
        from langchain_groq import ChatGroq

        if not os.environ.get("GROQ_API_KEY"):
            raise RuntimeError("GROQ_API_KEY environment variable is not set")
        # temperature=0: the same alert should get the same triage (repeatable, easier to evaluate)
        return ChatGroq(model=model, temperature=0, max_retries=3, timeout=60)

    # provider == "ollama" (imported lazily so the dependency stays optional)
    try:
        from langchain_ollama import ChatOllama
    except ImportError as e:
        raise RuntimeError("LLM_PROVIDER=ollama needs: pip install langchain-ollama") from e
    return ChatOllama(
        model=model,
        base_url=os.environ.get("OLLAMA_HOST", "http://localhost:11434"),
        temperature=0,
    )


def model_name():
    """Provider/model string recorded with each triage result (useful for evaluation)."""
    provider = _provider()
    return f"{provider}:{_model(provider)}"
