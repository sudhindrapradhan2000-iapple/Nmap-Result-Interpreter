import os

from dotenv import load_dotenv


# Load environment variables from the project's .env file.
load_dotenv()


# OpenAI configuration
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")
OPENAI_MODEL = os.getenv("OPENAI_MODEL", "gpt-6-luna")


# NVD configuration
NVD_API_KEY = os.getenv("NVD_API_KEY")


def validate_config() -> None:
    """Validate the configuration required to run the AI analysis."""

    if not OPENAI_API_KEY:
        raise RuntimeError(
            "OPENAI_API_KEY is not set. "
            "Add your OpenAI API key to the project's .env file."
        )
