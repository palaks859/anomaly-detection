from google import genai
import os

client = genai.Client(api_key=os.environ.get("GEMINI_API_KEY"))

for m in client.models.list():
    if "generateContent" in m.supported_actions:
        print(m.name)