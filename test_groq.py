import os
from groq import Groq
from dotenv import load_dotenv

# Load key from .env
load_dotenv()
api_key = os.getenv("GROQ_API_KEY")
if not api_key or api_key == "your_groq_api_key_here":
    api_key = os.getenv("GEMINI_API_KEY")

if not api_key or api_key == "your_groq_api_key_here" or api_key.startswith("AQ."):
    print("[-] Error: Valid Groq API Key (gsk_...) not detected in your .env file!")
    print(f"    Current GROQ_API_KEY in file: '{os.getenv('GROQ_API_KEY')}'")
    print("    Please make sure you have SAVED (Ctrl+S) the .env file with GROQ_API_KEY=gsk_...")
    exit(1)

print(f"[+] Loaded Groq API Key: {api_key[:8]}...****")

primary_model = os.getenv("GROQ_PRIMARY_MODEL", "qwen/qwen3.8-27b")
secondary_model = os.getenv("GROQ_SECONDARY_MODEL", "openai/gpt-oss-20b")

try:
    client = Groq(api_key=api_key)
    
    print(f"[*] Testing Primary Model: {primary_model}...")
    chat_primary = client.chat.completions.create(
        messages=[
            {"role": "system", "content": "You are a network security assistant. Always output valid JSON."},
            {"role": "user", "content": "Confirm you are online: {'status': 'ONLINE', 'tier': 'PRIMARY'}"}
        ],
        model=primary_model,
        response_format={"type": "json_object"}
    )
    print(f"  [+] {primary_model} -> Response:\n    {chat_primary.choices[0].message.content}")

    print(f"[*] Testing Secondary Model: {secondary_model}...")
    chat_secondary = client.chat.completions.create(
        messages=[
            {"role": "system", "content": "You are a network security assistant. Always output valid JSON."},
            {"role": "user", "content": "Confirm you are online: {'status': 'ONLINE', 'tier': 'SECONDARY'}"}
        ],
        model=secondary_model,
        response_format={"type": "json_object"}
    )
    print(f"  [+] {secondary_model} -> Response:\n    {chat_secondary.choices[0].message.content}")
    print("\n[+] Both Groq Cloud Models Verified & Operational!")

except Exception as e:
    print("[-] API Connection Failed!")
    print("Error details:", str(e))

