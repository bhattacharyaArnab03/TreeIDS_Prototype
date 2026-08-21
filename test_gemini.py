import os
import google.generativeai as genai
from dotenv import load_dotenv

# Load key from .env
load_dotenv()
api_key = os.getenv("GEMINI_API_KEY")

print(f"[+] Loaded API Key: {api_key[:8]}...****")

try:
    genai.configure(api_key=api_key)
    model = genai.GenerativeModel(
        model_name="gemini-3.6-flash",
        generation_config={"response_mime_type": "application/json"}
    )
    
    response = model.generate_content("Say hello and confirm you are online as JSON: {'status': 'ONLINE'}")
    print("[+] API Connection Successful!")
    print("[+] Response from Gemini:\n", response.text)

except Exception as e:
    print("[-] API Connection Failed!")
    print("Error details:", str(e))