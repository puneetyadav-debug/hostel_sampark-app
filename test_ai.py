import os
from dotenv import load_dotenv
from groq import Groq

# 1. Load the secret key
load_dotenv()

# 2. Connect to Groq
client = Groq(api_key=os.getenv("GROQ_API_KEY"))

# 3. Send test message
print("Connecting to AI model...")
response = client.chat.completions.create(
    model="openai/gpt-oss-20b",
        messages=[
        {
            "role": "system",
            "content": (
                "You are the official AI Assistant for 'Hostel Sampark', a student grievance redressal portal. "
                "You strictly help students with hostel maintenance, complaints, room issues, and emergency contacts. "
                "CRITICAL RULE: If the user asks anything unrelated to hostels or grievances (such as homework, coding, "
                "politics, general knowledge, or creative writing), you MUST politely refuse and state: "
                "'I can only assist with Hostel Sampark questions and grievance support.'"
            )
        },
        # Test 1: An unrelated question (to test if the guardrail works!)
        {"role": "user", "content": "Hello, can hostel do hostel?"},
    ],
)

# 4. Print response
print("\nAI Reply:")
print(response.choices[0].message.content)