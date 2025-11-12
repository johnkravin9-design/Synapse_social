from pydub import AudioSegment
import speech_recognition as sr
import os

# Convert m4a to wav
print("🎧 Converting audio...")
audio = AudioSegment.from_file("test.m4a", format="m4a")
audio.export("test.wav", format="wav")

# Recognize speech
print("🧠 Transcribing...")
r = sr.Recognizer()
with sr.AudioFile("test.wav") as source:
    data = r.record(source)

try:
    text = r.recognize_google(data)
    print("✅ You said:", text)
except sr.UnknownValueError:
    print("❌ Could not understand audio.")
except sr.RequestError as e:
    print("⚠️ Could not reach speech service:", e)
