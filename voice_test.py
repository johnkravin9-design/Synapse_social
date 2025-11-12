import sounddevice as sd
import numpy as np
import speech_recognition as sr

# Initialize recognizer
r = sr.Recognizer()

# Record audio for 5 seconds
duration = 5  # seconds
print("🎤 Listening...")
fs = 44100  # Sample rate
audio = sd.rec(int(duration * fs), samplerate=fs, channels=1, dtype='int16')
sd.wait()

# Convert NumPy array to AudioData for recognition
audio_data = sr.AudioData(audio.tobytes(), fs, 2)

try:
    text = r.recognize_google(audio_data)
    print("🗣️ You said:", text)
except sr.UnknownValueError:
    print("❌ Could not understand audio.")
except sr.RequestError:
    print("⚠️ Could not request results. Check connection.")
