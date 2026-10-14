from analyzer import analyze

def test_safe_message():
    assert analyze("See you at lunch tomorrow")["level"] == "LOW"

def test_digital_arrest():
    assert analyze("CBI officer: digital arrest, stay on video call")["score"] >= 75
def test_hinglish_scam():
    result = analyze("Aapka account band ho jayega. Turant OTP bhejiye aur kisi ko mat batana")
    assert result["score"] >= 40    