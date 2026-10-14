# hinglish_rules.py
# Format: (regex pattern, points, explanation)

HINGLISH_RULES = [
    # 🗣️ Hinglish (Roman letters)
    (r"(aapka|apka|aapke|apke).{0,25}(account|khata|card|sim).{0,25}(band|block|suspend)",
     15, "Hinglish: says your account/SIM/card will be blocked"),
    (r"(otp|pin|cvv).{0,20}(batao|bataiye|btao|bhejo|bhejiye|share kar)",
     20, "Hinglish: asks you to tell/send your OTP or PIN"),
    (r"(giraftar|giraftari|arrest ho)",
     25, "Hinglish: threatens arrest"),
    (r"(kisi ko|kisi se).{0,12}(mat|na).{0,12}(batana|batao|bolna|bataiye)",
     25, "Hinglish: tells you to keep it secret"),
    (r"(video call|call).{0,25}(par|pe|per).{0,15}(rahiye|rahein|bane rahiye|rehna)",
     20, "Hinglish: tells you to stay on the call"),
    (r"(paise|paisa|rakam|amount).{0,25}(transfer|bhejo|bhejiye|jama)",
     20, "Hinglish: asks you to transfer money"),
    (r"(inaam|inam|lottery|ladki).{0,20}(jeet|mila|nikli|jeeta)",
     15, "Hinglish: fake prize/lottery claim"),
    (r"(turant|abhi ke abhi|jaldi karein|aaj hi)",
     10, "Hinglish: creates false urgency"),
    (r"(adhikari|inspector|officer).{0,20}(cbi|police|ed|cyber)",
     20, "Hinglish: claims to be a government officer"),

    # 🪔 Hindi (Devanagari script)
    (r"डिजिटल अरेस्ट", 40, "Hindi: mentions 'digital arrest'"),
    (r"गिरफ्तार", 25, "Hindi: threatens arrest"),
    (r"(ओटीपी|ओ\.टी\.पी)", 10, "Hindi: mentions OTP"),
    (r"खाता.{0,15}(बंद|ब्लॉक)", 15, "Hindi: says your account will be blocked"),
    (r"किसी को.{0,10}(मत|न).{0,10}(बताना|बताएं|बोलना)", 25, "Hindi: tells you to keep it secret"),
    (r"(पैसे|रुपये|राशि).{0,20}(ट्रांसफर|भेजें|जमा)", 20, "Hindi: asks you to transfer money"),
    (r"(इनाम|लॉटरी).{0,15}(जीत|मिला|निकली)", 15, "Hindi: fake prize/lottery claim"),
]