# awareness_data.py

SCAM_TYPES = [
    {
        "icon": "👮",
        "title": "Digital Arrest",
        "how": "Fraudsters pose as CBI, ED, police or customs. They claim a parcel or your Aadhaar is linked to a crime, then keep you on a video call and demand money to 'clear your name'.",
        "red_flags": [
            "Anyone saying you are under 'digital arrest' (this is not a legal process)",
            "Orders to stay on video call and not tell family",
            "Demands to move money to a 'safe' or 'RBI verification' account",
        ],
        "what_to_do": "Disconnect immediately. No agency arrests or interrogates people over video calls or takes money to 'verify' it.",
    },
    {
        "icon": "🎣",
        "title": "Phishing (Fake Bank/KYC Messages)",
        "how": "Messages claim your account is blocked or KYC has expired and push you to a fake website that steals logins and OTPs.",
        "red_flags": [
            "Urgent threats: 'blocked in 24 hours'",
            "Links with odd domains like sbi-login.xyz",
            "Requests for OTP, PIN or password",
        ],
        "what_to_do": "Don't click. Open your bank's official app or type the website address yourself.",
    },
    {
        "icon": "📱",
        "title": "Malicious Apps (APK Scams)",
        "how": "You get a link to install an 'app' (bank update, RTO challan, KYC). It may read your SMS/OTPs or give attackers remote control of your phone.",
        "red_flags": [
            "Links ending in .apk",
            "Requests to enable 'unknown sources' or accessibility access",
            "Asks to install AnyDesk/TeamViewer-type tools",
        ],
        "what_to_do": "Install apps only from Google Play or the App Store. If you installed one, switch on airplane mode, uninstall it, and call your bank.",
    },
    {
        "icon": "🎁",
        "title": "Lottery & Prize Scams",
        "how": "You 'won' a prize but must pay a fee or share bank details first.",
        "red_flags": [
            "You never entered a contest",
            "Fees required to claim the prize",
            "Pressure to act fast",
        ],
        "what_to_do": "Ignore and block. Real prizes never require upfront payment.",
    },
]

EMERGENCY_STEPS = [
    "📞 Call the National Cyber Crime Helpline: 1930 (as fast as possible, since early reporting helps freeze money)",
    "🌐 File a complaint at cybercrime.gov.in",
    "🏦 Call your bank to block cards, UPI and net banking",
    "📵 Stop all contact with the scammer, and keep screenshots as evidence",
]