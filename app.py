
import streamlit as st
from transformers import pipeline
import re
from urllib.parse import urlparse
from trusted_domains import TRUSTED_DOMAINS

# Load HuggingFace phishing detection model
classifier = pipeline("text-classification", model="ml6team/bert-base-uncased-finetuned-phishing")

def extract_links(text):
    return re.findall(r'https?://\S+', text)

def is_suspicious_url(url):
    try:
        domain = urlparse(url).netloc.lower()
        return not any(trusted in domain for trusted in TRUSTED_DOMAINS)
    except:
        return True

def calculate_scam_score(message, suspicious_links):
    score = 0
    if "kyc" in message.lower(): score += 30
    if "urgent" in message.lower() or "suspend" in message.lower(): score += 20
    if suspicious_links: score += 30
    if "congratulations" in message.lower(): score += 10
    return min(score, 100)

st.set_page_config(page_title="FraudLens AI", layout="centered")
st.title("🔍 FraudLens AI – Scam Message Detector")

message = st.text_area("Paste a suspicious message below:", height=200)
if st.button("Analyze"):
    if not message.strip():
        st.warning("Please enter a message to analyze.")
    else:
        result = classifier(message)[0]
        prediction = result["label"]
        score = result["score"]

        links = extract_links(message)
        suspicious_links = [link for link in links if is_suspicious_url(link)]
        scam_score = calculate_scam_score(message, suspicious_links)

        st.subheader("📊 Analysis Result")
        st.markdown(f"**🧠 AI Prediction:** `{prediction}` ({score * 100:.2f}%)")
        st.markdown(f"**🚩 Scam Risk Score:** `{scam_score}/100`")
        
        if links:
            st.subheader("🔗 Links Found")
            for link in links:
                if link in suspicious_links:
                    st.error(f"⚠️ Suspicious: {link}")
                else:
                    st.success(f"✅ Trusted: {link}")
        else:
            st.info("No links found in the message.")
