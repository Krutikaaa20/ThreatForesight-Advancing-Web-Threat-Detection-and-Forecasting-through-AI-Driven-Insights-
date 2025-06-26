import streamlit as st
import pandas as pd
import requests
import whois
import joblib
import time
import smtplib
import os
import re
import tldextract
import urllib.parse
from datetime import datetime
import matplotlib.pyplot as plt
import numpy as np

# Load ML Model & Vectorizer
model = joblib.load(r"c:/Users/kruti/Downloads/phishing_model (4).pkl")
vectorizer = joblib.load(r"C:/Users/kruti/Downloads/tfidf_vectorizer.pkl")

# Extract domain from URL
def extract_domain(url):
    ext = tldextract.extract(url)
    return f"{ext.domain}.{ext.suffix}"

# ML-Based Phishing Detection
def detect_phishing_ml(url):
    input_vector = vectorizer.transform([url])
    prediction = model.predict(input_vector)[0]
    return "Phishing" if prediction == 1 else "Legitimate"

# Fetch latest phishing URLs
def get_live_phishing_urls():
    try:
        response = requests.get("https://openphish.com/feed.txt")
        return response.text.split("\n")[:10]
    except:
        return ["Failed to fetch phishing URLs"]

# Get WHOIS domain info
def get_domain_info(url):
    domain = extract_domain(url)
    try:
        data = whois.whois(domain)
        return {
            "Domain": data.domain_name,
            "Created": data.creation_date,
            "Expires": data.expiration_date,
            "Registrar": data.registrar
        }
    except:
        return {"Error": "WHOIS lookup failed"}

# Get IP location details
def get_ip_location(url):
    domain = extract_domain(url)
    try:
        response = requests.get(f"http://ip-api.com/json/{domain}")
        data = response.json()
        return {
            "Country": data.get("country", "Unknown"),
            "City": data.get("city", "Unknown"),
            "ISP": data.get("isp", "Unknown"),
            "IP": data.get("query", "Unknown")
        }
    except:
        return {"Error": "GeoIP lookup failed"}

# Send email alert
def send_alert(email, url):
    sender_email = os.getenv("EMAIL_USER")  # Store in environment variable
    sender_password = os.getenv("EMAIL_PASS")
    
    if not sender_email or not sender_password:
        return "Email credentials not set."

    try:
        server = smtplib.SMTP("smtp.gmail.com", 587)
        server.starttls()
        server.login(sender_email, sender_password)
        message = f"Subject: ⚠️ Phishing Alert\n\nThe URL {url} has been flagged as phishing."
        server.sendmail(sender_email, email, message)
        server.quit()
        return "Email Alert Sent!"
    except Exception as e:
        return f"Email Sending Failed: {e}"

# Streamlit UI
st.set_page_config(layout="wide")
st.title("🔒 Real-Time Phishing Detection Dashboard")

url = st.text_input("Enter a URL to check:")
if st.button("Check URL"):
    if url:
        result = detect_phishing_ml(url)
        timestamp = time.strftime('%Y-%m-%d %H:%M:%S')
        st.session_state.setdefault('phishing_data', []).append({"URL": url, "Status": result, "Timestamp": timestamp})
        st.success(f"URL classified as: {result}")
        
        # WHOIS Lookup
        st.write("### WHOIS Information")
        st.json(get_domain_info(url))

        # GeoIP Lookup
        st.write("### GeoIP Tracking")
        st.json(get_ip_location(url))

        # Send Alert if Phishing
        if result == "Phishing":
            email = st.text_input("Enter your email for alerts:")
            if st.button("Send Alert"):
                alert_status = send_alert(email, url)
                st.success(alert_status)

st.subheader("🚨 Latest Reported Phishing URLs")
st.write(get_live_phishing_urls())

# Show phishing data
phishing_df = pd.DataFrame(st.session_state.get('phishing_data', []))
if not phishing_df.empty:
    phishing_count = phishing_df[phishing_df['Status'] == "Phishing"].shape[0]
    safe_count = phishing_df[phishing_df['Status'] == "Legitimate"].shape[0]

    st.metric("Total Phishing URLs", phishing_count)
    st.metric("Total Legitimate URLs", safe_count)

    # Chart Fix
    fig, ax = plt.subplots()
    ax.bar(["Phishing", "Legitimate"], [phishing_count, safe_count], color=['red', 'green'])
    st.pyplot(fig)
