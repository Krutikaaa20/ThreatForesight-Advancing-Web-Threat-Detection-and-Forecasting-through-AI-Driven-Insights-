import streamlit as st
import pandas as pd
import time
import random
import matplotlib.pyplot as plt
import requests
import whois
from ipwhois import IPWhois

# Simulated phishing detection function
def detect_phishing(url):
    phishing_keywords = ['login', 'bank', 'verify', 'account', 'secure', 'update']
    if any(keyword in url.lower() for keyword in phishing_keywords):
        return "Phishing"
    return "Safe"

# Get WHOIS information
def get_whois_info(url):
    try:
        domain_info = whois.whois(url)
        return domain_info.domain_name, domain_info.creation_date, domain_info.expiration_date
    except:
        return "N/A", "N/A", "N/A"

# Get Geo-location of IP
def get_geo_location(ip):
    try:
        obj = IPWhois(ip)
        res = obj.lookup_rdap()
        return res.get('asn_country_code', 'N/A')
    except:
        return "N/A"

# Fetch OpenPhish live threats
def fetch_openphish():
    try:
        response = requests.get("https://openphish.com/feed.txt")
        if response.status_code == 200:
            return response.text.split('\n')[:10]  # Fetch top 10 threats
    except:
        return []
    return []

# Initialize session state if not present
if 'phishing_data' not in st.session_state:
    st.session_state.phishing_data = []

if 'url_simulation' not in st.session_state:
    st.session_state.url_simulation = False

st.title("🔒 Real-Time Phishing Detection & Dashboard")

# URL input form
url = st.text_input("Enter a URL to check:")
if st.button("Check URL"):
    result = detect_phishing(url)
    timestamp = time.strftime('%Y-%m-%d %H:%M:%S')
    domain, creation, expiration = get_whois_info(url)
    st.session_state.phishing_data.append({
        "URL": url, "Status": result, "Timestamp": timestamp, "Domain": domain,
        "Creation Date": creation, "Expiration Date": expiration
    })
    st.success(f"URL classified as: {result}")

# Toggle for real-time URL simulation
st.session_state.url_simulation = st.checkbox("Enable Real-Time URL Simulation")
if st.session_state.url_simulation:
    simulated_urls = ["login-example.com", "secure-bank.net", "random-site.org", "update-password.io"]
    if random.random() < 0.3:  # 30% chance of new URL every refresh
        new_url = random.choice(simulated_urls)
        result = detect_phishing(new_url)
        timestamp = time.strftime('%Y-%m-%d %H:%M:%S')
        domain, creation, expiration = get_whois_info(new_url)
        st.session_state.phishing_data.append({
            "URL": new_url, "Status": result, "Timestamp": timestamp, "Domain": domain,
            "Creation Date": creation, "Expiration Date": expiration
        })

# Convert session state data to DataFrame
phishing_df = pd.DataFrame(st.session_state.phishing_data)

# Real-time dashboard
st.subheader("📊 Live Phishing Analysis")
st.dataframe(phishing_df)

# Statistics & Metrics
if not phishing_df.empty:
    phishing_count = phishing_df[phishing_df['Status'] == "Phishing"].shape[0]
    safe_count = phishing_df[phishing_df['Status'] == "Safe"].shape[0]
    
    st.metric("Total Phishing URLs", phishing_count)
    st.metric("Total Safe URLs", safe_count)
    
    # Bar chart visualization
    chart_data = pd.DataFrame({
        "Category": ["Phishing", "Safe"],
        "Count": [phishing_count, safe_count]
    })
    st.bar_chart(chart_data.set_index("Category"))
    
    # Line chart for trend over time
    phishing_df['Timestamp'] = pd.to_datetime(phishing_df['Timestamp'])
    phishing_trend = phishing_df.groupby(phishing_df['Timestamp'].dt.strftime('%H:%M:%S'))['Status'].value_counts().unstack().fillna(0)
    st.line_chart(phishing_trend)
    
    # Pie Chart
    fig, ax = plt.subplots()
    ax.pie([phishing_count, safe_count], labels=["Phishing", "Safe"], autopct='%1.1f%%', colors=['red', 'green'])
    ax.set_title("Phishing vs Safe URLs")
    st.pyplot(fig)
    
    # Threat Level Indicator
    threat_level = (phishing_count / max(1, len(phishing_df))) * 100  # Normalize threat level
    st.progress(int(threat_level))
    st.write(f"Threat Level: {int(threat_level)}%")

# OpenPhish Live Threat Feed
st.subheader("⚠️ Live OpenPhish Threats")
openphish_data = fetch_openphish()
if openphish_data:
    for threat in openphish_data:
        st.warning(threat)
else:
    st.write("No live threats available.")

# Auto-refresh every 5 seconds
st.experimental_rerun()