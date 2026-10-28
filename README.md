# 🌐 IP Geolocation & WHOIS Network Tracer

A Python and Streamlit web application that resolves domain names to IP addresses, performs IP-to-location lookups, extracts Autonomous System Numbers (ASN) and routing details, queries domain WHOIS records, and visualizes network endpoints on an interactive Folium map.

---

## 🚀 Features

- **No API Keys Required:** Leverages public endpoints (`http://ip-api.com/json/`) and standard system DNS resolution.
- **Flexible Target Resolution:** Handles raw IPv4 targets (`1.1.1.1`) or domain names (`github.com`), stripping protocols and subpaths automatically.
- **Routing & Autonomous System Metadata:** Surfaces ASN, ISP, Organization name, City, Region, Zip, and Timezone.
- **Interactive Mapping:** Embeds a Leaflet-based map pin using `folium` and `streamlit-folium`.
- **WHOIS Inspection:** Queries domain creation, expiration, registrar, and nameservers using `python-whois`.
- **Responsive Layout:** 2-column dashboard featuring summary metric cards, structured data tables, and an expandable raw JSON viewer.

---

## 🛠️ Local Development Setup

### 1. Set up a virtual environment
```bash
# macOS/Linux
python3 -m venv venv
source venv/bin/activate

# Windows
python -m venv venv
venv\Scripts\activate
```

### 2. Install dependencies
```bash
pip install -r requirements.txt
```

### 3. Run the Streamlit application
```bash
streamlit run app.py
```
Open your browser at `http://localhost:8501`.

---

## ☁️ Deploying to Streamlit Community Cloud

1. Create a new GitHub repository.
2. Unzip this package and push `app.py`, `requirements.txt`, and `README.md` directly to your GitHub repository root.
3. Go to [share.streamlit.io](https://share.streamlit.io/).
4. Sign in with GitHub and click **"New app"**.
5. Select your repository, choose the branch (`main`), and set the main file path to `app.py`.
6. Click **"Deploy!"**.
