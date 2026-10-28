import streamlit as st
import requests
import socket
import re
import whois
import folium
from streamlit_folium import st_folium
import pandas as pd
from datetime import datetime
import ipaddress

st.set_page_config(
    page_title="IP Geolocation & WHOIS Tracer",
    page_icon="🌐",
    layout="wide",
    initial_sidebar_state="expanded"
)

st.markdown("""
<style>
    .metric-card {
        background-color: #f8f9fa;
        border-radius: 8px;
        padding: 16px;
        border: 1px solid #e9ecef;
        margin-bottom: 12px;
    }
</style>
""", unsafe_allow_html=True)


def clean_target_input(raw_input: str) -> str:
    cleaned = raw_input.strip()
    cleaned = re.sub(r"^https?://", "", cleaned, flags=re.IGNORECASE)
    cleaned = cleaned.split("/")[0]
    cleaned = cleaned.split("?")[0]
    cleaned = cleaned.split("#")[0]
    cleaned = cleaned.split(":")[0]
    return cleaned


def is_private_or_reserved_ip(ip_str: str) -> tuple[bool, str]:
    try:
        ip_obj = ipaddress.ip_address(ip_str)
        if ip_obj.is_private:
            return True, "Private / LAN address (RFC 1918)"
        if ip_obj.is_loopback:
            return True, "Loopback address (localhost)"
        if ip_obj.is_reserved:
            return True, "Reserved IETF / IANA address"
        if ip_obj.is_link_local:
            return True, "Link-local address (RFC 3927)"
        return False, ""
    except ValueError:
        return False, ""


def resolve_to_ip(target: str) -> tuple[str, bool]:
    ipv4_pattern = r"^(\d{1,3}\.){3}\d{1,3}$"
    if re.match(ipv4_pattern, target):
        return target, False
    try:
        resolved_ip = socket.gethostbyname(target)
        return resolved_ip, True
    except socket.gaierror as e:
        raise ValueError(f"Could not resolve domain '{target}' to an IP address: {e}")


def fetch_ip_metadata(ip_address: str) -> dict:
    fields = "status,message,country,countryCode,region,regionName,city,zip,lat,lon,timezone,isp,org,as,query"
    url = f"http://ip-api.com/json/{ip_address}?fields={fields}"
    response = requests.get(url, timeout=8)
    if response.status_code != 200:
        raise ConnectionError(f"HTTP {response.status_code} received from Geolocation endpoint.")
    data = response.json()
    if data.get("status") != "success":
        raise ValueError(data.get("message", "Failed to retrieve IP metadata."))
    return data


def fetch_whois_metadata(domain: str) -> dict:
    try:
        w = whois.whois(domain)
        def normalize_entry(val):
            if isinstance(val, list):
                val = val[0]
            if isinstance(val, datetime):
                return val.strftime("%Y-%m-%d %H:%M:%S UTC")
            return str(val) if val else "N/A"

        return {
            "Registrar": normalize_entry(w.get("registrar")),
            "Creation Date": normalize_entry(w.get("creation_date")),
            "Expiration Date": normalize_entry(w.get("expiration_date")),
            "Updated Date": normalize_entry(w.get("updated_date")),
            "Registrant / Org": normalize_entry(w.get("org") or w.get("name")),
            "Name Servers": ", ".join(w.get("nameservers", [])) if isinstance(w.get("nameservers"), list) else normalize_entry(w.get("nameservers")),
            "Raw WHOIS": w
        }
    except Exception as e:
        return {"error": str(e)}


if "trace_results" not in st.session_state:
    st.session_state.trace_results = None

with st.sidebar:
    st.title("🌐 Network Tracer")
    st.caption("Investigate IPs, Domain Infrastructure & ASNs")
    st.markdown("---")
    
    target_input = st.text_input(
        "Domain or IPv4 Target",
        value="github.com",
        help="Enter an IP address (e.g. 8.8.8.8) or host (e.g. github.com)"
    )
    
    run_trace = st.button("Trace Network", type="primary", use_container_width=True)

st.title("IP Geolocation & WHOIS Network Tracer")
st.caption("Query open geolocation endpoints and WHOIS registries without API keys.")

if run_trace and target_input:
    with st.spinner("Analyzing target infrastructure..."):
        clean_target = clean_target_input(target_input)
        if not clean_target:
            st.error("Please provide a valid domain or IP address.")
            st.session_state.trace_results = None
        else:
            try:
                target_ip, is_domain = resolve_to_ip(clean_target)
                is_private, private_reason = is_private_or_reserved_ip(target_ip)
                
                if is_private:
                    st.session_state.trace_results = {
                        "is_private": True,
                        "private_reason": private_reason,
                        "clean_target": clean_target,
                        "target_ip": target_ip,
                        "is_domain": is_domain
                    }
                else:
                    geo_data = fetch_ip_metadata(target_ip)
                    whois_data = fetch_whois_metadata(clean_target) if is_domain else None
                    
                    st.session_state.trace_results = {
                        "is_private": False,
                        "clean_target": clean_target,
                        "target_ip": target_ip,
                        "is_domain": is_domain,
                        "geo_data": geo_data,
                        "whois_data": whois_data
                    }
            except Exception as err:
                st.error(f"Error during trace execution: {err}")
                st.session_state.trace_results = None

if st.session_state.trace_results:
    res = st.session_state.trace_results
    
    if res.get("is_private"):
        st.warning(f"⚠️ **Private / Local Range IP Detected: `{res['target_ip']}`**")
        st.info(
            f"**Classification:** {res['private_reason']}\n\n"
            "Private IP addresses (such as `10.x.x.x`, `172.16-31.x.x`, `192.168.x.x`, and loopback `127.0.0.1`) "
            "belong to internal local networks and are non-routable across the public internet. "
            "Public geolocation servers and WHOIS registries do not hold location coordinates or routing data for local addresses."
        )
    else:
        clean_target = res["clean_target"]
        target_ip = res["target_ip"]
        is_domain = res["is_domain"]
        geo_data = res["geo_data"]
        whois_data = res["whois_data"]

        m1, m2, m3, m4 = st.columns(4)
        m1.metric("Resolved IP", geo_data.get("query", target_ip))
        m2.metric("Target Type", "Domain Host" if is_domain else "Raw IP Address")
        m3.metric("Country", f"{geo_data.get('country', 'N/A')} ({geo_data.get('countryCode', '')})")
        m4.metric("Coordinates", f"{geo_data.get('lat', 0.0):.4f}, {geo_data.get('lon', 0.0):.4f}")

        st.markdown("---")

        col_left, col_right = st.columns([1, 1], gap="large")

        with col_left:
            st.subheader("📍 Interactive Geolocation Map")
            lat = geo_data.get("lat")
            lon = geo_data.get("lon")

            if lat is not None and lon is not None:
                m = folium.Map(location=[lat, lon], zoom_start=9, tiles="OpenStreetMap")
                
                popup_text = f"""
                <b>Target:</b> {clean_target}<br>
                <b>IP:</b> {target_ip}<br>
                <b>City:</b> {geo_data.get('city')}, {geo_data.get('regionName')}<br>
                <b>ISP:</b> {geo_data.get('isp')}
                """
                
                folium.Marker(
                    [lat, lon],
                    popup=folium.Popup(popup_text, max_width=300),
                    tooltip=f"{clean_target} ({target_ip})",
                    icon=folium.Icon(color="red", icon="info-sign")
                ).add_to(m)

                st_folium(m, height=420, use_container_width=True, returned_objects=[])
            else:
                st.warning("Coordinates not available for this target.")

        with col_right:
            st.subheader("🏢 Network & Routing Intelligence")
            routing_metrics = [
                ("Autonomous System (ASN)", geo_data.get("as", "N/A")),
                ("Internet Service Provider (ISP)", geo_data.get("isp", "N/A")),
                ("Organization", geo_data.get("org", "N/A")),
                ("Location", f"{geo_data.get('city', 'N/A')}, {geo_data.get('regionName', 'N/A')} ({geo_data.get('zip', 'N/A')})"),
                ("Timezone", geo_data.get("timezone", "N/A")),
            ]
            routing_df = pd.DataFrame(routing_metrics, columns=["Attribute", "Value"])
            st.dataframe(routing_df, hide_index=True, use_container_width=True)

        st.markdown("---")

        st.subheader("📋 Domain Ownership & WHOIS Record")
        if is_domain:
            if whois_data and "error" not in whois_data:
                w1, w2, w3 = st.columns(3)
                with w1:
                    st.markdown(f"**Registrar:** {whois_data.get('Registrar')}")
                    st.markdown(f"**Organization:** {whois_data.get('Registrant / Org')}")
                with w2:
                    st.markdown(f"**Created:** {whois_data.get('Creation Date')}")
                    st.markdown(f"**Updated:** {whois_data.get('Updated Date')}")
                with w3:
                    st.markdown(f"**Expires:** {whois_data.get('Expiration Date')}")
                    st.markdown(f"**Nameservers:** {whois_data.get('Name Servers')}")
            else:
                st.warning(f"Could not retrieve complete WHOIS record: {whois_data.get('error', 'Unknown error')}")
        else:
            st.info("WHOIS domain queries are disabled when analyzing raw IPv4 addresses directly.")

        with st.expander("🔍 View Raw JSON Response"):
            st.json({
                "target": clean_target,
                "ip_api_response": geo_data,
                "whois_record": whois_data.get("Raw WHOIS") if whois_data and "Raw WHOIS" in whois_data else whois_data
            })
else:
    st.info("Enter a domain or IP address in the sidebar and click **Trace Network** to begin.")
