import numpy as np
import pandas as pd
import streamlit as st
import streamlit_authenticator as stauth

# Build credentials dictionary safely from secrets
credentials = {
    "usernames": {
        username: {
            "email": user_data["email"],
            "name": user_data["name"],
            "password": user_data["password"],
        }
        for username, user_data in st.secrets["credentials"]["usernames"].items()
    }
}

authenticator = stauth.Authenticate(
    credentials,
    st.secrets["cookie"]["name"],
    st.secrets["cookie"]["key"],
    st.secrets["cookie"]["expiry_days"],
    auto_hash=False,
)

try:
    authenticator.login()
except Exception as e:
    st.error(e)

if st.session_state.get("authentication_status") is False:
    st.error("Username/password is incorrect")
    st.stop()

if st.session_state.get("authentication_status") is None:
    st.warning("Please enter your username and password")
    st.stop()

authenticator.logout("Logout", "sidebar")

from snowflake.snowpark import Session
from datetime import datetime
from cryptography.hazmat.primitives import serialization
import uuid

@st.cache_resource(show_spinner=False)
def get_session():
    private_key = serialization.load_pem_private_key(
        st.secrets["snowflake"]["private_key"].encode(),
        password=None
    )

    connection_parameters = {
        "account": st.secrets["snowflake"]["account"],
        "user": st.secrets["snowflake"]["user"],
        "role": st.secrets["snowflake"]["role"],
        "warehouse": st.secrets["snowflake"]["warehouse"],
        "database": st.secrets["snowflake"]["database"],
        "schema": st.secrets["snowflake"]["schema"],
        "private_key": private_key,
        "client_session_keep_alive": True,  # Prevent token expiry on Streamlit Cloud
    }

    return Session.builder.configs(connection_parameters).create()

#session = get_session()

# ============================================================
# Helpers
# ============================================================
def format_url(url):
    """Add protocol to URL if missing."""
    if url is None or pd.isna(url):
        return None
    url = str(url).strip()
    if url == "":
        return None
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    return url


def parse_funding_amount(series: pd.Series) -> pd.Series:
    """Convert textual amount to numeric."""
    import re

    def _parse(x):
        if pd.isna(x):
            return np.nan

        s = str(x).strip().upper()
        if s in ("", "", "NONE", "N/A", "NA", "-"):
            return np.nan

        s = s.replace(",", "")
        for sym in ["$", "€", "£"]:
            s = s.replace(sym, "")

        multiplier = 1
        if s.endswith("B"):
            multiplier = 1_000_000_000
            s = s[:-1]
        elif s.endswith("M"):
            multiplier = 1_000_000
            s = s[:-1]
        elif s.endswith("K"):
            multiplier = 1_000
            s = s[:-1]

        s = "".join(re.findall(r"[0-9.]", s))
        return float(s) * multiplier if s else np.nan

    return series.apply(_parse)


# ============================================================
# Load data from Snowflake
# ============================================================
@st.cache_data(ttl=300)
def load_data(_session):
    # COMPANIES table
    companies = _session.sql("""
        SELECT
            company_id,
            company_name,
            website      AS website_url,   -- <== IMPORTANT FIX
            linkedin_url,
            category_group,
            status,
            employee_count
        FROM RISKINSIGHTSMEDIA_DB.ANALYTICS.COMPANIES
    """).to_pandas()

    # FUNDING_ROUNDS table
    funding = _session.sql("""
        SELECT
            round_id,
            company_id,
            company_name,
            stage_or_funding_round,
            amount_raised_total,
            lead_investor,
            website_url,
            linkedin_url,
            created_at,
            updated_at
        FROM RISKINSIGHTSMEDIA_DB.ANALYTICS.FUNDING_ROUNDS
    """).to_pandas()

    # Lowercase columns
    companies.columns = companies.columns.str.lower()
    funding.columns = funding.columns.str.lower()

    # Parse numeric funding
    if "amount_raised_total" in funding.columns:
        funding["amount_num"] = parse_funding_amount(funding["amount_raised_total"])
    else:
        funding["amount_num"] = np.nan

    # Parse created_at
    if "created_at" in funding.columns:
        funding["created_at_dt"] = pd.to_datetime(
            funding["created_at"], errors="coerce"
        )
    else:
        funding["created_at_dt"] = pd.NaT

    # Columns for merge
    merge_cols = [
        "company_id", "company_name", "website_url", "linkedin_url",
        "category_group", "status"
    ]
    merge_cols = [c for c in merge_cols if c in companies.columns]

    merged = funding.merge(
        companies[merge_cols],
        on="company_id",
        how="left",
        suffixes=("", "_company"),
    )

    return companies, funding, merged


def get_last_updated(_session):
    try:
        df = _session.sql("""
            SELECT MAX(updated_at) AS last_update
            FROM RISKINSIGHTSMEDIA_DB.ANALYTICS.FUNDING_ROUNDS
        """).to_pandas()

        if not df.empty and pd.notna(df.loc[0, "LAST_UPDATE"]):
            return str(df.loc[0, "LAST_UPDATE"])
    except Exception:
        pass
    return "Unknown"


# ============================================================
# Table viewer (Hides IDs + Renames Columns + No Download)
# ============================================================
def _clean_url(url):
    """Strip protocol and www for clean display while keeping the full URL for linking."""
    if url is None or pd.isna(url):
        return None
    s = str(url).strip()
    if not s:
        return None
    # Ensure full URL has protocol (for linking)
    full = s if s.startswith(("http://", "https://")) else "https://" + s
    # Clean display: strip https://, http://, www.
    display = s.replace("https://", "").replace("http://", "")
    if display.startswith("www."):
        display = display[4:]
    return full  # store full URL but display column shows clean version


def _display_url(url):
    """Return clean display text for a URL (no protocol or www)."""
    if url is None or pd.isna(url):
        return ""
    s = str(url).strip()
    s = s.replace("https://", "").replace("http://", "")
    if s.startswith("www."):
        s = s[4:]
    return s


def display_table(df: pd.DataFrame, table_name: str):

    # Hide ID columns + technical columns
    df = df.drop(
        columns=["company_id", "round_id", "created_at", "created_at_dt"],
        errors="ignore"
    ).copy()

    # Rename columns for display only
    rename_map = {
        "company_name": "Company",
        "stage_or_funding_round": "Funding",
        "amount_raised_total": "Amount Raised Total",
        "lead_investor": "Lead Investor",
        "website_url": "Website",
        "linkedin_url": "LinkedIn",
        "category_group": "Market Segment",
        "status": "Status",
        "employee_count": "Employee Count",
        "updated_at": "Last Edited At",
        "updated_by": "Last Edited By",
    }

    df.rename(
        columns={k: v for k, v in rename_map.items() if k in df.columns},
        inplace=True
    )

    # Build column config for URL columns (clean display text + clickable)
    col_config = {}
    if "Website" in df.columns:
        col_config["Website"] = st.column_config.LinkColumn(
            "Website",
            display_text=r"https?://(?:www\.)?(.+)"
        )
    if "LinkedIn" in df.columns:
        col_config["LinkedIn"] = st.column_config.LinkColumn(
            "LinkedIn",
            display_text=r"https?://(?:www\.)?(.+)"
        )

    # Search field
    search_term = st.text_input(
        f"Search in {table_name}:",
        placeholder="Type to search...",
        key=f"search_{table_name}"
    )

    if search_term:
        string_cols = df.select_dtypes(include="object").columns
        mask = (
            df[string_cols].astype(str)
            .apply(lambda col: col.str.contains(search_term, case=False, na=False))
            .any(axis=1)
        )
        view_df = df[mask]
        st.caption(f"{len(view_df)} matching rows")
    else:
        view_df = df
        st.caption(f"{len(view_df)} rows")

    # Show table (no download button)
    st.dataframe(view_df, width="stretch", hide_index=True, column_config=col_config)


# ============================================================
# PAGE CONFIG
# ============================================================
st.set_page_config(page_title="Funding Intelligence Dashboard", layout="wide")

st.title("Funding Intelligence Dashboard")
st.caption("Explore funding rounds, investors, categories, and companies from Snowflake.")

session = get_session()
companies_df, funding_df, merged_df = load_data(session)

if funding_df.empty or companies_df.empty:
    st.error("No data available in Snowflake.")
    st.stop()


# ============================================================
# Sidebar Filters
# ============================================================
st.sidebar.header("Filters")

stage_options = sorted(merged_df["stage_or_funding_round"].dropna().astype(str).unique())
selected_stages = st.sidebar.multiselect("Funding Stage / Round", stage_options)

investor_options = sorted(merged_df["lead_investor"].dropna().astype(str).unique())
selected_investors = st.sidebar.multiselect("Lead Investor", investor_options)

category_options = sorted(merged_df["category_group"].dropna().astype(str).unique()) \
    if "category_group" in merged_df.columns else []
selected_categories = st.sidebar.multiselect("Market Segment", category_options)

status_options = sorted(merged_df["status"].dropna().astype(str).unique()) \
    if "status" in merged_df.columns else []
selected_status = st.sidebar.multiselect("Company Status", status_options)

st.sidebar.markdown("---")
selected_table = st.sidebar.selectbox(
    "Select table to view:",
    ["Both Tables", "funding_rounds", "companies"],
    index=2
)

st.sidebar.markdown("---")
st.sidebar.caption(f"Last updated: **{get_last_updated(session)}**")


# ============================================================
# Apply Filters
# ============================================================
filtered = merged_df.copy()

if selected_stages:
    filtered = filtered[filtered["stage_or_funding_round"].isin(selected_stages)]
if selected_investors:
    filtered = filtered[filtered["lead_investor"].isin(selected_investors)]
if selected_categories and "category_group" in filtered.columns:
    filtered = filtered[filtered["category_group"].isin(selected_categories)]
if selected_status and "status" in filtered.columns:
    filtered = filtered[filtered["status"].isin(selected_status)]


# ============================================================
# KPIs
# ============================================================
st.subheader("Key KPIs (Filtered)")

total_funding = filtered["amount_num"].sum(skipna=True)
total_rounds = filtered["round_id"].nunique() if "round_id" in filtered.columns else 0
unique_companies = filtered["company_id"].nunique() if "company_id" in filtered.columns else 0

top_investor = (
    filtered.groupby("lead_investor")["amount_num"]
    .sum()
    .sort_values(ascending=False)
    .index[0]
    if not filtered.empty and filtered["lead_investor"].notna().any()
    else "N/A"
)

top_company = (
    filtered.groupby("company_name")["amount_num"]
    .sum()
    .sort_values(ascending=False)
    .index[0]
    if not filtered.empty and filtered["company_name"].notna().any()
    else "N/A"
)

k1, k2, k3, k4, k5 = st.columns(5)
k1.metric("Total Funding", f"${total_funding:,.0f}" if total_funding else "N/A")
k2.metric("Funding Rounds", int(total_rounds))
k3.metric("Unique Companies", int(unique_companies))
k4.metric("Top Investor (by $)", top_investor)
k5.metric("Top Funded Company", top_company)

st.markdown("---")


# Check if logged-in user is admin
_current_user = (st.session_state.get("username") or "").lower()
is_admin = _current_user == "jeremy"
is_contributor = _current_user == "jitesh"

# ============================================================
# Tabs
# ============================================================
tab_list = ["Rounds Analysis", "Investors", "Company Explorer"]
if is_admin:
    tab_list.append("Admin Panel")
elif is_contributor:
    tab_list.append("Contributor Panel")

tabs = st.tabs(tab_list)
tab1 = tabs[0]
tab2 = tabs[1]
tab3 = tabs[2]
tab4 = tabs[3] if (is_admin or is_contributor) else None


# -------------------------
# Tab 1: Rounds Analysis
# -------------------------
with tab1:
    st.markdown("### Rounds Analysis")

    c1, c2 = st.columns(2)

    if "stage_or_funding_round" in filtered.columns:
        with c1:
            st.markdown("**Funding totals by round**")
            totals = (
                filtered.groupby("stage_or_funding_round")["amount_num"]
                .sum()
                .sort_values(ascending=False)
            )
            st.bar_chart(totals)

        with c2:
            st.markdown("**Company count per round**")
            counts = (
                filtered.groupby("stage_or_funding_round")["company_id"]
                .nunique()
                .sort_values(ascending=False)
            )
            st.bar_chart(counts)


# -------------------------
# Tab 2: Investors
# -------------------------
with tab2:
    st.markdown("### Investors")

    c3, c4 = st.columns(2)

    with c3:
        st.markdown("**Top investors by funding**")
        inv_fund = (
            filtered.groupby("lead_investor")["amount_num"]
            .sum()
            .sort_values(ascending=False)
            .head(20)
        )
        st.bar_chart(inv_fund)

    with c4:
        st.markdown("**Top investors by deal count**")
        inv_count = (
            filtered.groupby("lead_investor")["round_id"]
            .nunique()
            .sort_values(ascending=False)
            .head(20)
        )
        st.bar_chart(inv_count)

    st.markdown("---")

    st.markdown("**Top funded companies**")
    comp_fund = (
        filtered.groupby("company_name")["amount_num"]
        .sum()
        .sort_values(ascending=False)
        .head(20)
    )
    st.bar_chart(comp_fund)


# -------------------------
# Tab 3: Company Explorer
# -------------------------
with tab3:
    st.markdown("### Company Explorer")

    group_cols = ["company_id", "company_name", "website_url", "linkedin_url"]
    if "category_group" in filtered.columns:
        group_cols.append("category_group")
    if "status" in filtered.columns:
        group_cols.append("status")

    company_metrics = (
        filtered.groupby(group_cols, dropna=False)
        .agg(total_funding=("amount_num", "sum"))
        .reset_index()
    )

    company_metrics = company_metrics.sort_values(by="total_funding", ascending=False)
    top_companies = company_metrics.head(25)

    for _, row in top_companies.iterrows():
        with st.container(border=True):

            st.markdown(f"#### {row['company_name']}")

            detail_list = []
            if "category_group" in row and pd.notna(row["category_group"]):
                detail_list.append(f"Market Segment: {row['category_group']}")
            if "status" in row and pd.notna(row["status"]):
                detail_list.append(f"Status: {row['status']}")

            if detail_list:
                st.markdown(" • ".join(detail_list))

            cols = st.columns([1, 3])

            with cols[0]:
                website = format_url(row.get("website_url"))
                linkedin = format_url(row.get("linkedin_url"))

                if website:
                    st.link_button("Website", website, width="stretch")
                if linkedin:
                    st.link_button("LinkedIn", linkedin, width="stretch")

            with cols[1]:
                tf = (
                    f"${row['total_funding']:,.0f}"
                    if pd.notna(row["total_funding"])
                    else "N/A"
                )
                st.markdown("**Funding Summary**")
                st.write(f"- Total funding: {tf}")


# ============================================================
# Data Tables
# ============================================================
st.markdown("---")
st.subheader("Data Tables")

allowed_round_ids = filtered["round_id"].dropna().unique() if "round_id" in filtered.columns else []
allowed_company_ids = filtered["company_id"].dropna().unique() if "company_id" in filtered.columns else []

funding_filtered = funding_df[funding_df["round_id"].isin(allowed_round_ids)]
companies_filtered = companies_df[companies_df["company_id"].isin(allowed_company_ids)]

if selected_table == "Both Tables":
    st.markdown("### Funding Rounds Table")
    display_table(funding_filtered, "funding_rounds")

    st.markdown("### Companies Table")
    display_table(companies_filtered, "companies")

elif selected_table == "funding_rounds":
    display_table(funding_filtered, "funding_rounds")

elif selected_table == "companies":
    display_table(companies_filtered, "companies")

st.caption("Dashboard loads live data from Snowflake.")


# ============================================================
# Admin Panel (Jeremy only — Direct Edit)
# ============================================================
if is_admin and tab4 is not None:
    with tab4:
        st.markdown("### 🔒 Admin Panel")
        st.caption("Only you can see this tab. Use the forms below to manage data in Snowflake.")

        admin_tab1, admin_tab2, admin_tab3, admin_tab4 = st.tabs([
            "➕ Add Company",
            "✏️ Update Company",
            "💰 Log Funding Round",
            "📋 Review Suggestions"
        ])

        # -------------------------
        # Admin Sub-Tab 1: Add Company
        # -------------------------
        with admin_tab1:
            st.markdown("#### Add a New Company")
            MARKET_SEGMENTS = [
                "",
                "Cloud & Application Security",
                "Data Security & AI Security",
                "Endpoint & IoT/OT Security",
                "Identity",
                "Network & Infrastructure Security",
                "Risk & Compliance",
                "Security Awareness & Training",
                "Security Operations",
                "Security Services",
            ]

            CATEGORIES = [
                "",
                "API Security", "Access Management (AM)", "Anomaly Detection (IoT/OT)",
                "Anti-phishing and Simulated Phishing", "Application Detection & Response (ADR)",
                "Application Security Orchestration and Correlation (ASOC)",
                "Application Security Posture Management (ASPM)",
                "Application Security Testing (AST)", "Attack Surface Management (ASM)",
                "Automated Penetration Testing", "Automated Security Control Assessment (ASCA)",
                "Backup and Recovery", "Bot Detection & Mitigation",
                "Breach and Attack Simulation (BAS)", "Cloud Access Security Broker (CASB)",
                "Cloud Detection & Response (CDR)", "Cloud IAM", "Cloud Identity Federation",
                "Cloud Infrastructure Entitlements Management (CIEM)",
                "Cloud Native Application Protection Platforms (CNAPP)",
                "Cloud Security Posture Management (CSPM)",
                "Cloud Workload Protection Platforms (CWPP)", "Compliance Management",
                "Container Security", "Continuous Threat Exposure Management (CTEM)",
                "Customer Identity", "Cyber Asset Attack Surface Management (CAASM)",
                "Cyber Insurance", "Cyber Range", "Cyber Risk Quantification",
                "Cybersecurity Education & Training", "DDoS Mitigation",
                "Data Loss Prevention (DLP)", "Data Security Posture Management (DSPM)",
                "Deception Platform", "Dynamic Application Security Testing (DAST)",
                "Email Security Software", "Encryption Key Management System (EKMS)",
                "Endpoint Detection and Response (EDR)", "Endpoint Protection Platform (EPP)",
                "Enterprise Browser Security", "Enterprise Email Security",
                "Extended Detection and Response (XDR)",
                "External Attack Surface Management (EASM)",
                "Forensic and Incident Response", "Fraud Prevention",
                "Fraud and Financial Crime Protection",
                "Governance, Risk, and Compliance (GRC)",
                "Host-Based Intrusion Detection Systems (HIDS)", "Human Risk Management",
                "Identity Governance and Administration (IGA)",
                "Identity Threat and Detection Response (ITDR)", "Identity Verification",
                "Identity and Access Management (IAM)", "Incident Response",
                "Industrial Controls Systems (ICS) Security", "Industrial IoT Security",
                "Insider Risk Management (IRM)", "Integrated Cloud Email Security (ICES)",
                "Intrusion Detection System (IDS)",
                "Intrusion Detection and Prevention Systems (IDPS)", "IoT Security",
                "Managed Detection and Response (MDR)", "Managed Security Services",
                "Mobile Application Security Testing", "Mobile Data Protection (MDP)",
                "Mobile Device Management (MDM)", "Mobile Threat Defense",
                "Network Access Control (NAC)", "Network Detection and Response (NDR)",
                "Network-Based Intrusion Detection Systems (NIDS)",
                "Operational Technology (OT) Security", "Password Management",
                "Patch Management", "Penetration Testing", "Privacy",
                "Privilege Elevation & Delegation Management (PEDM)",
                "Privileged Access Management (PAM)",
                "Privileged Account & Session Management (PASM)",
                "Privileged Identity Management (PIM)",
                "Risk Management & Compliance", "Risk-Based Vulnerability Management (RBVM)",
                "Runtime Application Self-Protection (RASP)",
                "SaaS Security Posture Management (SSPM)",
                "Secure Access Service Edge (SASE)", "Secure Collaboration and Messaging",
                "Secure Remote Access", "Secure Web Gateway (SWG)",
                "Security Awareness Computer-Based Training (SACBT)",
                "Security Awareness Training (SAT)",
                "Security Information and Event Management (SIEM)",
                "Security Orchestration and Automated Response (SOAR)",
                "Security Service Edge (SSE)", "Single Sign-On (SSO)",
                "Software Composition Analysis (SCA)", "Software Supply Chain Security",
                "Third-Party Risk Management (TPRM)", "Unified Threat Management (UTM)",
                "VPN Firewalls", "Vendor Risk Management", "Virtual Private Networks (VPNs)",
                "Vulnerability Assessment", "Vulnerability Management (IoT/OT)",
                "Vulnerability Management (VM)", "Vulnerability Risk Management (VRM)",
                "Web Application Firewall (WAF)",
                "Web Application and API Protection (WAAP)", "Wireless Security",
                "Zero Trust Edge Solutions (ZTE)", "Zero Trust Network Access (ZTNA)",
            ]

            with st.form("add_company_form"):
                new_name        = st.text_input("Company Name *", placeholder="e.g. Acme Corp")
                new_website     = st.text_input("Website", placeholder="e.g. https://acme.com")
                new_linkedin    = st.text_input("LinkedIn URL", placeholder="e.g. https://linkedin.com/company/acme")
                new_segment     = st.selectbox("Market Segment", MARKET_SEGMENTS)
                new_category    = st.selectbox("Category", CATEGORIES)
                new_status      = st.selectbox("Status", ["", "Active", "Acquired", "Closed", "IPO", "Unknown"])
                new_employees   = st.text_input("Employee Count", placeholder="e.g. 50, 200-500")

                submitted = st.form_submit_button("Add Company ✅")
                if submitted:
                    if not new_name.strip():
                        st.error("Company Name is required.")
                    else:
                        try:
                            session.sql(f"USE WAREHOUSE {st.secrets['snowflake']['warehouse']}").collect()
                            new_company_id = str(uuid.uuid4())
                            now_str = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")

                            def _q(val):
                                """Return SQL-quoted string or NULL."""
                                if val is None or str(val).strip() == "":
                                    return "NULL"
                                return "'" + str(val).replace("'", "''") + "'"

                            sql = f"""
                                INSERT INTO RISKINSIGHTSMEDIA_DB.ANALYTICS.COMPANIES
                                (COMPANY_ID, COMPANY_NAME, WEBSITE, LINKEDIN_URL,
                                 CATEGORY_GROUP, STATUS, EMPLOYEE_COUNT,
                                 CREATED_AT, UPDATED_AT, CREATED_BY, UPDATED_BY)
                                VALUES (
                                    {_q(new_company_id)},
                                    {_q(new_name.strip())},
                                    {_q(new_website.strip())},
                                    {_q(new_linkedin.strip())},
                                    {_q(new_category)},
                                    {_q(new_status)},
                                    {_q(new_employees.strip())},
                                    TO_TIMESTAMP_NTZ({_q(now_str)}),
                                    TO_TIMESTAMP_NTZ({_q(now_str)}),
                                    {_q(_current_user)},
                                    {_q(_current_user)}
                                )
                            """
                            session.sql(sql).collect()
                            st.success(f"✅ Company '{new_name}' added successfully!")
                            st.cache_data.clear()
                            st.rerun()
                        except Exception as e:
                            st.error(f"❌ Error adding company: {e}")


        # -------------------------
        # Admin Sub-Tab 2: Update Company
        # -------------------------
        with admin_tab2:
            st.markdown("#### Update an Existing Company")
            company_options = companies_df[["company_id", "company_name"]].dropna(subset=["company_name"])
            company_map = dict(zip(company_options["company_name"], company_options["company_id"]))

            selected_company = st.selectbox(
                "Select Company to Update",
                options=[""] + list(company_map.keys()),
                key="update_company_select"
            )

            if selected_company:
                cid = company_map[selected_company]
                current = companies_df[companies_df["company_id"] == cid].iloc[0]

                CATEGORIES = [
                    "",
                    "API Security", "Access Management (AM)", "Anomaly Detection (IoT/OT)",
                    "Anti-phishing and Simulated Phishing", "Application Detection & Response (ADR)",
                    "Application Security Orchestration and Correlation (ASOC)",
                    "Application Security Posture Management (ASPM)",
                    "Application Security Testing (AST)", "Attack Surface Management (ASM)",
                    "Automated Penetration Testing", "Automated Security Control Assessment (ASCA)",
                    "Backup and Recovery", "Bot Detection & Mitigation",
                    "Breach and Attack Simulation (BAS)", "Cloud Access Security Broker (CASB)",
                    "Cloud Detection & Response (CDR)", "Cloud IAM", "Cloud Identity Federation",
                    "Cloud Infrastructure Entitlements Management (CIEM)",
                    "Cloud Native Application Protection Platforms (CNAPP)",
                    "Cloud Security Posture Management (CSPM)",
                    "Cloud Workload Protection Platforms (CWPP)", "Compliance Management",
                    "Container Security", "Continuous Threat Exposure Management (CTEM)",
                    "Customer Identity", "Cyber Asset Attack Surface Management (CAASM)",
                    "Cyber Insurance", "Cyber Range", "Cyber Risk Quantification",
                    "Cybersecurity Education & Training", "DDoS Mitigation",
                    "Data Loss Prevention (DLP)", "Data Security Posture Management (DSPM)",
                    "Deception Platform", "Dynamic Application Security Testing (DAST)",
                    "Email Security Software", "Encryption Key Management System (EKMS)",
                    "Endpoint Detection and Response (EDR)", "Endpoint Protection Platform (EPP)",
                    "Enterprise Browser Security", "Enterprise Email Security",
                    "Extended Detection and Response (XDR)",
                    "External Attack Surface Management (EASM)",
                    "Forensic and Incident Response", "Fraud Prevention",
                    "Fraud and Financial Crime Protection",
                    "Governance, Risk, and Compliance (GRC)",
                    "Host-Based Intrusion Detection Systems (HIDS)", "Human Risk Management",
                    "Identity Governance and Administration (IGA)",
                    "Identity Threat and Detection Response (ITDR)", "Identity Verification",
                    "Identity and Access Management (IAM)", "Incident Response",
                    "Industrial Controls Systems (ICS) Security", "Industrial IoT Security",
                    "Insider Risk Management (IRM)", "Integrated Cloud Email Security (ICES)",
                    "Intrusion Detection System (IDS)",
                    "Intrusion Detection and Prevention Systems (IDPS)", "IoT Security",
                    "Managed Detection and Response (MDR)", "Managed Security Services",
                    "Mobile Application Security Testing", "Mobile Data Protection (MDP)",
                    "Mobile Device Management (MDM)", "Mobile Threat Defense",
                    "Network Access Control (NAC)", "Network Detection and Response (NDR)",
                    "Network-Based Intrusion Detection Systems (NIDS)",
                    "Operational Technology (OT) Security", "Password Management",
                    "Patch Management", "Penetration Testing", "Privacy",
                    "Privilege Elevation & Delegation Management (PEDM)",
                    "Privileged Access Management (PAM)",
                    "Privileged Account & Session Management (PASM)",
                    "Privileged Identity Management (PIM)",
                    "Risk Management & Compliance", "Risk-Based Vulnerability Management (RBVM)",
                    "Runtime Application Self-Protection (RASP)",
                    "SaaS Security Posture Management (SSPM)",
                    "Secure Access Service Edge (SASE)", "Secure Collaboration and Messaging",
                    "Secure Remote Access", "Secure Web Gateway (SWG)",
                    "Security Awareness Computer-Based Training (SACBT)",
                    "Security Awareness Training (SAT)",
                    "Security Information and Event Management (SIEM)",
                    "Security Orchestration and Automated Response (SOAR)",
                    "Security Service Edge (SSE)", "Single Sign-On (SSO)",
                    "Software Composition Analysis (SCA)", "Software Supply Chain Security",
                    "Third-Party Risk Management (TPRM)", "Unified Threat Management (UTM)",
                    "VPN Firewalls", "Vendor Risk Management", "Virtual Private Networks (VPNs)",
                    "Vulnerability Assessment", "Vulnerability Management (IoT/OT)",
                    "Vulnerability Management (VM)", "Vulnerability Risk Management (VRM)",
                    "Web Application Firewall (WAF)",
                    "Web Application and API Protection (WAAP)", "Wireless Security",
                    "Zero Trust Edge Solutions (ZTE)", "Zero Trust Network Access (ZTNA)",
                ]
                STATUS_OPTIONS = ["", "Active", "Acquired", "Closed", "IPO", "Unknown"]

                with st.form("update_company_form"):
                    upd_name = st.text_input("Company Name", value=str(current.get("company_name", "") or ""))
                    upd_website = st.text_input("Website", value=str(current.get("website_url", "") or ""))
                    upd_linkedin = st.text_input("LinkedIn URL", value=str(current.get("linkedin_url", "") or ""))
                    MARKET_SEGMENTS_UPD = [
                        "", "Cloud & Application Security", "Data Security & AI Security",
                        "Endpoint & IoT/OT Security", "Identity",
                        "Network & Infrastructure Security", "Risk & Compliance",
                        "Security Awareness & Training", "Security Operations", "Security Services",
                    ]
                    upd_segment = st.selectbox("Market Segment", MARKET_SEGMENTS_UPD)
                    cur_cat = str(current.get("category_group", "") or "")
                    upd_category = st.selectbox(
                        "Category",
                        CATEGORIES,
                        index=CATEGORIES.index(cur_cat) if cur_cat in CATEGORIES else 0
                    )
                    upd_status = st.selectbox(
                        "Status",
                        STATUS_OPTIONS,
                        index=STATUS_OPTIONS.index(current.get("status", "") or ""
                        ) if (current.get("status", "") or "") in STATUS_OPTIONS else 0
                    )
                    upd_employees = st.text_input(
                        "Employee Count",
                        value=str(current.get("employee_count", "") or ""),
                        placeholder="e.g. 50, 200-500"
                    )


                    submitted2 = st.form_submit_button("Save Changes ✅")
                    if submitted2:
                        try:
                            session.sql(f"USE WAREHOUSE {st.secrets['snowflake']['warehouse']}").collect()
                            now_upd = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
                            session.sql(f"""
                                UPDATE RISKINSIGHTSMEDIA_DB.ANALYTICS.COMPANIES
                                SET
                                    company_name   = {repr(upd_name.strip())},
                                    website        = {repr(upd_website.strip()) if upd_website.strip() else 'NULL'},
                                    linkedin_url   = {repr(upd_linkedin.strip()) if upd_linkedin.strip() else 'NULL'},
                                    category_group = {repr(upd_category.strip()) if upd_category.strip() else 'NULL'},
                                    status         = {repr(upd_status) if upd_status else 'NULL'},
                                    employee_count = {repr(upd_employees.strip()) if upd_employees.strip() else 'NULL'},
                                    updated_at     = TO_TIMESTAMP_NTZ('{now_upd}'),
                                    updated_by     = {repr(_current_user)}
                                WHERE company_id = {repr(str(cid))}
                            """).collect()
                            st.success(f"✅ Company '{upd_name}' updated successfully!")
                            st.cache_data.clear()
                            st.rerun()
                        except Exception as e:
                            st.error(f"❌ Error updating company: {e}")

        # -------------------------
        # Admin Sub-Tab 3: Log Funding Round
        # -------------------------
        with admin_tab3:
            st.markdown("#### Log a New Funding Round")
            company_options2 = companies_df[["company_id", "company_name"]].dropna(subset=["company_name"])
            company_map2 = dict(zip(company_options2["company_name"], company_options2["company_id"]))

            with st.form("add_funding_form"):
                fr_company = st.selectbox(
                    "Company *",
                    options=[""] + list(company_map2.keys()),
                    key="funding_company_select"
                )
                fr_stage = st.text_input("Funding Stage / Round *", placeholder="e.g. Series A, Seed")
                fr_amount = st.text_input("Amount Raised", placeholder="e.g. 5M, 1.2B")
                fr_investor = st.text_input("Lead Investor", placeholder="e.g. Sequoia Capital")
                fr_website = st.text_input("Website", placeholder="e.g. https://company.com")
                fr_linkedin = st.text_input("LinkedIn URL", placeholder="e.g. https://linkedin.com/company/x")

                submitted3 = st.form_submit_button("Log Funding Round ✅")
                if submitted3:
                    if not fr_company or not fr_stage.strip():
                        st.error("Company and Funding Stage are required.")
                    else:
                        try:
                            session.sql(f"USE WAREHOUSE {st.secrets['snowflake']['warehouse']}").collect()
                            cid2 = company_map2[fr_company]
                            now = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
                            session.sql(f"""
                                INSERT INTO RISKINSIGHTSMEDIA_DB.ANALYTICS.FUNDING_ROUNDS
                                (company_id, company_name, stage_or_funding_round,
                                 amount_raised_total, lead_investor, website_url, linkedin_url,
                                 created_at, updated_at, created_by, updated_by)
                                VALUES
                                ({repr(str(cid2))},
                                 {repr(fr_company)},
                                 {repr(fr_stage.strip())},
                                 {repr(fr_amount.strip()) if fr_amount.strip() else 'NULL'},
                                 {repr(fr_investor.strip()) if fr_investor.strip() else 'NULL'},
                                 {repr(fr_website.strip()) if fr_website.strip() else 'NULL'},
                                 {repr(fr_linkedin.strip()) if fr_linkedin.strip() else 'NULL'},
                                 '{now}', '{now}', {repr(_current_user)}, {repr(_current_user)})
                            """).collect()
                            st.success(f"✅ Funding round logged for '{fr_company}'!")
                            st.cache_data.clear()
                            st.rerun()
                        except Exception as e:
                            st.error(f"❌ Error logging funding round: {e}")

        # -------------------------
        # Admin Sub-Tab 4: Review Suggestions
        # -------------------------
        with admin_tab4:
            st.markdown("#### 📋 Pending Suggestions from Contributors")
            try:
                session.sql(f"USE WAREHOUSE {st.secrets['snowflake']['warehouse']}").collect()
                # Create suggestions table if it doesn't exist
                session.sql("""
                    CREATE TABLE IF NOT EXISTS RISKINSIGHTSMEDIA_DB.ANALYTICS.EDIT_SUGGESTIONS (
                        suggestion_id VARCHAR PRIMARY KEY,
                        submitted_by VARCHAR,
                        submission_type VARCHAR,
                        company_name VARCHAR,
                        field_name VARCHAR,
                        old_value VARCHAR,
                        new_value VARCHAR,
                        notes VARCHAR,
                        status VARCHAR DEFAULT 'pending',
                        submitted_at TIMESTAMP,
                        reviewed_at TIMESTAMP
                    )
                """).collect()

                suggestions_df = session.sql("""
                    SELECT suggestion_id, submitted_by, submission_type, company_name,
                           field_name, old_value, new_value, notes, status, submitted_at
                    FROM RISKINSIGHTSMEDIA_DB.ANALYTICS.EDIT_SUGGESTIONS
                    WHERE status = 'pending'
                    ORDER BY submitted_at DESC
                """).to_pandas()

                if suggestions_df.empty:
                    st.info("✅ No pending suggestions right now.")
                else:
                    suggestions_df.columns = suggestions_df.columns.str.lower()
                    st.caption(f"{len(suggestions_df)} pending suggestion(s)")
                    for _, row in suggestions_df.iterrows():
                        with st.container(border=True):
                            col_info, col_actions = st.columns([3, 1])
                            with col_info:
                                st.markdown(f"**{row['submission_type']}** — {row['company_name']}")
                                st.write(f"Field: `{row['field_name']}` → **{row['new_value']}**")
                                if row.get('notes'):
                                    st.caption(f"Note: {row['notes']}")
                                st.caption(f"Submitted by {row['submitted_by']} at {row['submitted_at']}")
                            with col_actions:
                                sid = str(row['suggestion_id'])
                                if st.button("✅ Approve", key=f"approve_{sid}"):
                                    now = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
                                    session.sql(f"""
                                        UPDATE RISKINSIGHTSMEDIA_DB.ANALYTICS.EDIT_SUGGESTIONS
                                        SET status = 'approved', reviewed_at = '{now}'
                                        WHERE suggestion_id = '{sid}'
                                    """).collect()
                                    st.success("Approved!")
                                    st.cache_data.clear()
                                    st.rerun()
                                if st.button("❌ Reject", key=f"reject_{sid}"):
                                    now = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
                                    session.sql(f"""
                                        UPDATE RISKINSIGHTSMEDIA_DB.ANALYTICS.EDIT_SUGGESTIONS
                                        SET status = 'rejected', reviewed_at = '{now}'
                                        WHERE suggestion_id = '{sid}'
                                    """).collect()
                                    st.warning("Rejected.")
                                    st.rerun()
            except Exception as e:
                st.error(f"❌ Could not load suggestions: {e}")


# ============================================================
# Contributor Panel (jitesh — Suggest Edits only)
# ============================================================
if is_contributor and tab4 is not None:
    with tab4:
        st.markdown("### ✏️ Contributor Panel")
        st.caption("Suggest edits to company or funding data. Jeremy will review and approve your suggestions.")

        c_tab1, c_tab2 = st.tabs(["🏢 Suggest Company Edit", "💡 Suggest New Entry"])

        # -------------------------
        # Contributor Sub-Tab 1: Suggest Company Edit
        # -------------------------
        with c_tab1:
            st.markdown("#### Suggest a change to an existing company")
            c_options = companies_df[["company_id", "company_name"]].dropna(subset=["company_name"])
            c_map = dict(zip(c_options["company_name"], c_options["company_id"]))

            c_selected = st.selectbox("Select Company", [""] + list(c_map.keys()), key="contrib_company_select")

            if c_selected:
                c_current = companies_df[companies_df["company_id"] == c_map[c_selected]].iloc[0]

                with st.form("suggest_edit_form"):
                    field_to_edit = st.selectbox("Which field to update?", [
                        "company_name", "website", "linkedin_url", "category_group", "status", "employee_count"
                    ])
                    old_val = str(c_current.get(field_to_edit, "") or "")
                    st.text_input("Current value (read-only)", value=old_val, disabled=True)
                    new_val = st.text_input("Suggested new value *")
                    notes = st.text_area("Notes / reason for change", placeholder="Optional: explain why this change is needed")

                    submitted_c = st.form_submit_button("Submit Suggestion 📤")
                    if submitted_c:
                        if not new_val.strip():
                            st.error("Please enter the new value.")
                        else:
                            try:
                                session.sql(f"USE WAREHOUSE {st.secrets['snowflake']['warehouse']}").collect()
                                session.sql("""
                                    CREATE TABLE IF NOT EXISTS RISKINSIGHTSMEDIA_DB.ANALYTICS.EDIT_SUGGESTIONS (
                                        suggestion_id VARCHAR PRIMARY KEY,
                                        submitted_by VARCHAR,
                                        submission_type VARCHAR,
                                        company_name VARCHAR,
                                        field_name VARCHAR,
                                        old_value VARCHAR,
                                        new_value VARCHAR,
                                        notes VARCHAR,
                                        status VARCHAR DEFAULT 'pending',
                                        submitted_at TIMESTAMP,
                                        reviewed_at TIMESTAMP
                                    )
                                """).collect()
                                now = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
                                sid = str(uuid.uuid4())
                                session.sql(f"""
                                    INSERT INTO RISKINSIGHTSMEDIA_DB.ANALYTICS.EDIT_SUGGESTIONS
                                    (suggestion_id, submitted_by, submission_type, company_name,
                                     field_name, old_value, new_value, notes, status, submitted_at)
                                    VALUES
                                    ('{sid}',
                                     '{st.session_state.get("username")}',
                                     'Company Edit',
                                     {repr(c_selected)},
                                     {repr(field_to_edit)},
                                     {repr(old_val)},
                                     {repr(new_val.strip())},
                                     {repr(notes.strip()) if notes.strip() else 'NULL'},
                                     'pending', '{now}')
                                """).collect()
                                st.success("✅ Suggestion submitted! Jeremy will review it shortly.")
                            except Exception as e:
                                st.error(f"❌ Error submitting suggestion: {e}")

        # -------------------------
        # Contributor Sub-Tab 2: Suggest New Entry
        # -------------------------
        with c_tab2:
            st.markdown("#### Suggest a completely new company or funding round to add")
            with st.form("suggest_new_form"):
                new_type = st.selectbox("Type of entry", ["New Company", "New Funding Round"])
                new_co_name = st.text_input("Company Name *")
                new_field = st.text_input(
                    "Key detail *",
                    placeholder="For company: website URL. For funding round: e.g. Series A — $5M"
                )
                new_notes = st.text_area("Additional notes / source", placeholder="Where did you find this info?")

                submitted_new = st.form_submit_button("Submit Suggestion 📤")
                if submitted_new:
                    if not new_co_name.strip() or not new_field.strip():
                        st.error("Company Name and Key detail are required.")
                    else:
                        try:
                            session.sql(f"USE WAREHOUSE {st.secrets['snowflake']['warehouse']}").collect()
                            session.sql("""
                                CREATE TABLE IF NOT EXISTS RISKINSIGHTSMEDIA_DB.ANALYTICS.EDIT_SUGGESTIONS (
                                    suggestion_id VARCHAR PRIMARY KEY,
                                    submitted_by VARCHAR,
                                    submission_type VARCHAR,
                                    company_name VARCHAR,
                                    field_name VARCHAR,
                                    old_value VARCHAR,
                                    new_value VARCHAR,
                                    notes VARCHAR,
                                    status VARCHAR DEFAULT 'pending',
                                    submitted_at TIMESTAMP,
                                    reviewed_at TIMESTAMP
                                )
                            """).collect()
                            now = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
                            sid = str(uuid.uuid4())
                            session.sql(f"""
                                INSERT INTO RISKINSIGHTSMEDIA_DB.ANALYTICS.EDIT_SUGGESTIONS
                                (suggestion_id, submitted_by, submission_type, company_name,
                                 field_name, old_value, new_value, notes, status, submitted_at)
                                VALUES
                                ('{sid}',
                                 '{st.session_state.get("username")}',
                                 {repr(new_type)},
                                 {repr(new_co_name.strip())},
                                 'new_entry',
                                 NULL,
                                 {repr(new_field.strip())},
                                 {repr(new_notes.strip()) if new_notes.strip() else 'NULL'},
                                 'pending', '{now}')
                            """).collect()
                            st.success("✅ Suggestion submitted! Jeremy will review it shortly.")
                        except Exception as e:
                            st.error(f"❌ Error submitting suggestion: {e}")






