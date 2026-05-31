import os
import json
import time
import concurrent.futures
from urllib.parse import urlparse

import requests
from bs4 import BeautifulSoup
from flask import Flask, request, jsonify, render_template
from anthropic import Anthropic
from tavily import TavilyClient

app = Flask(__name__)
client = Anthropic(api_key=os.environ.get("ANTHROPIC_API_KEY"))
tavily = TavilyClient(api_key=os.environ.get("TAVILY_API_KEY"))

# ── Script-tag fingerprints (website HTML scan) ───────────────────────────────
FINGERPRINTS = {
    "Google Analytics":  {"patterns": ["google-analytics.com", "googletagmanager.com", "gtag/js"], "domain": "google.com",        "category": "Analytics & BI"},
    "Segment":           {"patterns": ["cdn.segment.com", "segment.io"],                            "domain": "segment.com",       "category": "Analytics & BI"},
    "Mixpanel":          {"patterns": ["cdn.mxpnl.com", "api.mixpanel.com"],                        "domain": "mixpanel.com",      "category": "Analytics & BI"},
    "Amplitude":         {"patterns": ["cdn.amplitude.com"],                                        "domain": "amplitude.com",     "category": "Analytics & BI"},
    "Heap":              {"patterns": ["cdn.heapanalytics.com"],                                    "domain": "heap.io",           "category": "Analytics & BI"},
    "FullStory":         {"patterns": ["edge.fullstory.com", "rs.fullstory.com"],                   "domain": "fullstory.com",     "category": "Analytics & BI"},
    "Hotjar":            {"patterns": ["static.hotjar.com"],                                        "domain": "hotjar.com",        "category": "Analytics & BI"},
    "Pendo":             {"patterns": ["cdn.pendo.io"],                                             "domain": "pendo.io",          "category": "Analytics & BI"},
    "HubSpot":           {"patterns": ["hs-scripts.com", "js.hs-scripts.com"],                      "domain": "hubspot.com",       "category": "CRM"},
    "Salesforce":        {"patterns": ["sfdcstatic.com", "force.com"],                              "domain": "salesforce.com",    "category": "CRM"},
    "Marketo":           {"patterns": ["munchkin.marketo.net"],                                     "domain": "marketo.com",       "category": "Marketing Automation"},
    "Pardot":            {"patterns": ["pardot.com"],                                               "domain": "pardot.com",        "category": "Marketing Automation"},
    "Facebook Pixel":    {"patterns": ["connect.facebook.net", "fbevents.js"],                      "domain": "facebook.com",      "category": "Advertising"},
    "LinkedIn Insight":  {"patterns": ["snap.licdn.com"],                                           "domain": "linkedin.com",      "category": "Advertising"},
    "Google Ads":        {"patterns": ["googleadservices.com"],                                     "domain": "google.com",        "category": "Advertising"},
    "6sense":            {"patterns": ["6sense.com", "6si.com"],                                    "domain": "6sense.com",        "category": "ABM & Intent"},
    "Demandbase":        {"patterns": ["tag.demandbase.com"],                                       "domain": "demandbase.com",    "category": "ABM & Intent"},
    "Intercom":          {"patterns": ["widget.intercom.io", "js.intercomcdn.com"],                 "domain": "intercom.com",      "category": "Customer Support"},
    "Zendesk":           {"patterns": ["static.zdassets.com", "zopim.com"],                         "domain": "zendesk.com",       "category": "Customer Support"},
    "Drift":             {"patterns": ["js.driftt.com"],                                            "domain": "drift.com",         "category": "Sales & Chat"},
    "Crisp":             {"patterns": ["client.crisp.chat"],                                        "domain": "crisp.chat",        "category": "Customer Support"},
    "Calendly":          {"patterns": ["assets.calendly.com"],                                      "domain": "calendly.com",      "category": "Scheduling"},
    "Chili Piper":       {"patterns": ["js.chilipiper.com"],                                        "domain": "chilipiper.com",    "category": "Scheduling"},
    "Stripe":            {"patterns": ["js.stripe.com"],                                            "domain": "stripe.com",        "category": "Payments"},
    "Recurly":           {"patterns": ["js.recurly.com"],                                           "domain": "recurly.com",       "category": "Payments"},
    "Sentry":            {"patterns": ["browser.sentry-cdn.com"],                                   "domain": "sentry.io",         "category": "DevOps & Monitoring"},
    "Datadog":           {"patterns": ["rum.browser-intake-datadoghq.com"],                         "domain": "datadoghq.com",     "category": "DevOps & Monitoring"},
    "New Relic":         {"patterns": ["js-agent.newrelic.com"],                                    "domain": "newrelic.com",      "category": "DevOps & Monitoring"},
    "Optimizely":        {"patterns": ["cdn.optimizely.com"],                                       "domain": "optimizely.com",    "category": "A/B Testing"},
    "Gainsight":         {"patterns": ["gainsight.com"],                                            "domain": "gainsight.com",     "category": "Customer Success"},
    "ChurnZero":         {"patterns": ["churnzero.net"],                                            "domain": "churnzero.com",     "category": "Customer Success"},
}

# ── Comprehensive text-based tool registry (100+ tools) ───────────────────────
# Scans any text source for tool name mentions
TOOLS_REGISTRY = {
    # CRM
    "Salesforce":       {"domain": "salesforce.com",        "category": "CRM",                    "kw": ["salesforce", "sfdc", "salescloud"]},
    "HubSpot":          {"domain": "hubspot.com",           "category": "CRM",                    "kw": ["hubspot"]},
    "Pipedrive":        {"domain": "pipedrive.com",         "category": "CRM",                    "kw": ["pipedrive"]},
    "Zoho CRM":         {"domain": "zoho.com",              "category": "CRM",                    "kw": ["zoho crm"]},

    # Sales Engagement
    "Outreach":         {"domain": "outreach.io",           "category": "Sales Engagement",        "kw": ["outreach.io", "outreach sales"]},
    "Salesloft":        {"domain": "salesloft.com",         "category": "Sales Engagement",        "kw": ["salesloft"]},
    "Gong":             {"domain": "gong.io",               "category": "Sales Engagement",        "kw": ["gong.io", "gong calls", "gong revenue"]},
    "Apollo":           {"domain": "apollo.io",             "category": "Sales Engagement",        "kw": ["apollo.io"]},
    "ZoomInfo":         {"domain": "zoominfo.com",          "category": "Sales Engagement",        "kw": ["zoominfo"]},
    "Clearbit":         {"domain": "clearbit.com",          "category": "Sales Engagement",        "kw": ["clearbit"]},

    # Marketing Automation
    "HubSpot Marketing":{"domain": "hubspot.com",           "category": "Marketing Automation",    "kw": ["hubspot marketing", "hubspot email"]},
    "Marketo":          {"domain": "marketo.com",           "category": "Marketing Automation",    "kw": ["marketo"]},
    "Pardot":           {"domain": "pardot.com",            "category": "Marketing Automation",    "kw": ["pardot", "salesforce marketing cloud"]},
    "Iterable":         {"domain": "iterable.com",          "category": "Marketing Automation",    "kw": ["iterable"]},
    "Braze":            {"domain": "braze.com",             "category": "Marketing Automation",    "kw": ["braze"]},
    "Klaviyo":          {"domain": "klaviyo.com",           "category": "Marketing Automation",    "kw": ["klaviyo"]},
    "Customer.io":      {"domain": "customer.io",           "category": "Marketing Automation",    "kw": ["customer.io"]},
    "Mailchimp":        {"domain": "mailchimp.com",         "category": "Marketing Automation",    "kw": ["mailchimp"]},
    "SendGrid":         {"domain": "sendgrid.com",          "category": "Marketing Automation",    "kw": ["sendgrid"]},

    # Analytics & BI
    "Snowflake":        {"domain": "snowflake.com",         "category": "Analytics & BI",          "kw": ["snowflake"]},
    "Looker":           {"domain": "looker.com",            "category": "Analytics & BI",          "kw": ["looker"]},
    "Tableau":          {"domain": "tableau.com",           "category": "Analytics & BI",          "kw": ["tableau"]},
    "Power BI":         {"domain": "powerbi.microsoft.com", "category": "Analytics & BI",          "kw": ["power bi", "powerbi"]},
    "Amplitude":        {"domain": "amplitude.com",         "category": "Analytics & BI",          "kw": ["amplitude"]},
    "Mixpanel":         {"domain": "mixpanel.com",          "category": "Analytics & BI",          "kw": ["mixpanel"]},
    "Segment":          {"domain": "segment.com",           "category": "Analytics & BI",          "kw": ["segment cdp", "segment.io"]},
    "Heap":             {"domain": "heap.io",               "category": "Analytics & BI",          "kw": ["heap analytics", "heap.io"]},
    "FullStory":        {"domain": "fullstory.com",         "category": "Analytics & BI",          "kw": ["fullstory"]},
    "Metabase":         {"domain": "metabase.com",          "category": "Analytics & BI",          "kw": ["metabase"]},
    "Mode":             {"domain": "mode.com",              "category": "Analytics & BI",          "kw": ["mode analytics"]},
    "Sigma":            {"domain": "sigmacomputing.com",    "category": "Analytics & BI",          "kw": ["sigma computing"]},

    # Data Infrastructure
    "Databricks":       {"domain": "databricks.com",        "category": "Data Infrastructure",     "kw": ["databricks"]},
    "dbt":              {"domain": "getdbt.com",            "category": "Data Infrastructure",     "kw": [" dbt ", "dbt labs", "data build tool"]},
    "Fivetran":         {"domain": "fivetran.com",          "category": "Data Infrastructure",     "kw": ["fivetran"]},
    "Airbyte":          {"domain": "airbyte.com",           "category": "Data Infrastructure",     "kw": ["airbyte"]},
    "Apache Kafka":     {"domain": "kafka.apache.org",      "category": "Data Infrastructure",     "kw": ["kafka", "apache kafka"]},
    "Apache Spark":     {"domain": "spark.apache.org",      "category": "Data Infrastructure",     "kw": ["apache spark", "pyspark", "spark streaming"]},
    "Apache Airflow":   {"domain": "airflow.apache.org",    "category": "Data Infrastructure",     "kw": ["airflow", "apache airflow"]},
    "Redis":            {"domain": "redis.io",              "category": "Data Infrastructure",     "kw": ["redis"]},
    "PostgreSQL":       {"domain": "postgresql.org",        "category": "Data Infrastructure",     "kw": ["postgresql", "postgres"]},
    "MySQL":            {"domain": "mysql.com",             "category": "Data Infrastructure",     "kw": ["mysql"]},
    "MongoDB":          {"domain": "mongodb.com",           "category": "Data Infrastructure",     "kw": ["mongodb", "mongo"]},
    "Elasticsearch":    {"domain": "elastic.co",            "category": "Data Infrastructure",     "kw": ["elasticsearch", "elastic stack"]},
    "BigQuery":         {"domain": "cloud.google.com",      "category": "Data Infrastructure",     "kw": ["bigquery"]},
    "Redshift":         {"domain": "aws.amazon.com",        "category": "Data Infrastructure",     "kw": ["redshift", "amazon redshift"]},
    "Stitch":           {"domain": "stitchdata.com",        "category": "Data Infrastructure",     "kw": ["stitch data", "stitch etl"]},
    "Hightouch":        {"domain": "hightouch.com",         "category": "Data Infrastructure",     "kw": ["hightouch"]},
    "Census":           {"domain": "getcensus.com",         "category": "Data Infrastructure",     "kw": ["census reverse etl"]},

    # Cloud Infrastructure
    "AWS":              {"domain": "aws.amazon.com",        "category": "Cloud Infrastructure",    "kw": ["aws ", "amazon web services", "amazon s3", "ec2", "lambda"]},
    "GCP":              {"domain": "cloud.google.com",      "category": "Cloud Infrastructure",    "kw": ["google cloud", " gcp ", "google kubernetes"]},
    "Azure":            {"domain": "azure.microsoft.com",   "category": "Cloud Infrastructure",    "kw": ["microsoft azure", "azure cloud"]},
    "Cloudflare":       {"domain": "cloudflare.com",        "category": "Cloud Infrastructure",    "kw": ["cloudflare"]},

    # DevOps
    "Kubernetes":       {"domain": "kubernetes.io",         "category": "DevOps",                  "kw": ["kubernetes", " k8s "]},
    "Docker":           {"domain": "docker.com",            "category": "DevOps",                  "kw": ["docker"]},
    "Terraform":        {"domain": "terraform.io",          "category": "DevOps",                  "kw": ["terraform"]},
    "GitHub":           {"domain": "github.com",            "category": "DevOps",                  "kw": ["github"]},
    "GitLab":           {"domain": "gitlab.com",            "category": "DevOps",                  "kw": ["gitlab"]},
    "CircleCI":         {"domain": "circleci.com",          "category": "DevOps",                  "kw": ["circleci"]},
    "Jenkins":          {"domain": "jenkins.io",            "category": "DevOps",                  "kw": ["jenkins"]},
    "ArgoCD":           {"domain": "argoproj.github.io",    "category": "DevOps",                  "kw": ["argocd", "argo cd"]},
    "LaunchDarkly":     {"domain": "launchdarkly.com",      "category": "DevOps",                  "kw": ["launchdarkly", "feature flag", "feature flags"]},

    # Monitoring
    "Datadog":          {"domain": "datadoghq.com",         "category": "DevOps & Monitoring",     "kw": ["datadog"]},
    "Sentry":           {"domain": "sentry.io",             "category": "DevOps & Monitoring",     "kw": ["sentry"]},
    "New Relic":        {"domain": "newrelic.com",          "category": "DevOps & Monitoring",     "kw": ["new relic", "newrelic"]},
    "PagerDuty":        {"domain": "pagerduty.com",         "category": "DevOps & Monitoring",     "kw": ["pagerduty"]},
    "Grafana":          {"domain": "grafana.com",           "category": "DevOps & Monitoring",     "kw": ["grafana"]},
    "Splunk":           {"domain": "splunk.com",            "category": "DevOps & Monitoring",     "kw": ["splunk"]},
    "LogRocket":        {"domain": "logrocket.com",         "category": "DevOps & Monitoring",     "kw": ["logrocket"]},

    # Security
    "Okta":             {"domain": "okta.com",              "category": "Security",                "kw": ["okta"]},
    "Auth0":            {"domain": "auth0.com",             "category": "Security",                "kw": ["auth0"]},
    "CrowdStrike":      {"domain": "crowdstrike.com",       "category": "Security",                "kw": ["crowdstrike"]},

    # Customer Support
    "Zendesk":          {"domain": "zendesk.com",           "category": "Customer Support",        "kw": ["zendesk"]},
    "Intercom":         {"domain": "intercom.com",          "category": "Customer Support",        "kw": ["intercom"]},
    "Freshdesk":        {"domain": "freshworks.com",        "category": "Customer Support",        "kw": ["freshdesk", "freshworks"]},
    "Kustomer":         {"domain": "kustomer.com",          "category": "Customer Support",        "kw": ["kustomer"]},
    "Gladly":           {"domain": "gladly.com",            "category": "Customer Support",        "kw": ["gladly"]},

    # Customer Success
    "Gainsight":        {"domain": "gainsight.com",         "category": "Customer Success",        "kw": ["gainsight"]},
    "ChurnZero":        {"domain": "churnzero.com",         "category": "Customer Success",        "kw": ["churnzero"]},
    "Totango":          {"domain": "totango.com",           "category": "Customer Success",        "kw": ["totango"]},
    "Vitally":          {"domain": "vitally.io",            "category": "Customer Success",        "kw": ["vitally"]},

    # Payments
    "Stripe":           {"domain": "stripe.com",            "category": "Payments",                "kw": ["stripe payments", "stripe api", "stripe billing"]},
    "Braintree":        {"domain": "braintreepayments.com", "category": "Payments",                "kw": ["braintree"]},
    "Chargebee":        {"domain": "chargebee.com",         "category": "Payments",                "kw": ["chargebee"]},
    "Recurly":          {"domain": "recurly.com",           "category": "Payments",                "kw": ["recurly"]},
    "Zuora":            {"domain": "zuora.com",             "category": "Payments",                "kw": ["zuora"]},

    # Collaboration
    "Slack":            {"domain": "slack.com",             "category": "Collaboration",           "kw": ["slack"]},
    "Notion":           {"domain": "notion.so",             "category": "Collaboration",           "kw": ["notion"]},
    "Confluence":       {"domain": "atlassian.com",         "category": "Collaboration",           "kw": ["confluence"]},
    "Jira":             {"domain": "atlassian.com",         "category": "Collaboration",           "kw": ["jira"]},
    "Asana":            {"domain": "asana.com",             "category": "Collaboration",           "kw": ["asana"]},
    "Linear":           {"domain": "linear.app",            "category": "Collaboration",           "kw": ["linear.app", "linear issues"]},
    "Zoom":             {"domain": "zoom.us",               "category": "Collaboration",           "kw": ["zoom"]},

    # HR & People
    "Workday":          {"domain": "workday.com",           "category": "HR & People",             "kw": ["workday hris", "workday hr", "workday payroll"]},
    "BambooHR":         {"domain": "bamboohr.com",          "category": "HR & People",             "kw": ["bamboohr", "bamboo hr"]},
    "HiBob":            {"domain": "hibob.com",             "category": "HR & People",             "kw": ["hibob", "hi bob"]},
    "Personio":         {"domain": "personio.com",          "category": "HR & People",             "kw": ["personio"]},
    "Rippling":         {"domain": "rippling.com",          "category": "HR & People",             "kw": ["rippling"]},
    "Gusto":            {"domain": "gusto.com",             "category": "HR & People",             "kw": ["gusto payroll", "gusto hr"]},
    "ADP":              {"domain": "adp.com",               "category": "HR & People",             "kw": ["adp payroll", "adp workforce"]},
    "Deel":             {"domain": "deel.com",              "category": "HR & People",             "kw": ["deel", "deel global payroll"]},
    "Papaya Global":    {"domain": "papayaglobal.com",      "category": "HR & People",             "kw": ["papaya global"]},
    "Greenhouse":       {"domain": "greenhouse.io",         "category": "HR & People",             "kw": ["greenhouse ats", "greenhouse.io", "greenhouse recruiting"]},
    "Lever":            {"domain": "lever.co",              "category": "HR & People",             "kw": ["lever ats", "lever.co"]},
    "Ashby":            {"domain": "ashbyhq.com",           "category": "HR & People",             "kw": ["ashby ats", "ashby recruiting"]},
    "Lattice":          {"domain": "lattice.com",           "category": "HR & People",             "kw": ["lattice hr", "lattice performance"]},
    "Culture Amp":      {"domain": "cultureamp.com",        "category": "HR & People",             "kw": ["culture amp"]},
    "15Five":           {"domain": "15five.com",            "category": "HR & People",             "kw": ["15five"]},
    "Leapsome":         {"domain": "leapsome.com",          "category": "HR & People",             "kw": ["leapsome"]},
    "Checkr":           {"domain": "checkr.com",            "category": "HR & People",             "kw": ["checkr"]},
    "Carta":            {"domain": "carta.com",             "category": "HR & People",             "kw": ["carta equity", "carta cap table"]},

    # Finance
    "NetSuite":         {"domain": "netsuite.com",          "category": "Finance",                 "kw": ["netsuite"]},
    "QuickBooks":       {"domain": "quickbooks.intuit.com", "category": "Finance",                 "kw": ["quickbooks"]},
    "Xero":             {"domain": "xero.com",              "category": "Finance",                 "kw": ["xero accounting", "xero finance"]},
    "Workiva":          {"domain": "workiva.com",           "category": "Finance",                 "kw": ["workiva"]},
    "Anaplan":          {"domain": "anaplan.com",           "category": "Finance",                 "kw": ["anaplan"]},
    "Pigment":          {"domain": "pigment.app",           "category": "Finance",                 "kw": ["pigment fpa", "pigment planning"]},
    "Mosaic":           {"domain": "mosaic.tech",           "category": "Finance",                 "kw": ["mosaic strategic finance", "mosaic.tech"]},
    "Sage":             {"domain": "sage.com",              "category": "Finance",                 "kw": ["sage intacct", "sage accounting"]},
    "Expensify":        {"domain": "expensify.com",         "category": "Finance",                 "kw": ["expensify"]},
    "Navan":            {"domain": "navan.com",             "category": "Finance",                 "kw": ["navan", "tripactions"]},

    # Procurement & Spend
    "Coupa":            {"domain": "coupa.com",             "category": "Procurement & Spend",     "kw": ["coupa"]},
    "Zip":              {"domain": "ziphq.com",             "category": "Procurement & Spend",     "kw": ["zip procurement", "ziphq"]},
    "Brex":             {"domain": "brex.com",              "category": "Procurement & Spend",     "kw": ["brex"]},
    "Ramp":             {"domain": "ramp.com",              "category": "Procurement & Spend",     "kw": ["ramp finance", "ramp spend", "ramp corporate card"]},
    "Spendesk":         {"domain": "spendesk.com",          "category": "Procurement & Spend",     "kw": ["spendesk"]},
    "Procurify":        {"domain": "procurify.com",         "category": "Procurement & Spend",     "kw": ["procurify"]},
    "SAP Ariba":        {"domain": "ariba.com",             "category": "Procurement & Spend",     "kw": ["sap ariba", "ariba procurement"]},
    "Airbase":          {"domain": "airbase.com",           "category": "Procurement & Spend",     "kw": ["airbase"]},

    # ABM & Intent
    "6sense":           {"domain": "6sense.com",            "category": "ABM & Intent",            "kw": ["6sense"]},
    "Demandbase":       {"domain": "demandbase.com",        "category": "ABM & Intent",            "kw": ["demandbase"]},
    "Rollworks":        {"domain": "rollworks.com",         "category": "ABM & Intent",            "kw": ["rollworks"]},

    # Design
    "Figma":            {"domain": "figma.com",             "category": "Design",                  "kw": ["figma"]},

    # Internal Tools & Automation
    "Retool":           {"domain": "retool.com",            "category": "Internal Tools",          "kw": ["retool"]},
    "Zapier":           {"domain": "zapier.com",            "category": "Automation",              "kw": ["zapier"]},
    "Make":             {"domain": "make.com",              "category": "Automation",              "kw": ["make.com", "integromat"]},
    "Workato":          {"domain": "workato.com",           "category": "Automation",              "kw": ["workato"]},
    "monday.com":       {"domain": "monday.com",            "category": "Collaboration",           "kw": ["monday.com", "monday work os", "monday crm"]},

    # Sales Intelligence
    "Gong":             {"domain": "gong.io",               "category": "Sales Engagement",        "kw": ["gong.io", "gong revenue", "gong platform", "gong calls", "using gong", "uses gong"]},
    "Clari":            {"domain": "clari.com",             "category": "Sales Engagement",        "kw": ["clari"]},
    "Chorus":           {"domain": "chorus.ai",             "category": "Sales Engagement",        "kw": ["chorus.ai", "chorus by zoominfo"]},

    # Security & Identity
    "Okta":             {"domain": "okta.com",              "category": "Security",                "kw": ["okta"]},
    "Wiz":              {"domain": "wiz.io",                "category": "Security",                "kw": ["wiz.io", "wiz cloud security", "wiz security"]},
    "CrowdStrike":      {"domain": "crowdstrike.com",       "category": "Security",                "kw": ["crowdstrike"]},
    "Palo Alto Networks":{"domain": "paloaltonetworks.com", "category": "Security",                "kw": ["palo alto networks", "prisma cloud", "cortex xdr"]},
    "Snyk":             {"domain": "snyk.io",               "category": "Security",                "kw": ["snyk"]},
    "Cloudflare":       {"domain": "cloudflare.com",        "category": "Security",                "kw": ["cloudflare"]},

    # BI & Data (additional)
    "Power BI":         {"domain": "powerbi.microsoft.com", "category": "Analytics & BI",          "kw": ["power bi", "powerbi", "microsoft power bi"]},
    "Snowflake":        {"domain": "snowflake.com",         "category": "Data Infrastructure",     "kw": ["snowflake"]},
}


def normalize_domain(text):
    text = text.strip().lower()
    if text.startswith(("http://", "https://")):
        return urlparse(text).netloc.replace("www.", "")
    text = text.replace("www.", "")
    return text if "." in text else text + ".com"


def fetch_page(url, timeout=4):
    try:
        r = requests.get(
            url,
            timeout=timeout,
            headers={"User-Agent": "Mozilla/5.0 (compatible; StackInvestigator/1.0)"},
            allow_redirects=True,
        )
        return r.text
    except Exception:
        return ""


def scan_text_for_tools(text, source, confidence="medium"):
    """Scan any text for known tool mentions using TOOLS_REGISTRY."""
    found = {}
    text_lower = " " + text.lower() + " "
    for name, info in TOOLS_REGISTRY.items():
        if name in found:
            continue
        if any(kw in text_lower for kw in info["kw"]):
            found[name] = {
                "name": name,
                "domain": info["domain"],
                "category": info["category"],
                "confidence": confidence,
                "source": source,
            }
    return list(found.values())


def scan_website(domain):
    """Scan website HTML for script fingerprints and text-based tool mentions."""
    script_found = {}
    text_found = {}

    pages = [("", "high"), ("/integrations", "high"), ("/marketplace", "high"), ("/apps", "high")]

    for page, confidence in pages:
        for scheme in ("https", "http"):
            html = fetch_page(f"{scheme}://{domain}{page}")
            if not html:
                continue
            html_lower = html.lower()

            # Script fingerprints
            for name, info in FINGERPRINTS.items():
                if name not in script_found and any(p.lower() in html_lower for p in info["patterns"]):
                    script_found[name] = {
                        "name": name,
                        "domain": info["domain"],
                        "category": info["category"],
                        "confidence": "high",
                        "source": f"website{page or '/'}",
                    }

            # Text-based mentions on integration/marketplace pages
            if page in ("/integrations", "/marketplace", "/apps"):
                soup = BeautifulSoup(html, "html.parser")
                page_text = soup.get_text(separator=" ", strip=True)
                for t in scan_text_for_tools(page_text, f"website{page}", "high"):
                    if t["name"] not in text_found:
                        text_found[t["name"]] = t

            break  # got a response, skip http fallback

    # Merge: script fingerprints take priority
    merged = {**text_found, **script_found}
    return list(merged.values())


def tavily_search(query):
    try:
        result = tavily.search(query=query, max_results=7, search_depth="basic")
        return "\n\n".join(x.get("content", "") for x in result.get("results", []))
    except Exception:
        return ""


def synthesize(company_name, domain, website_tools, tavily_text):
    """Claude extracts tools from Tavily text + merges with website scan results."""

    website_list = "\n".join(f"- {t['name']} ({t['category']})" for t in website_tools) or "None"

    prompt = f"""You are a B2B tech analyst. Your job is to identify the tech stack of {company_name} (domain: {domain}).

== WEBSITE SCAN — HIGH CONFIDENCE (detected directly in their HTML) ==
{website_list}

== PUBLIC SOURCES TEXT (job listings, vendor pages, press) ==
{tavily_text[:14000] if tavily_text else "No data"}

STRICT RULES:
1. From the PUBLIC SOURCES section, only extract a tool if the text clearly connects it to {company_name} — e.g. "{company_name} uses X", "experience with X required", "{company_name} is an X customer/partner", "built on X", "powered by X".
   CRITICAL: "{company_name} integrates with X" or "{company_name} + X integration" means their CUSTOMERS can connect the two tools — NOT that {company_name} itself uses X internally. Do NOT include tools found only on integration/partnership pages.
2. Do NOT include a tool just because it appears somewhere in the text. The connection to {company_name} must be clear.
3. Website scan tools are confirmed — keep them all.
4. SELF-REFERENCE: Never include {domain} or {company_name} as a tool. If the company IS the product (e.g. Stripe in Stripe's results, HubSpot in HubSpot's results, Cloudflare in Cloudflare's results), exclude it entirely.
5. CLOUD SUB-SERVICES: Do NOT list sub-services as separate tools. AWS Lambda/S3/EC2/EKS/CloudFront/RDS → "AWS" only. Cloud Run/GKE/Cloud Storage → "GCP" only. Azure Functions/Azure AD/Azure DevOps → "Azure" only.
6. COMPETITORS: If {company_name} makes a product that competes with a tool, exclude that tool unless evidence is very explicit. Examples: Linear does not use Jira. Datadog does not use New Relic or Splunk. Notion does not use Asana. HubSpot does not use Salesforce as a CRM.
7. COMPETING PAIRS: Do not list both tools from a competing pair (GitHub vs GitLab, Jira vs Linear vs Asana) unless there is strong explicit evidence for each separately.
8. NO FRAMEWORKS/LANGUAGES: Do not list programming languages, frontend frameworks (React, Next.js, TypeScript, Vue, Ruby, Node.js, Redux, WebGL) or open-source databases (PostgreSQL, MySQL, Redis) unless the company's product is specifically built around that technology.
9. TOOL CAP: Return a maximum of 25 tools total. If you find more, keep only the most certain ones.
10. Categories (use ONLY these, no others): CRM | Marketing Automation | Analytics & BI | Sales Engagement | Customer Support | Data Infrastructure | Cloud Infrastructure | DevOps & Monitoring | Payments | HR & People | Finance | Procurement & Spend | Security | Collaboration | ABM & Intent | Automation | Design | Internal Tools
11. Confidence: "high" = confirmed by website scan OR explicitly named in a job requirement/case study. "medium" = mentioned in a vendor/3rd party source. Never assign "high" to more than half the tools in a scan.

Return ONLY valid JSON:
{{
  "company_name": "{company_name}",
  "company_domain": "{domain}",
  "stack": [
    {{
      "category": "string",
      "tools": [{{"name": "string", "domain": "string", "confidence": "high|medium"}}]
    }}
  ]
}}"""

    msg = client.messages.create(
        model="claude-sonnet-4-6",
        max_tokens=2000,
        messages=[{"role": "user", "content": prompt}],
    )
    text = msg.content[0].text.strip()
    if "```" in text:
        parts = text.split("```")
        text = parts[1]
        if text.startswith("json"):
            text = text[4:]
    text = text.strip()
    # Find JSON boundaries in case Claude added extra text
    start = text.find("{")
    end = text.rfind("}") + 1
    if start != -1 and end > start:
        text = text[start:end]
    return json.loads(text)


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/stack", methods=["POST"])
def get_stack():
    try:
        body = request.get_json(silent=True) or {}
        raw = (body.get("company") or "").strip()
        if not raw:
            return jsonify({"error": "Please enter a company domain"}), 400

        domain = normalize_domain(raw)
        company_name = domain.split(".")[0].title()
        t0 = time.time()

        with concurrent.futures.ThreadPoolExecutor(max_workers=5) as ex:
            w_future = ex.submit(scan_website, domain)
            j_future = ex.submit(tavily_search,
                f'"{domain}" OR "{company_name}" jobs hiring "experience with" OR "proficiency in" software tools CRM analytics DevOps')
            v_future = ex.submit(tavily_search,
                f'"{domain}" customer case study technology vendor uses integrates')
            i_future = ex.submit(tavily_search,
                f'"{domain}" integrates with apps marketplace tools partners')
            e_future = ex.submit(tavily_search,
                f'"{domain}" tech stack engineering "powered by" OR "built with" OR "we use"')
            c_future = ex.submit(tavily_search,
                f'"{domain}" AWS OR GCP OR Azure OR Snowflake OR Salesforce partner customer')
            s_future = ex.submit(tavily_search,
                f'"{domain}" Gong OR Salesloft OR Outreach OR Clari OR Zapier OR "monday.com" sales tools automation')
            sec_future = ex.submit(tavily_search,
                f'"{domain}" Okta OR Wiz OR CrowdStrike OR "Palo Alto" OR Snyk security identity')
            fin_future = ex.submit(tavily_search,
                f'"{domain}" Workday OR BambooHR OR Rippling OR Deel OR NetSuite OR QuickBooks OR Anaplan OR Coupa OR Ramp OR Brex OR Expensify finance HR payroll procurement')

            try:
                website_tools = w_future.result(timeout=14)
            except Exception:
                website_tools = []
            try:
                jobs_text = j_future.result(timeout=10)
            except Exception:
                jobs_text = ""
            try:
                vendors_text = v_future.result(timeout=10)
            except Exception:
                vendors_text = ""
            try:
                integr_text = i_future.result(timeout=10)
            except Exception:
                integr_text = ""
            try:
                eng_text = e_future.result(timeout=10)
            except Exception:
                eng_text = ""
            try:
                cloud_text = c_future.result(timeout=10)
            except Exception:
                cloud_text = ""
            try:
                sales_text = s_future.result(timeout=10)
            except Exception:
                sales_text = ""
            try:
                sec_text = sec_future.result(timeout=10)
            except Exception:
                sec_text = ""
            try:
                fin_text = fin_future.result(timeout=10)
            except Exception:
                fin_text = ""

        def cap(t, n=1500): return t[:n] if t else ""
        all_tavily_text = "\n\n---\n\n".join(filter(None, [
            cap(jobs_text), cap(vendors_text), cap(integr_text),
            cap(eng_text), cap(cloud_text), cap(sales_text), cap(sec_text), cap(fin_text)
        ]))

        print(f"[{domain}] website: {len(website_tools)} tools, tavily: {len(all_tavily_text)} chars — {time.time()-t0:.1f}s")
        print(f"[{domain}] sales search snippet: {sales_text[:300]!r}")

        result = synthesize(company_name, domain, website_tools, all_tavily_text)
        print(f"[{domain}] total {time.time()-t0:.1f}s")
        return jsonify(result)

    except Exception as e:
        print(f"Error in get_stack: {e}")
        return jsonify({"error": "Something went wrong. Please try again."}), 500


if __name__ == "__main__":
    import threading, webbrowser
    threading.Timer(1.2, lambda: webbrowser.open("http://localhost:5001")).start()
    app.run(debug=True, port=5001)
