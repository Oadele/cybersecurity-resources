# Impossible Travel – Successful Entra ID Sign-ins

## Detection Summary

This analytic rule detects **impossible or highly improbable travel** by identifying successful Entra ID sign-ins from **different countries within a short time window** for the same user.  
Such behavior may indicate **credential compromise**, **token theft**, or **session replay**.

This rule focuses on **successful authentication events** to reduce noise and surface higher-risk scenarios.

---

## MITRE ATT&CK

- **T1078.004** – Valid Accounts: Cloud Accounts  
- **T1078** – Valid Accounts  
- **T1071** – Application Layer Protocol  

---

## Data Sources

| Source | Table |
|------|------|
| Entra ID | `_Im_Authentication` (SigninLogs) |

---

## Detection Logic (KQL)

### Configuration Parameters

Customize these values for your environment:

```kql

let LookbackWindow      = 8h;
let MaxTravelMinutes    = 60;

let TrustedHostPrefixes = dynamic([]);
let KnownProxyIPs       = dynamic([]);
let AllowedCountries    = dynamic([]);

let EntraSuccessSignins =
    _Im_Authentication
    | where TimeGenerated > ago(LookbackWindow)
    | where EventProduct == "Entra ID"
    | where EventType == "Logon"
    | where Type == "SigninLogs"
    | where EventResult == "Success"
    | where isnotempty(TargetUsername)
      and isnotempty(SrcIpAddr)
      and SrcIpAddr !in ("127.0.0.1", "::1", "0.0.0.0")
    | extend
        User    = tolower(TargetUsername),
        Country = tostring(SrcGeoCountry),
        City    = tostring(SrcGeoCity)
    | where isnotempty(Country) and Country != "Unknown"
    | project
        TimeGenerated,
        User,
        SrcIpAddr,
        Country,
        City,
        SrcHostname,
        AppDisplayName,
        HttpUserAgent;

EntraSuccessSignins
| join kind=inner (EntraSuccessSignins) on User
| where TimeGenerated < TimeGenerated1
| extend TravelMinutes = datetime_diff("minute", TimeGenerated1, TimeGenerated)
| where TravelMinutes between (1 .. MaxTravelMinutes)
| where Country != Country1
| where SrcIpAddr != SrcIpAddr1
| extend
    FirstCountry    = Country1,
    SecondCountry   = Country,
    FirstIP         = SrcIpAddr1,
    SecondIP        = SrcIpAddr,
    FirstUA         = HttpUserAgent1,
    SecondUA        = HttpUserAgent,
    FirstApp        = AppDisplayName1,
    SecondApp       = AppDisplayName,
    FirstHost       = SrcHostname1,
    SecondHost      = SrcHostname
| summarize
    arg_min(TravelMinutes, *),
    PairCount = count(),
    StartTime = min(TimeGenerated),
    EndTime   = max(TimeGenerated1)
  by User
| extend
    SameUA     = FirstUA == SecondUA and isnotempty(FirstUA),
    SameApp    = FirstApp == SecondApp and isnotempty(FirstApp),
    SameHost   = FirstHost == SecondHost and isnotempty(FirstHost)

// Optional exclusions
| where not(
    array_length(TrustedHostPrefixes) > 0
    and FirstHost has_any (TrustedHostPrefixes)
    and SecondHost has_any (TrustedHostPrefixes)
)
| where not(
    array_length(KnownProxyIPs) > 0
    and (FirstIP in (KnownProxyIPs) or SecondIP in (KnownProxyIPs))
    and (
        array_length(AllowedCountries) == 0
        or (FirstCountry in (AllowedCountries) and SecondCountry in (AllowedCountries))
    )
)

// ----------------------
// Risk Scoring
// ----------------------
| extend RiskScore =
    20                                   // Base impossible travel
  + iff(TravelMinutes <= 10, 30,
        iff(TravelMinutes <= 30, 20, 10))
  + iff(SameUA,   15, 0)
  + iff(SameApp,  10, 0)
  + iff(SameHost, 15, 0)
  + iff(PairCount > 1, 10, 0)

| extend RiskScore = min_of(RiskScore, 100)

| extend RiskLevel =
    case(
        RiskScore >= 75, "High",
        RiskScore >= 40, "Medium",
        "Low"
    )

| extend mitre = "T1078.004, T1078, T1071"
