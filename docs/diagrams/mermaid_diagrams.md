# CyberRegis Platform - Mermaid Diagrams

This file contains Mermaid diagram code for all essential features of the CyberRegis platform. Copy and paste each diagram into Mermaid UI (https://mermaid.live/) to generate images.

---

## 1. System Architecture Diagram

```mermaid
graph TB
    Client[Client Application] --> API[Flask REST API]
    API --> Routes[Routes Layer]
    Routes --> Services[Services Layer]
    Services --> Models[Models Layer]
    Services --> Utils[Utilities Layer]
    
    Services --> URLService[URL Service]
    Services --> IPService[IP Service]
    Services --> DomainService[Domain Service]
    Services --> PCAPService[PCAP Service]
    Services --> AIService[AI Service]
    
    URLService --> GSB[Google Safe Browsing API]
    IPService --> AbuseIPDB[AbuseIPDB API]
    PCAPService --> VT[VirusTotal API]
    AIService --> Gemini[Google Gemini API]
    
    Utils --> Cache[TTL Cache]
    Utils --> Validator[Input Validator]
    Utils --> Logger[Logger]
    
    Services --> Telegram[Telegram Notification]
    
    Models --> Response[Response Formatter]
    
    style API fill:#e1f5ff
    style Routes fill:#b3e5fc
    style Services fill:#81d4fa
    style Models fill:#4fc3f7
    style Utils fill:#29b6f6
    style Cache fill:#ffeb3b
```

---

## 2. URL Security Analysis Flow

```mermaid
flowchart TD
    Start([URL Analysis Request]) --> Validate[Validate URL Format]
    Validate -->|Invalid| Error[Return Error]
    Validate -->|Valid| CheckCache{Check Cache}
    CheckCache -->|Hit| ReturnCached[Return Cached Result]
    CheckCache -->|Miss| GSBQuery[Query Google Safe Browsing API]
    GSBQuery --> SSLCheck{HTTPS?}
    SSLCheck -->|Yes| ValidateSSL[Validate SSL Certificate]
    SSLCheck -->|No| PatternAnalysis[Domain Pattern Analysis]
    ValidateSSL --> PatternAnalysis
    PatternAnalysis --> WHOIS[Retrieve WHOIS Data]
    WHOIS --> Aggregate[Aggregate Results]
    Aggregate --> RiskScore[Calculate Risk Score]
    RiskScore --> StoreCache[Store in Cache]
    StoreCache --> ReturnResult[Return Analysis Result]
    ReturnCached --> End([End])
    ReturnResult --> End
    Error --> End
    
    style Start fill:#4caf50
    style End fill:#f44336
    style CheckCache fill:#ff9800
    style RiskScore fill:#9c27b0
```

---

## 3. IP Reputation Analysis Flow

```mermaid
flowchart TD
    Start([IP Analysis Request]) --> Validate[Validate IP Address]
    Validate -->|Invalid| Error[Return Error]
    Validate -->|Valid| CheckCache{Check Cache}
    CheckCache -->|Hit| ReturnCached[Return Cached Result]
    CheckCache -->|Miss| AbuseIPDB[Query AbuseIPDB API]
    AbuseIPDB --> GetData[Retrieve Data]
    GetData --> Confidence[Get Confidence Score]
    GetData --> GeoLoc[Get Geolocation]
    GetData --> ASN[Get ASN Information]
    GetData --> TorCheck[Check Tor Exit Node]
    Confidence --> Classify[Classify Risk Level]
    GeoLoc --> Classify
    ASN --> Classify
    TorCheck --> Classify
    Classify -->|High/Medium| Notify[Send Telegram Alert]
    Classify --> Recommendations[Generate Recommendations]
    Recommendations --> StoreCache[Store in Cache]
    StoreCache --> ReturnResult[Return Analysis Result]
    ReturnCached --> End([End])
    ReturnResult --> End
    Notify --> ReturnResult
    Error --> End
    
    style Start fill:#4caf50
    style End fill:#f44336
    style Classify fill:#ff9800
    style Notify fill:#e91e63
```

---

## 4. Domain Security Analysis Flow

```mermaid
flowchart TD
    Start([Domain Analysis Request]) --> Validate[Validate Domain]
    Validate -->|Invalid| Error[Return Error]
    Validate -->|Valid| CheckCache{Check Cache}
    CheckCache -->|Hit| ReturnCached[Return Cached Result]
    CheckCache -->|Miss| Parallel[Parallel Analysis]
    
    Parallel --> WHOIS[WHOIS Lookup]
    Parallel --> DNS[DNS Record Analysis]
    Parallel --> SSL[SSL/TLS Certificate Chain]
    Parallel --> DNSSEC[DNSSEC Validation]
    
    WHOIS --> A[Get A Records]
    WHOIS --> AAAA[Get AAAA Records]
    WHOIS --> MX[Get MX Records]
    WHOIS --> NS[Get NS Records]
    WHOIS --> TXT[Get TXT Records]
    
    DNS --> A
    DNS --> AAAA
    DNS --> MX
    DNS --> NS
    DNS --> TXT
    
    SSL --> CertValidation[Validate Certificate Chain]
    DNSSEC --> DNSSECCheck[Check DNSSEC Status]
    
    A --> Aggregate[Aggregate Results]
    AAAA --> Aggregate
    MX --> Aggregate
    NS --> Aggregate
    TXT --> Aggregate
    CertValidation --> Aggregate
    DNSSECCheck --> Aggregate
    
    Aggregate --> SecurityCheck[Security Assessment]
    SecurityCheck --> Recommendations[Generate Recommendations]
    Recommendations --> StoreCache[Store in Cache]
    StoreCache --> ReturnResult[Return Analysis Result]
    ReturnCached --> End([End])
    ReturnResult --> End
    Error --> End
    
    style Start fill:#4caf50
    style End fill:#f44336
    style Parallel fill:#2196f3
    style SecurityCheck fill:#ff9800
```

---

## 5. Network Packet Analysis Flow

```mermaid
flowchart TD
    Start([PCAP Upload]) --> Validate[Validate File Format]
    Validate -->|Invalid| Error[Return Error]
    Validate -->|Valid| SaveFile[Save to Uploads Directory]
    SaveFile --> PyShark[PyShark Analysis]
    PyShark --> ProtocolAnalysis[Protocol Analysis]
    ProtocolAnalysis --> ExtractMetadata[Extract Metadata]
    ExtractMetadata --> CountProtocols[Count Protocols]
    CountProtocols --> GenerateChart[Generate Protocol Chart]
    
    SaveFile --> VirusTotal[Upload to VirusTotal]
    VirusTotal --> WaitScan[Wait for Scan]
    WaitScan --> GetReport[Get Scan Report]
    GetReport --> MalwareCheck{Malware Detected?}
    MalwareCheck -->|Yes| HighRisk[Mark as High Risk]
    MalwareCheck -->|No| LowRisk[Mark as Low Risk]
    
    GenerateChart --> Aggregate[Aggregate Results]
    HighRisk --> Aggregate
    LowRisk --> Aggregate
    
    Aggregate --> Notify{High Risk?}
    Notify -->|Yes| Telegram[Send Telegram Alert]
    Notify -->|No| ReturnResult[Return Analysis Result]
    Telegram --> ReturnResult
    ReturnCached --> End([End])
    ReturnResult --> End
    Error --> End
    
    style Start fill:#4caf50
    style End fill:#f44336
    style MalwareCheck fill:#ff9800
    style Notify fill:#e91e63
    style GenerateChart fill:#9c27b0
```

---

## 6. Security Scanning Workflow

```mermaid
flowchart TD
    Start([Security Scan Request]) --> SelectType{Select Scan Type}
    
    SelectType -->|Port Scan| PortScan[Nmap Port Scan]
    SelectType -->|Vulnerability| VulnScan[Vulnerability Scan]
    SelectType -->|Security Headers| HeaderScan[Security Headers Scan]
    SelectType -->|Email Security| EmailScan[Email Security Scan]
    
    PortScan --> OpenPorts[Identify Open Ports]
    OpenPorts --> ServiceVersion[Detect Service Versions]
    ServiceVersion --> PortResults[Port Scan Results]
    
    VulnScan --> CVECheck[Check CVE Database]
    CVECheck --> RiskPrioritize[Prioritize Risks]
    RiskPrioritize --> VulnResults[Vulnerability Results]
    
    HeaderScan --> CheckCSP[Check CSP Header]
    HeaderScan --> CheckHSTS[Check HSTS Header]
    HeaderScan --> CheckXFrame[Check X-Frame-Options]
    HeaderScan --> CheckOther[Check Other Headers]
    CheckCSP --> HeaderResults[Security Headers Results]
    CheckHSTS --> HeaderResults
    CheckXFrame --> HeaderResults
    CheckOther --> HeaderResults
    
    EmailScan --> CheckSPF[Check SPF Records]
    EmailScan --> CheckDKIM[Check DKIM Records]
    EmailScan --> CheckDMARC[Check DMARC Records]
    CheckSPF --> EmailResults[Email Security Results]
    CheckDKIM --> EmailResults
    CheckDMARC --> EmailResults
    
    PortResults --> Aggregate[Aggregate Results]
    VulnResults --> Aggregate
    HeaderResults --> Aggregate
    EmailResults --> Aggregate
    
    Aggregate --> ReturnResult[Return Scan Results]
    ReturnResult --> End([End])
    
    style Start fill:#4caf50
    style End fill:#f44336
    style SelectType fill:#2196f3
    style Aggregate fill:#ff9800
```

---

## 7. AI-Powered Consultation Flow

```mermaid
flowchart TD
    Start([User Query]) --> ValidateInput[Validate Input]
    ValidateInput --> KeywordCheck[Keyword-Based Topic Validation]
    KeywordCheck -->|Not Cybersecurity| Reject[Reject Query]
    KeywordCheck -->|Cybersecurity| RiskAssessment[Risk Assessment]
    RiskAssessment -->|High Risk| AddWarning[Add Advisory Warning]
    RiskAssessment -->|Low/Medium Risk| BuildPrompt[Build System Prompt]
    AddWarning --> BuildPrompt
    
    BuildPrompt --> SafetyFilter[Apply Safety Filters]
    SafetyFilter --> GeminiAPI[Query Google Gemini API]
    GeminiAPI --> ResponseCheck{Response Valid?}
    ResponseCheck -->|No| Error[Return Error]
    ResponseCheck -->|Yes| FormatResponse[Format Response]
    FormatResponse --> AddCodeExamples[Add Code Examples]
    AddCodeExamples --> ReturnResponse[Return Response]
    
    Reject --> End([End])
    Error --> End
    ReturnResponse --> End
    
    style Start fill:#4caf50
    style End fill:#f44336
    style KeywordCheck fill:#ff9800
    style RiskAssessment fill:#e91e63
    style SafetyFilter fill:#9c27b0
```

---

## 8. Caching Strategy Flow

```mermaid
flowchart TD
    Request([Incoming Request]) --> GenerateKey[Generate Cache Key]
    GenerateKey --> CheckCache{Cache Hit?}
    CheckCache -->|Yes| CheckTTL{TTL Valid?}
    CheckTTL -->|Yes| ReturnCache[Return Cached Data]
    CheckTTL -->|No| RemoveExpired[Remove Expired Entry]
    CheckCache -->|No| ProcessRequest[Process Request]
    
    RemoveExpired --> ProcessRequest
    ProcessRequest --> ExternalAPI[Call External API]
    ExternalAPI --> GetResponse[Get API Response]
    GetResponse --> CheckSize{Cache Full?}
    CheckSize -->|No| StoreCache[Store in Cache]
    CheckSize -->|Yes| LRUEvict[LRU Eviction]
    LRUEvict --> StoreCache
    StoreCache --> ReturnResponse[Return Response]
    
    ReturnCache --> End([End])
    ReturnResponse --> End
    
    style Request fill:#4caf50
    style End fill:#f44336
    style CheckCache fill:#ff9800
    style CheckTTL fill:#2196f3
    style LRUEvict fill:#e91e63
```

---

## 9. Notification System Flow

```mermaid
flowchart TD
    SecurityEvent([Security Event Detected]) --> CheckType{Event Type}
    
    CheckType -->|URL Check| URLCheck{Malicious URL?}
    CheckType -->|IP Check| IPCheck{High/Medium Risk?}
    CheckType -->|PCAP| PCAPCheck{Malware Detected?}
    
    URLCheck -->|Yes| ShouldNotify{Should Notify?}
    URLCheck -->|No| Skip[Skip Notification]
    
    IPCheck -->|Yes| CheckConfidence{Confidence > 50?}
    IPCheck -->|No| Skip
    CheckConfidence -->|Yes| ShouldNotify
    CheckConfidence -->|No| Skip
    
    PCAPCheck -->|Yes| ShouldNotify
    PCAPCheck -->|No| Skip
    
    ShouldNotify --> FormatMessage[Format Telegram Message]
    FormatMessage --> TelegramAPI[Send via Telegram API]
    TelegramAPI --> LogNotification[Log Notification]
    LogNotification --> End([End])
    
    Skip --> End
    
    style SecurityEvent fill:#4caf50
    style End fill:#f44336
    style ShouldNotify fill:#ff9800
    style TelegramAPI fill:#2196f3
```

---

## 10. Overall Request Processing Flow

```mermaid
flowchart TD
    ClientRequest([Client Request]) --> RateLimit{Rate Limit Check}
    RateLimit -->|Exceeded| RateLimitError[Return 429 Error]
    RateLimit -->|OK| ValidateInput[Input Validation]
    ValidateInput -->|Invalid| ValidationError[Return Validation Error]
    ValidateInput -->|Valid| RouteRequest{Route Request}
    
    RouteRequest -->|URL| URLFlow[URL Analysis Flow]
    RouteRequest -->|IP| IPFlow[IP Analysis Flow]
    RouteRequest -->|Domain| DomainFlow[Domain Analysis Flow]
    RouteRequest -->|PCAP| PCAPFlow[PCAP Analysis Flow]
    RouteRequest -->|Scan| ScanFlow[Security Scan Flow]
    RouteRequest -->|Chat| ChatFlow[AI Consultation Flow]
    
    URLFlow --> CacheCheck{Check Cache}
    IPFlow --> CacheCheck
    DomainFlow --> CacheCheck
    PCAPFlow --> ProcessPCAP[Process PCAP]
    ScanFlow --> ProcessScan[Process Scan]
    ChatFlow --> ProcessChat[Process Chat]
    
    CacheCheck -->|Hit| ReturnCached[Return Cached]
    CacheCheck -->|Miss| ProcessRequest[Process Request]
    
    ProcessRequest --> ExternalAPI[Call External APIs]
    ExternalAPI --> AggregateResults[Aggregate Results]
    AggregateResults --> FormatResponse[Format Response]
    FormatResponse --> StoreCache[Store in Cache]
    StoreCache --> CheckNotify{High Risk?}
    
    ProcessPCAP --> AggregateResults
    ProcessScan --> AggregateResults
    ProcessChat --> FormatResponse
    
    CheckNotify -->|Yes| SendNotification[Send Telegram Alert]
    CheckNotify -->|No| ReturnResponse[Return Response]
    SendNotification --> ReturnResponse
    ReturnCached --> ReturnResponse
    ReturnResponse --> End([End])
    
    RateLimitError --> End
    ValidationError --> End
    
    style ClientRequest fill:#4caf50
    style End fill:#f44336
    style RateLimit fill:#ff9800
    style CacheCheck fill:#2196f3
    style CheckNotify fill:#e91e63
```

---

## 11. System Component Interaction Diagram

```mermaid
graph LR
    subgraph "Client Layer"
        WebApp[Web Application]
        MobileApp[Mobile App]
        CLI[CLI Tool]
    end
    
    subgraph "API Layer"
        FlaskAPI[Flask REST API]
        RateLimiter[Rate Limiter]
        CORS[CORS Handler]
    end
    
    subgraph "Service Layer"
        URLService[URL Service]
        IPService[IP Service]
        DomainService[Domain Service]
        PCAPService[PCAP Service]
        AIService[AI Service]
        ScanService[Scan Service]
    end
    
    subgraph "External APIs"
        GSB[Google Safe Browsing]
        AbuseIPDB[AbuseIPDB]
        VirusTotal[VirusTotal]
        Gemini[Google Gemini]
    end
    
    subgraph "Utilities"
        Cache[TTL Cache]
        Logger[Logger]
        Validator[Validator]
    end
    
    subgraph "Notification"
        Telegram[Telegram Bot]
    end
    
    WebApp --> FlaskAPI
    MobileApp --> FlaskAPI
    CLI --> FlaskAPI
    
    FlaskAPI --> RateLimiter
    RateLimiter --> CORS
    CORS --> URLService
    CORS --> IPService
    CORS --> DomainService
    CORS --> PCAPService
    CORS --> AIService
    CORS --> ScanService
    
    URLService --> GSB
    URLService --> Cache
    IPService --> AbuseIPDB
    IPService --> Cache
    DomainService --> Cache
    PCAPService --> VirusTotal
    AIService --> Gemini
    
    URLService --> Telegram
    IPService --> Telegram
    PCAPService --> Telegram
    
    URLService --> Logger
    IPService --> Logger
    DomainService --> Logger
    PCAPService --> Logger
    AIService --> Logger
    ScanService --> Logger
    
    FlaskAPI --> Validator
    
    style FlaskAPI fill:#e1f5ff
    style Cache fill:#ffeb3b
    style Telegram fill:#4caf50
```

---

## Usage Instructions

1. Copy any diagram code block (between the ```mermaid markers)
2. Go to https://mermaid.live/ or use any Mermaid-compatible tool
3. Paste the code into the editor
4. Export as PNG, SVG, or PDF
5. Use the exported images in your LaTeX document

---

## Notes

- All diagrams use standard Mermaid syntax
- Colors are applied for better visualization
- Each diagram can be customized by modifying the style attributes
- For LaTeX, PNG format at 300 DPI is recommended
- SVG format provides better scalability for vector graphics
