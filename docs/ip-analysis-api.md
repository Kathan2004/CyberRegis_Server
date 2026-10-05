# IP Analysis API Documentation

## Overview

The enhanced IP Analysis API provides comprehensive security analysis of IP addresses by integrating multiple threat intelligence sources including VirusTotal, AbuseIPDB, and geolocation services. This API returns detailed security assessments with risk scores, threat categories, and actionable recommendations.

## Endpoint

```
POST /api/check-ip
```

## Request Format

### Headers
```
Content-Type: application/json
```

### Request Body
```json
{
  "ip": "8.8.8.8"
}
```

### Parameters
- `ip` (string, required): IPv4 address to analyze (e.g., "8.8.8.8")

## Response Structure

### Success Response (200 OK)
```json
{
  "status": "success",
  "timestamp": "2024-01-15T10:30:00Z",
  "data": {
    "ip_details": {
      "address": "8.8.8.8",
      "domain": "dns.google",
      "isp": "Google LLC",
      "location": {
        "city": "Mountain View",
        "region": "California",
        "country": "United States",
        "country_code": "US"
      }
    },
    "risk_assessment": {
      "risk_level": "Low",
      "confidence_score": 15,
      "total_reports": 5,
      "last_reported": "2024-01-15T10:30:00Z",
      "categories": ["clean"]
    },
    "technical_details": {
      "as_name": "AS15169 - Google LLC",
      "asn": "AS15169",
      "is_public": true,
      "is_tor": false,
      "usage_type": "ISP",
      "organization": "Google LLC"
    },
    "virustotal": {
      "risk_assessment": {
        "risk_score": 12,
        "risk_level": "LOW",
        "malicious_count": 2,
        "suspicious_count": 1,
        "detection_ratio": "3/85",
        "total_engines": 85
      },
      "metadata": {
        "reputation": 25,
        "file_type": "IP Address",
        "analysis_date": 1705312200
      },
      "data": {
        "attributes": {
          "stats": {
            "malicious": 2,
            "suspicious": 1,
            "harmless": 82,
            "total": 85
          },
          "results": {
            "engine1": {"category": "malicious", "result": "detected"},
            "engine2": {"category": "harmless", "result": "clean"}
          }
        }
      }
    },
    "virustotal_summary": "IP 8.8.8.8 has been flagged by 3 out of 85 security engines as potentially malicious (Risk Level: LOW).",
    "recommendations": [
      "Continue monitoring this IP address for any changes in behavior",
      "Consider this IP as potentially safe but maintain vigilance"
    ]
  }
}
```

### Error Response (400 Bad Request)
```json
{
  "status": "error",
  "error": "Invalid IP format",
  "message": "Please provide a valid IPv4 address (e.g., 192.168.1.1)"
}
```

### Error Response (500 Internal Server Error)
```json
{
  "status": "error",
  "error": "Analysis failed",
  "message": "VirusTotal API timeout",
  "timestamp": "2024-01-15T10:30:00Z"
}
```

## Response Fields

### Top Level
- `status`: Response status ("success" or "error")
- `timestamp`: ISO 8601 timestamp of the analysis
- `data`: Main analysis data (present only on success)
- `error`: Error type (present only on error)
- `message`: Error description (present only on error)

### IP Details (`data.ip_details`)
- `address`: The analyzed IP address
- `domain`: Associated domain name (if available)
- `isp`: Internet Service Provider
- `location`: Geographic location information
  - `city`: City name
  - `region`: State/region name
  - `country`: Country name
  - `country_code`: ISO country code

### Risk Assessment (`data.risk_assessment`)
- `risk_level`: Overall risk level ("High", "Medium", "Low", "Unknown")
- `confidence_score`: Confidence score from 0-100
- `total_reports`: Total number of abuse reports
- `last_reported`: Timestamp of last abuse report
- `categories`: Array of threat categories (e.g., ["malware", "phishing", "botnet"])

### Technical Details (`data.technical_details`)
- `as_name`: Autonomous System name
- `asn`: Autonomous System Number
- `is_public`: Whether the IP is public (true/false)
- `is_tor`: Whether the IP is a TOR exit node (true/false)
- `usage_type`: Type of usage (ISP, TOR Exit Node, Malicious, etc.)
- `organization`: Organization name

### VirusTotal Analysis (`data.virustotal`)
- `risk_assessment`: VirusTotal-specific risk assessment
  - `risk_score`: Risk score from 0-100
  - `risk_level`: Risk level ("HIGH", "MEDIUM", "LOW", "VERY_LOW", "UNKNOWN")
  - `malicious_count`: Number of malicious detections
  - `suspicious_count`: Number of suspicious detections
  - `detection_ratio`: Ratio of detections to total engines
  - `total_engines`: Total number of security engines
- `metadata`: Additional metadata
  - `reputation`: Reputation score
  - `file_type`: Type of analyzed item
  - `analysis_date`: Last analysis timestamp
- `data`: Raw VirusTotal data structure

### Summary and Recommendations
- `virustotal_summary`: Human-readable summary of VirusTotal analysis
- `recommendations`: Array of actionable security recommendations

## Threat Categories

The API identifies the following threat categories:

- `malware`: Associated with malware distribution
- `phishing`: Used in phishing campaigns
- `botnet`: Part of a botnet network
- `tor_exit_node`: TOR exit node
- `public_proxy`: Public proxy server
- `clean`: No threats detected
- `unknown`: Unable to determine threat level

## Risk Levels

### AbuseIPDB Risk Levels
- **High**: Abuse confidence score > 75 OR total reports > 50
- **Medium**: Abuse confidence score > 50 OR total reports > 20
- **Low**: Below Medium thresholds

### VirusTotal Risk Levels
- **HIGH**: Risk score ≥ 75
- **MEDIUM**: Risk score ≥ 50
- **LOW**: Risk score ≥ 25
- **VERY_LOW**: Risk score < 25
- **UNKNOWN**: Unable to determine

## Rate Limiting

- **Limit**: 20 requests per minute per IP address
- **Headers**: Rate limit information is included in response headers

## Error Codes

| HTTP Status | Error Type | Description |
|-------------|------------|-------------|
| 400 | Invalid IP format | IP address format is invalid |
| 400 | IP address required | No IP address provided |
| 400 | No data provided | Empty request body |
| 500 | Analysis failed | Backend analysis error |
| 500 | Internal server error | Unexpected server error |

## Performance

- **Response Time**: Typically < 5 seconds
- **Timeout**: 30 seconds for external API calls
- **Caching**: Results cached for 1 hour (TTL)

## Dependencies

### External APIs
- **VirusTotal**: Malware analysis and reputation
- **AbuseIPDB**: IP reputation and abuse reports
- **IP-API**: Fallback geolocation service

### API Keys Required
- `VIRUSTOTAL_API_KEY`: VirusTotal API key
- `ABUSEIPDB_API_KEY`: AbuseIPDB API key

## Example Usage

### cURL
```bash
curl -X POST http://localhost:4000/api/check-ip \
  -H "Content-Type: application/json" \
  -d '{"ip": "8.8.8.8"}'
```

### Python
```python
import requests

response = requests.post(
    "http://localhost:4000/api/check-ip",
    json={"ip": "8.8.8.8"},
    headers={"Content-Type": "application/json"}
)

if response.status_code == 200:
    data = response.json()
    risk_level = data["data"]["risk_assessment"]["risk_level"]
    print(f"Risk Level: {risk_level}")
else:
    print(f"Error: {response.json()}")
```

### JavaScript/Node.js
```javascript
const response = await fetch('http://localhost:4000/api/check-ip', {
  method: 'POST',
  headers: {
    'Content-Type': 'application/json',
  },
  body: JSON.stringify({ ip: '8.8.8.8' })
});

const data = await response.json();
if (data.status === 'success') {
  const riskLevel = data.data.risk_assessment.risk_level;
  console.log(`Risk Level: ${riskLevel}`);
} else {
  console.error(`Error: ${data.error}`);
}
```

## Testing

Use the provided test script to verify functionality:

```bash
python test_ip_analysis.py
```

## Monitoring

The API logs all requests and errors to `security_checker.log` with detailed information about:
- Request processing
- External API calls
- Error conditions
- Performance metrics

## Security Considerations

- Input validation for IP addresses
- Rate limiting to prevent abuse
- API key protection
- Error message sanitization
- Request logging for audit trails

## Troubleshooting

### Common Issues

1. **VirusTotal API errors**
   - Check API key validity
   - Verify rate limits
   - Check network connectivity

2. **Slow response times**
   - External API timeouts
   - Network latency
   - High server load

3. **Missing data**
   - API key configuration
   - External service availability
   - Rate limiting

### Debug Steps

1. Check server logs (`security_checker.log`)
2. Verify API keys are configured
3. Test external API connectivity
4. Monitor rate limiting
5. Check network connectivity

## Changelog

### Version 2.0 (Current)
- Enhanced VirusTotal integration
- Comprehensive risk assessment
- Multiple threat intelligence sources
- Improved error handling
- Performance optimizations
- Enhanced response structure

### Version 1.0 (Previous)
- Basic IP reputation checking
- Simple risk assessment
- Limited threat categories
- Basic error handling
