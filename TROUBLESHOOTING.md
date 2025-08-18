# CyberRegis Troubleshooting Guide

## Issues Resolved

### 1. ✅ Missing `/api/monitoring-results` Endpoint
- **Added**: `/api/monitoring-results` (GET) - Returns system status and available endpoints
- **Added**: `/api/health` (GET) - Basic health check
- **Added**: `/api/status` (GET) - Detailed system metrics (requires psutil)
- **Added**: `/api/test` (GET/POST/OPTIONS) - CORS test endpoint

### 2. ✅ CORS Configuration Enhanced
- **Enhanced CORS setup** with specific origins
- **Added preflight handler** for OPTIONS requests
- **Proper headers** for cross-origin requests

### 3. ✅ Dependencies Updated
- **Added**: `psutil` for system monitoring
- **Enhanced**: CORS handling with proper preflight support

### 4. ✅ Fixed 500 Error in `/api/check-url`
- **Resolved naming conflict** between `analyze_domain` function and endpoint
- **Enhanced error handling** with detailed logging
- **Added fallback** for missing Google Safe Browsing API key
- **Added test endpoint** `/api/test-url` for debugging

### 5. ✅ Fixed 500 Error in `/api/security-file-content`
- **Enhanced error handling** for external HTTP requests (503, 404, timeouts)
- **Added specific error codes** for different failure scenarios
- **Improved logging** with detailed request information
- **Added test endpoint** `/api/test-security-file` for connectivity testing
- **Better timeout handling** and connection error management

### 6. ✅ Fixed Port Scanner Root Privilege Issues
- **Replaced SYN scans (-sS)** with TCP Connect scans (-sT) - no root required
- **Added fallback scanning** using basic socket connections when nmap fails
- **Enhanced error handling** for privilege-related issues
- **Added comprehensive logging** for debugging scan issues
- **Created test script** `test_port_scanner.py` for verification

## New Endpoints Available

### Monitoring & Health
```bash
# Get monitoring results (fixes your frontend error)
GET /api/monitoring-results

# Health check
GET /api/health

# System status with metrics
GET /api/status

# CORS test endpoint
GET/POST /api/test

# URL validation test (for debugging)
POST /api/test-url
{"url": "https://example.com"}

# Security file connectivity test (for debugging)
POST /api/test-security-file
{"file_type": "robots", "domain": "example.com"}

# Security file content fetch
POST /api/security-file-content
{"file_type": "robots", "domain": "example.com"}
```

### Security Scanners
```bash
# Port scanning
POST /api/scan-ports
{"target": "192.168.1.1"}

# Vulnerability assessment
POST /api/vulnerability-scan
{"target": "192.168.1.1"}

# SSL/TLS analysis
POST /api/ssl-analysis
{"domain": "example.com"}

# Security headers check
POST /api/security-headers
{"url": "https://example.com"}

# Email security analysis
POST /api/email-security
{"domain": "example.com"}
```

## Frontend React Hydration Fix

### Issue: Time Mismatch
The hydration error occurs because server and client render different times.

### Solution Options:

#### Option 1: Use Client-Side Only Rendering
```tsx
'use client'

import { useEffect, useState } from 'react'

export default function TimeComponent() {
  const [time, setTime] = useState('')
  
  useEffect(() => {
    const updateTime = () => {
      setTime(new Date().toLocaleTimeString())
    }
    updateTime()
    const interval = setInterval(updateTime, 1000)
    return () => clearInterval(interval)
  }, [])
  
  return <div>{time}</div>
}
```

#### Option 2: Suppress Hydration Warning
```tsx
'use client'

import { useEffect, useState } from 'react'

export default function TimeComponent() {
  const [mounted, setMounted] = useState(false)
  const [time, setTime] = useState('')
  
  useEffect(() => {
    setMounted(true)
    const updateTime = () => {
      setTime(new Date().toLocaleTimeString())
    }
    updateTime()
    const interval = setInterval(updateTime, 1000)
    return () => clearInterval(interval)
  }, [])
  
  if (!mounted) return <div>Loading...</div>
  
  return <div>{time}</div>
}
```

## Testing Your Backend

### 1. Use the Debug Script
```bash
# Run the debug script to test all endpoints
python debug_endpoints.py
```

### 2. Use the Security File Test Script
```bash
# Run the specialized security file testing script
python test_security_files.py
```

### 3. Use the Port Scanner Test Script
```bash
# Run the port scanner testing script (no root required)
python test_port_scanner.py
```

### 2. Test CORS with curl
```bash
# Test preflight request
curl -X OPTIONS http://localhost:4000/api/test \
  -H "Origin: http://localhost:3000" \
  -H "Access-Control-Request-Method: POST" \
  -H "Access-Control-Request-Headers: Content-Type" \
  -v

# Test actual request
curl -X GET http://localhost:4000/api/test \
  -H "Origin: http://localhost:3000" \
  -v
```

### 3. Test monitoring endpoint
```bash
curl http://localhost:4000/api/monitoring-results
```

### 4. Test URL check endpoint
```bash
curl -X POST http://localhost:4000/api/check-url \
  -H "Content-Type: application/json" \
  -d '{"url": "https://google.com"}'
```

### 5. Test URL validation endpoint
```bash
curl -X POST http://localhost:4000/api/test-url \
  -H "Content-Type: application/json" \
  -d '{"url": "https://example.com"}'
```

### 6. Test security file connectivity
```bash
curl -X POST http://localhost:4000/api/test-security-file \
  -H "Content-Type: application/json" \
  -d '{"file_type": "robots", "domain": "google.com"}'
```

### 7. Test security file content fetch
```bash
curl -X POST http://localhost:4000/api/security-file-content \
  -H "Content-Type: application/json" \
  -d '{"file_type": "robots", "domain": "google.com"}'
```

## Installation

### Install new dependencies
```bash
pip install -r requirements.txt
```

### Restart your Flask server
```bash
python KALE.py
```

## Frontend Integration

### Update your frontend API calls
```typescript
// Example: Fetch monitoring results
const fetchMonitoringResults = async () => {
  try {
    const response = await fetch('http://localhost:4000/api/monitoring-results', {
      method: 'GET',
      headers: {
        'Content-Type': 'application/json',
      },
    })
    
    if (!response.ok) {
      throw new Error(`HTTP error! status: ${response.status}`)
    }
    
    const data = await response.json()
    return data
  } catch (error) {
    console.error('Error fetching monitoring results:', error)
    throw error
  }
}

// Example: Check URL safety
const checkUrlSafety = async (url: string) => {
  try {
    const response = await fetch('http://localhost:4000/api/check-url', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ url }),
    })
    
    if (!response.ok) {
      const errorData = await response.json()
      throw new Error(errorData.message || `HTTP error! status: ${response.status}`)
    }
    
    const data = await response.json()
    return data
  } catch (error) {
    console.error('Error checking URL safety:', error)
    throw error
  }
}
```

## Common Issues & Solutions

### 1. CORS Still Not Working?
- Check if your Flask server is running on port 4000
- Verify frontend is on port 3000
- Check browser console for specific CORS errors
- Run the debug script to test endpoints

### 2. Endpoint Not Found?
- Ensure Flask server is running
- Check the endpoint URL matches exactly
- Verify the HTTP method (GET vs POST)
- Check server logs for any startup errors

### 3. 500 Internal Server Error?
- Check server console for detailed error messages
- Verify all dependencies are installed
- Test with the debug script first
- Check if API keys are configured (Google Safe Browsing)

### 4. React Hydration Errors?
- Use client-side rendering for time-sensitive components
- Implement proper loading states
- Avoid server/client time differences

## Debugging Steps

### 1. Check Server Logs
When you get a 500 error, check your Flask server console for:
- Detailed error messages
- Stack traces
- Print statements from the enhanced error handling

### 2. Use the Debug Script
```bash
python debug_endpoints.py
```
This will test all endpoints and show exactly where the problem is.

### 3. Test Individual Endpoints
Start with simple endpoints like `/api/health` and work your way up to more complex ones.

### 4. Check API Keys
Ensure your Google Safe Browsing API key is valid, or the system will use fallback checks.

## Next Steps

1. **Restart your Flask server** with the updated code
2. **Run the debug script** to test all endpoints
3. **Check server logs** for any error messages
4. **Test the URL check endpoint** with the debug script
5. **Update your frontend** to use the correct endpoints
6. **Fix React hydration** using the provided solutions
7. **Test the full integration** between frontend and backend

## Support

If you continue to experience issues:
1. Check Flask server logs for errors
2. Run the debug script and share the output
3. Verify all dependencies are installed
4. Test endpoints individually with curl
5. Check browser console for specific error messages
