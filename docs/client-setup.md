# CyberRegis Client

## Prerequisites
- Node.js 18+
- npm

## 1) Clone your client repository
```bash
git clone <your-client-repo-url>
cd <your-client-folder>
```

## 2) Install dependencies
```bash
npm install
```

## 3) Configure environment
Create `.env.local` in the client root:

```env
NEXT_PUBLIC_API_BASE_URL=http://127.0.0.1:5000
```

## 4) Run client
```bash
npm run dev
```

Client endpoint (default):
- `http://127.0.0.1:3000`

## 5) Build for production
```bash
npm run build
npm start
```

## Notes
- These are normal local startup commands (no proxy-bypass commands).
- Ensure server is running before using client features that call APIs.
