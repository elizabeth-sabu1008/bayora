# BAYORA — Sealed AI Safety Evaluation Environment

BAYORA is a secure, verifiable evaluation platform designed for red/blue LLM security testing with strict tenant isolation, cryptographic audit trails, sandboxed defense execution, and side-channel timing mitigation.

Built with **Express + TypeScript + Vite + React 19 + Tailwind CSS**.

---

## ⚙️ Environment Configuration

Copy `.env.example` to `.env.local` for local development or configure these variables directly in your hosting dashboard:

| Variable | Required | Default | Description |
| :--- | :--- | :--- | :--- |
| `GEMINI_API_KEY` | **Yes** (for live AI) | — | Google Gemini API key for live inference and automated red/blue generation. |
| `GEMINI_MODEL` | No | `gemini-3.8-flash` | Primary Gemini model ID used for inference and red/blue generator agents. |
| `GEMINI_FALLBACK_MODEL` | No | `gemini-3.5-flash-lite` | Secondary fallback model if primary model encounters 503/429 high demand. |
| `PORT` | No | `3000` | Port for the Express server. |
| `NODE_ENV` | No | `development` | Environment mode (`development` or `production`). |
| `VLLM_BASE_URL` | No | — | Optional base URL of a vLLM inference server (e.g. `http://localhost:8000`) for live Prometheus KV-cache metrics. |

> **Security Note:** Never commit `.env` or `.env.local` to source control. They are strictly excluded in `.gitignore`. No secret keys are ever exposed or bundled into client-side code.

---

## 💻 Local Development

**Prerequisites:** Node.js 18+ (tested on Node.js 20/22/24)

1. **Install dependencies:**
   ```bash
   npm install --legacy-peer-deps
   ```

2. **Configure your Gemini API key:**
   Create `.env.local` in the project root:
   ```env
   GEMINI_API_KEY=AQ.Ab8RN6IfqJlzSNFgTlh03HJz1wno8fvuCliUFDO52DXQLC9XSQ
   GEMINI_MODEL=gemini-3.8-flash
  
   ```

3. **Start the development server:**
   ```bash
   npm run dev
   ```
   Open `https://bayora-l6eq.onrender.com/` in your browser.

---

## 🚀 Production Deployment

Deploying to hosts such as **Google Cloud Run**, **Render**, **Railway**, **Vercel**, or a custom VM/Docker container:

### Deployment Steps

1. **Set Environment Variables on the Host Dashboard:**
   In your host's Settings / Environment Variables section, configure:
   - `GEMINI_API_KEY`: Your Google Gemini API key
   - `NODE_ENV`: `production`
   - `PORT`: `3000` (or host-provided `$PORT`)
   - `GEMINI_MODEL`: `gemini-3.8-flash` (optional)
   - `VLLM_BASE_URL`: `http://your-vllm-host:8000` (optional, for GPU cache telemetry)

2. **Build the production frontend bundle:**
   ```bash
   npm run build
   ```
   This generates the optimized static assets in `./dist`.

3. **Start the production server:**
   ```bash
   NODE_ENV=production npm start
   ```
   (On platforms like Render/Railway, specify `npm run build` as the Build Command and `NODE_ENV=production npm start` as the Start Command).

---

### Platform-Specific Deployment Guides

#### Google Cloud Run
```bash
# Build & deploy container or source:
gcloud run deploy bayora \
  --source . \
  --set-env-vars GEMINI_API_KEY="your-api-key",NODE_ENV="production" \
  --allow-unauthenticated
```

#### Render
1. Create a **New Web Service** connected to your repository.
2. Set **Build Command**: `npm install --legacy-peer-deps && npm run build`
3. Set **Start Command**: `NODE_ENV=production npm start`
4. Add **Environment Variable**: `GEMINI_API_KEY` = your Gemini API key.

#### Railway
1. Deploy from GitHub repository.
2. In **Variables**, add `GEMINI_API_KEY` and `NODE_ENV=production`.
3. In **Settings**, set Build Command: `npm install --legacy-peer-deps && npm run build` and Start Command: `npm start`.

---

## 📡 API Endpoints

### System Health
- **`GET /api/health`**
  Returns server health and whether Gemini and vLLM are configured:
  ```json
  {
    "status": "ok",
    "geminiConfigured": true,
    "geminiModel": "gemini-3.8-flash",
    "vllmConfigured": false,
    "time": "2026-10-27T12:00:00.000Z"
  }
  ```

### vLLM Cache Telemetry
- **`GET /api/vllm/metrics`**
  - If `VLLM_BASE_URL` is set, streams and parses real Prometheus metrics from `${VLLM_BASE_URL}/metrics`.
  - If unset, returns:
    ```json
    {
      "connected": false,
      "status": "unavailable",
      "message": "vLLM not connected - cache metrics unavailable",
      "metrics": null
    }
    ```

### Live LLM & Red-Teaming Endpoints
*Note: Returns `503 Service Unavailable` with `{"error": "GEMINI_API_KEY not configured on server"}` if `GEMINI_API_KEY` is missing.*
- **`POST /api/llm/query`**: Queries Gemini LLM under evaluation with prompt and system prompt.
- **`POST /api/llm/generate-attacks`**: Automated Red Team Agent generates diverse jailbreak attacks at runtime.
- **`POST /api/llm/generate-defense`**: Automated Blue Team Agent drafts sandboxed defense JS functions.
- **`POST /api/llm/adaptive-attack`**: Generates adaptive attack prompts based on prior coarse verdicts.

---

## 🧪 Testing & Verification

Run TypeScript linting and build validation:
```bash
# Type-check
npm run lint

# Production build
npm run build
```
