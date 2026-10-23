# Canva Template Importer

A small web app. Drop in a PDF (or a PPTX, DOCX, AI, PSD or XLSX file), click **Send to Canva**, and you get back a link to an editable Canva design in your own Canva account.

It uses Canva's official [Connect API, Design Import](https://www.canva.dev/docs/connect/api-reference/design-imports/). It runs on **Vercel** or locally with **Node.js 18+**.

## Project layout

```
public/index.html     the upload page
api/                  Vercel serverless functions (sign-in, import, large-file upload)
lib/canva.js          shared Canva logic
server.js             local server (not used on Vercel)
```

## 1. Create the Canva integration (one time)

1. Go to https://www.canva.com/developers/integrations, click **Create an integration**, and choose **Private**. Only people on your Canva team can sign in with it.
2. **Configuration tab:** copy the **Client ID**, then click **Generate secret** and copy the **Client secret**.
3. **Scopes tab:** turn on `design:content` **Write** and `design:meta` **Read**.
4. **Authentication tab:** add a redirect URL for each place you run the app:
   - Vercel: `https://YOUR-APP.vercel.app/api/oauth/callback`
   - Local: `http://127.0.0.1:3001/api/oauth/callback`

## 2. Deploy on Vercel

1. In Vercel, **Add New → Project** and import this GitHub repo. Framework preset: **Other**. Leave the build settings empty.
2. **Settings → Environment Variables**, add:
   - `CANVA_CLIENT_ID`
   - `CANVA_CLIENT_SECRET`
   - `SESSION_SECRET`: optional. Any long random string, used to encrypt sign-in cookies.
3. **Deployments → Redeploy** so the variables take effect.
4. Make sure your Vercel URL + `/api/oauth/callback` is in the Canva integration's redirect URLs (step 1.4).

Every push to `main` redeploys automatically.

### Large files (optional, recommended)

Vercel limits a direct upload to about **4.4 MB**. To allow files up to **200 MB**:

1. In your Vercel project, open **Storage → Create → Blob**. Give it a name, choose **public** access, and connect it to this project.
2. Vercel adds the `BLOB_READ_WRITE_TOKEN` variable automatically. **Redeploy**.

Big files then upload straight from the browser to Vercel Blob. Canva imports them from there using its [URL import API](https://www.canva.dev/docs/connect/api-reference/design-imports/create-url-import-job/), which Canva labels as a preview, and the temporary file is deleted afterward. Files under 4.4 MB keep using the direct upload.

## Troubleshooting

- **"Setup needed"** on the page: the Canva keys aren't set in Vercel. Add them and redeploy.
- **"Canva sign-in failed … redirect"**: the redirect URL in your Canva integration must exactly match `https://YOUR-APP.vercel.app/api/oauth/callback`.
- **"Too large"**: set up a Blob store (above), or compress the file.

## Run locally

```bash
cp .env.example .env    # paste in your client ID and secret
npm install
npm start
```

Open **http://127.0.0.1:3001**, click **Connect Canva** and approve. Then drop in your file.

Opening `public/index.html` directly in a browser, without the server, shows a **preview mode** where imports are simulated.

## How sign-in works

Each person who opens the app connects their **own** Canva account, and designs go into that account. The sign-in is stored in an encrypted, HTTP-only browser cookie for up to 90 days. Nothing is saved on the server. **Disconnect** clears it.

## Notes

- Each PDF page becomes a Canva page, and text, shapes and images stay editable.
- Fonts Canva doesn't have get replaced with similar ones, so check the headlines after an import.
- To use the result as a reusable template, open it in Canva and use **File → Make a copy** for each new listing. On Canva Teams you can also use **Share → Template link**.
