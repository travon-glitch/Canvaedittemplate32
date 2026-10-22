# Canva Template Importer

A small local web app. Drop in a PDF (or a PPTX, DOCX, AI, PSD or XLSX file), click **Send to Canva**, and you get back a link to an editable Canva design in your own account.

It uses Canva's official [Connect API, Design Import](https://www.canva.dev/docs/connect/api-reference/design-imports/). You need **Node.js 18 or newer**. There's nothing else to install.

## One-time setup (about 5 minutes)

1. **Create a Canva integration.** Go to https://www.canva.com/developers/integrations, click **Create an integration**, and choose **Private** (only your team can use it).
2. **Configuration tab:**
   - Copy the **Client ID**.
   - Click **Generate secret** and copy the **Client secret**.
3. **Scopes tab:** turn on
   - `design:content`: **Write**
   - `design:meta`: **Read**
4. **Authentication tab:** add this redirect URL exactly:
   ```
   http://127.0.0.1:3001/oauth/callback
   ```
5. In this folder, copy `.env.example` to `.env` and paste in your client ID and secret.

## Run it

```bash
npm start    # or: node server.js
```

Open **http://127.0.0.1:3001**, click **Connect Canva** and approve. Then drop in your file.

Your Canva sign-in is saved in `.canva-token.json` in this folder, so you only connect once. Click **Disconnect** or delete that file to sign out. Keep `.env` and `.canva-token.json` private.

## Notes

- Each PDF page becomes a Canva page, and text, shapes and images stay editable.
- Fonts Canva doesn't have get replaced with similar ones, so check the headlines after an import.
- To use the result as a reusable template, open it in Canva and use **File → Make a copy** for each new listing. On Canva Teams you can also use **Share → Template link**.
- If you change `PORT`, update the redirect URL in your Canva integration to match.
