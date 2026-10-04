# ScamCheck PH v6 — Deployment Checklist

## Source
1. Create a GitHub/GitLab/Bitbucket repository.
2. Upload the contents of this folder to the repository root.
3. Commit `render.yaml` on the default branch.

## Render
1. Open Render Dashboard → Blueprints → New Blueprint Instance.
2. Select the repository containing `render.yaml`.
3. Review the Web Service and PostgreSQL resource before applying.
4. Fill all variables marked `sync: false`.
5. Set `APP_BASE_URL` to the final HTTPS URL.
6. Deploy.

## Production providers
- PayMongo: production secret key + webhook secret; verify the webhook endpoint.
- Resend: verified sending domain + API key + sender address.
- S3-compatible storage: private bucket, restricted credentials, malware scanning/retention policy.

## Database
Run `npm run migrate:pg` once the production `DATABASE_URL` is available and before serving real traffic if the schema is not already initialized.

## Verification
- `GET /api/health` returns HTTP 200.
- `npm run prod:check` passes with production variables.
- Register/login, report, save, DeepCheck checkout, and webhook flows are tested in provider test mode before enabling real payments.
