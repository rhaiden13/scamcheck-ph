#!/usr/bin/env node
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const root = path.join(__dirname, '..');
const data = path.join(root, 'data');
const read = (name) => {
  const f = path.join(data, name + '.json');
  try { return JSON.parse(fs.readFileSync(f, 'utf8')); } catch { return []; }
};
const iso = (v) => v ? new Date(v) : null;
const dbUrl = process.env.DATABASE_URL;
if (!dbUrl) {
  console.error('DATABASE_URL is required. Refusing to migrate without an explicit database target.');
  process.exit(1);
}
const { Pool } = require('pg');
const pool = new Pool({ connectionString: dbUrl, max: 5, ssl: process.env.PGSSL === 'disable' ? false : { rejectUnauthorized: false } });
const q = (text, params=[]) => pool.query(text, params);

(async () => {
  await q(`CREATE TABLE IF NOT EXISTS migration_meta (key TEXT PRIMARY KEY, value TEXT NOT NULL)`);
  await q('BEGIN');
  const users = read('users');
  const sessions = read('sessions');
  const scans = read('scans');
  const scams = read('scams');
  const reports = read('reports');
  const deepchecks = read('deepchecks');
  const saved = read('saved-checks');
  const notifications = read('notifications');
  const resets = read('password-resets');
  const keys = read('api-keys');
  const audit = read('audit');

  for (const u of users) await q(`INSERT INTO users (id,email,password_hash,username,role,status,display_name,email_verified,created_at,updated_at)
    VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10) ON CONFLICT (id) DO NOTHING`,
    [u.id,u.email,u.passwordHash,u.username || 'user',u.role || 'user',u.status || 'active',u.displayName || u.email,u.emailVerified !== false,iso(u.createdAt)||new Date(),iso(u.updatedAt)]);
  for (const s of sessions) await q(`INSERT INTO sessions (token_hash,user_id,created_at,expires_at) VALUES ($1,$2,$3,$4) ON CONFLICT DO NOTHING`,
    [crypto.createHash('sha256').update(String(s.token)).digest('hex'),s.userId,iso(s.createdAt)||new Date(),iso(s.expiresAt)||new Date()]);
  for (const s of scans) await q(`INSERT INTO scans (id,user_id,created_at,input_type,preview,result) VALUES ($1,$2,$3,$4,$5,$6) ON CONFLICT DO NOTHING`,
    [s.id,s.userId||null,iso(s.createdAt)||new Date(),s.inputType||'message',s.preview||'',s.result||{}]);
  for (const s of scams) await q(`INSERT INTO scams (id,target,normalized,type,status,reports,note,last_reviewed) VALUES ($1,$2,$3,$4,$5,$6,$7,$8)
    ON CONFLICT (normalized) DO UPDATE SET status=EXCLUDED.status,reports=EXCLUDED.reports,note=EXCLUDED.note,last_reviewed=EXCLUDED.last_reviewed`,
    [s.id,s.target,s.normalized||String(s.target||'').toLowerCase(),s.type||'Entity',s.status||'reported',Number(s.reports||0),s.note||'',iso(s.lastReviewed)]);
  for (const r of reports) await q(`INSERT INTO reports (id,user_id,created_at,category,target,description,incident_date,amount_lost,status,evidence_count,reviewed_at,reviewed_by,review_note,report_counted,report_counted_at)
    VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15) ON CONFLICT DO NOTHING`,
    [r.id,r.userId||null,iso(r.createdAt)||new Date(),r.category||'other',r.target||'',r.description||'',r.incidentDate?new Date(r.incidentDate):null,r.amountLost==null?null:Number(r.amountLost),r.status||'submitted',Number(r.evidenceCount||0),iso(r.reviewedAt),r.reviewedBy||null,r.reviewNote||null,!!r.reportCounted,iso(r.reportCountedAt)]);
  for (const d of deepchecks) await q(`INSERT INTO deepchecks (order_id,user_id,created_at,updated_at,price,status,target,type,context,evidence_count,evidence,result)
    VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12) ON CONFLICT DO NOTHING`,
    [d.orderId,d.userId,iso(d.createdAt)||new Date(),iso(d.updatedAt||d.createdAt)||new Date(),Number(d.price||50),d.status||'pending_payment',d.target,d.type||'message',d.context||'',Number(d.evidenceCount||0),d.evidence||[],d.result||{}]);
  for (const s of saved) await q(`INSERT INTO saved_checks (id,user_id,scan_id,created_at,input_type,preview,result) VALUES ($1,$2,$3,$4,$5,$6,$7) ON CONFLICT DO NOTHING`,
    [s.id,s.userId,s.scanId,iso(s.createdAt)||new Date(),s.inputType||'message',s.preview||'',s.result||{}]);
  for (const n of notifications) await q(`INSERT INTO notifications (id,user_id,title,message,kind,read,created_at) VALUES ($1,$2,$3,$4,$5,$6,$7) ON CONFLICT DO NOTHING`,
    [n.id,n.userId,n.title||'',n.message||'',n.kind||'info',!!n.read,iso(n.createdAt)||new Date()]);
  for (const r of resets) await q(`INSERT INTO password_resets (kind,user_id,token_hash,created_at,expires_at) VALUES ($1,$2,$3,$4,$5) ON CONFLICT (token_hash) DO NOTHING`,
    [r.kind||'reset',r.userId,r.tokenHash,iso(r.createdAt)||new Date(),iso(r.expiresAt)||new Date()]);
  for (const k of keys) await q(`INSERT INTO api_keys (id,name,hash,created_at,revoked,revoked_at,created_by) VALUES ($1,$2,$3,$4,$5,$6,$7) ON CONFLICT DO NOTHING`,
    [k.id,k.name||'Unnamed key',k.hash,iso(k.createdAt)||new Date(),!!k.revoked,iso(k.revokedAt),k.createdBy||null]);
  for (const a of audit) await q(`INSERT INTO audit_logs (id,at,actor,action,target,meta) VALUES ($1,$2,$3,$4,$5,$6) ON CONFLICT DO NOTHING`,
    [a.id,iso(a.at)||new Date(),a.actor||null,a.action||'unknown',a.target||null,a.meta||{}]);

  await q(`INSERT INTO migration_meta(key,value) VALUES ('json_migration_completed_at', $1)
           ON CONFLICT (key) DO UPDATE SET value=EXCLUDED.value`, [new Date().toISOString()]);
  await q('COMMIT');
  console.log(JSON.stringify({ok:true,users:users.length,sessions:sessions.length,scans:scans.length,scams:scams.length,reports:reports.length,deepchecks:deepchecks.length,saved:saved.length,notifications:notifications.length,resets:resets.length,apiKeys:keys.length,audit:audit.length},null,2));
})().catch(async (err) => {
  try { await q('ROLLBACK'); } catch {}
  console.error('Migration failed:', err.message);
  process.exitCode = 1;
}).finally(() => pool.end());
