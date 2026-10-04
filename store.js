const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

class Store {
  constructor({ root, files, databaseUrl }) {
    this.root = root;
    this.files = files;
    this.databaseUrl = databaseUrl || '';
    this.usePg = Boolean(this.databaseUrl);
    this.pool = null;
  }

  async init() {
    if (!this.usePg) return;
    const { Pool } = require('pg');
    this.pool = new Pool({
      connectionString: this.databaseUrl,
      max: Number(process.env.PGPOOL_MAX || 10),
      idleTimeoutMillis: 30000,
      connectionTimeoutMillis: 10000,
      ssl: process.env.PGSSL === 'disable' ? false : { rejectUnauthorized: false }
    });
    await this.pool.query('SELECT 1');
    const schema = fs.readFileSync(path.join(this.root, 'db', 'schema.sql'), 'utf8');
    await this.pool.query(schema);
  }

  async close() { if (this.pool) await this.pool.end(); }
  _read(name) { try { return JSON.parse(fs.readFileSync(this.files[name], 'utf8')); } catch { return []; } }
  _write(name, data) { fs.writeFileSync(this.files[name], JSON.stringify(data, null, 2)); }
  async q(text, params=[]) { if (!this.pool) throw new Error('PostgreSQL is not initialized.'); return this.pool.query(text, params); }

  async stats() {
    if (!this.usePg) {
      return {
        checks: this._read('scans').length,
        reports: this._read('reports').length,
        knownEntities: this._read('scams').length,
        users: this._read('users').length,
        deepchecks: this._read('deepchecks').length,
        saved: this._read('saved-checks').length
      };
    }
    const [checks,reports,scams,users,deep,saved] = await Promise.all([
      this.q('SELECT count(*)::int AS n FROM scans'), this.q('SELECT count(*)::int AS n FROM reports'),
      this.q('SELECT count(*)::int AS n FROM scams'), this.q('SELECT count(*)::int AS n FROM users'),
      this.q('SELECT count(*)::int AS n FROM deepchecks'), this.q('SELECT count(*)::int AS n FROM saved_checks')
    ]);
    return {checks:checks.rows[0].n,reports:reports.rows[0].n,knownEntities:scams.rows[0].n,users:users.rows[0].n,deepchecks:deep.rows[0].n,saved:saved.rows[0].n};
  }

  async findUserByEmail(email) {
    if (!this.usePg) return this._read('users').find(x => x.email === email) || null;
    const r = await this.q('SELECT * FROM users WHERE email=$1 LIMIT 1',[email]);
    return r.rows[0] ? this._user(r.rows[0]) : null;
  }
  async findUserById(id) {
    if (!this.usePg) return this._read('users').find(x => x.id === id) || null;
    const r = await this.q('SELECT * FROM users WHERE id=$1 LIMIT 1',[id]);
    return r.rows[0] ? this._user(r.rows[0]) : null;
  }
  async listUsers() {
    if (!this.usePg) return this._read('users');
    const r = await this.q('SELECT * FROM users ORDER BY created_at DESC'); return r.rows.map(x=>this._user(x));
  }
  _user(x) { return {id:x.id,email:x.email,passwordHash:x.password_hash,username:x.username,role:x.role,status:x.status,displayName:x.display_name,emailVerified:Boolean(x.email_verified),createdAt:new Date(x.created_at).toISOString(),updatedAt:x.updated_at?new Date(x.updated_at).toISOString():undefined}; }
  async insertUser(u) {
    if (!this.usePg) { const xs=this._read('users'); xs.unshift(u); this._write('users',xs.slice(0,10000)); return u; }
    await this.q(`INSERT INTO users(id,email,password_hash,username,role,status,display_name,email_verified,created_at,updated_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`,[u.id,u.email,u.passwordHash,u.username,u.role,u.status,u.displayName,Boolean(u.emailVerified),u.createdAt,u.updatedAt||null]); return u;
  }
  async updateUser(u) {
    if (!this.usePg) { const xs=this._read('users'); const i=xs.findIndex(x=>x.id===u.id); if(i>=0) xs[i]=u; this._write('users',xs); return u; }
    await this.q(`UPDATE users SET email=$2,password_hash=$3,username=$4,role=$5,status=$6,display_name=$7,email_verified=$8,updated_at=$9 WHERE id=$1`,[u.id,u.email,u.passwordHash,u.username,u.role,u.status,u.displayName,Boolean(u.emailVerified),u.updatedAt||null]); return u;
  }
  async deleteUser(id) {
    if (!this.usePg) { for(const n of ['users','sessions','saved-checks','notifications']) this._write(n,this._read(n).filter(x=>x.id!==id&&x.userId!==id)); return; }
    await this.q('DELETE FROM users WHERE id=$1',[id]);
  }

  async createSession(s) {
    if (!this.usePg) { const xs=this._read('sessions'); xs.unshift(s); this._write('sessions',xs.slice(0,5000)); return; }
    const h=crypto.createHash('sha256').update(String(s.token)).digest('hex');
    await this.q('INSERT INTO sessions(token_hash,user_id,created_at,expires_at) VALUES($1,$2,$3,$4) ON CONFLICT DO NOTHING',[h,s.userId,s.createdAt,s.expiresAt]);
  }
  async findSessionByToken(token) {
    if (!this.usePg) return this._read('sessions').find(x=>x.token===token&&x.expiresAt>new Date().toISOString())||null;
    const h=crypto.createHash('sha256').update(String(token)).digest('hex');
    const r=await this.q('SELECT * FROM sessions WHERE token_hash=$1 AND expires_at>now() LIMIT 1',[h]);
    if(!r.rows[0])return null; const x=r.rows[0]; return {token, userId:x.user_id, createdAt:new Date(x.created_at).toISOString(), expiresAt:new Date(x.expires_at).toISOString()};
  }
  async deleteSessionByToken(token) { if(!this.usePg){this._write('sessions',this._read('sessions').filter(x=>x.token!==token));return;} const h=crypto.createHash('sha256').update(String(token)).digest('hex'); await this.q('DELETE FROM sessions WHERE token_hash=$1',[h]); }
  async deleteSessionsForUser(userId) { if(!this.usePg){this._write('sessions',this._read('sessions').filter(x=>x.userId!==userId));return;} await this.q('DELETE FROM sessions WHERE user_id=$1',[userId]); }

  async findScam(normalized) {
    if(!this.usePg) return this._read('scams').find(x=>x.normalized===normalized || String(x.target||'').toLowerCase()===normalized) || null;
    const r=await this.q('SELECT * FROM scams WHERE normalized=$1 LIMIT 1',[normalized]); return r.rows[0]?this._scam(r.rows[0]):null;
  }
  async listScams(query='') {
    if(!this.usePg){let xs=this._read('scams'); if(query) xs=xs.filter(x=>`${x.target} ${x.type} ${x.note} ${x.status}`.toLowerCase().includes(query.toLowerCase())); return xs.slice(0,200);}
    const params=[]; let sql='SELECT * FROM scams'; if(query){params.push('%'+query.toLowerCase()+'%');sql+=' WHERE lower(target||\' \'||type||\' \'||coalesce(note,\'\')||\' \'||status) LIKE $1';} sql+=' ORDER BY last_reviewed DESC NULLS LAST LIMIT 200'; const r=await this.q(sql,params); return r.rows.map(x=>this._scam(x));
  }
  _scam(x){return {id:x.id,target:x.target,normalized:x.normalized,type:x.type,status:x.status,reports:x.reports,note:x.note||'',lastReviewed:x.last_reviewed?new Date(x.last_reviewed).toISOString():undefined};}
  async insertScam(s){ if(!this.usePg){const xs=this._read('scams');xs.unshift(s);this._write('scams',xs.slice(0,10000));return s;} await this.q(`INSERT INTO scams(id,target,normalized,type,status,reports,note,last_reviewed) VALUES($1,$2,$3,$4,$5,$6,$7,$8) ON CONFLICT(normalized) DO UPDATE SET status=EXCLUDED.status,reports=EXCLUDED.reports,note=EXCLUDED.note,last_reviewed=EXCLUDED.last_reviewed`,[s.id,s.target,s.normalized,s.type,s.status,s.reports,s.note||'',s.lastReviewed||null]); return s; }
  async deleteScam(id){ if(!this.usePg){this._write('scams',this._read('scams').filter(x=>x.id!==id));return;} await this.q('DELETE FROM scams WHERE id=$1',[id]); }

  async insertScan(s){ if(!this.usePg){const xs=this._read('scans');xs.unshift(s);this._write('scans',xs.slice(0,10000));return s;} await this.q('INSERT INTO scans(id,user_id,created_at,input_type,preview,result) VALUES($1,$2,$3,$4,$5,$6)',[s.id,s.userId||null,s.createdAt,s.inputType,s.preview,s.result]); return s; }
  async listScansForUser(uid){ if(!this.usePg)return this._read('scans').filter(x=>x.userId===uid).slice(0,100); const r=await this.q('SELECT * FROM scans WHERE user_id=$1 ORDER BY created_at DESC LIMIT 100',[uid]); return r.rows.map(x=>({id:x.id,userId:x.user_id,createdAt:new Date(x.created_at).toISOString(),inputType:x.input_type,preview:x.preview,result:x.result,source:x.result?.source,ocrText:x.result?.ocrText})); }
  async findScanForUser(id,uid){ if(!this.usePg)return this._read('scans').find(x=>x.id===id&&x.userId===uid)||null; const r=await this.q('SELECT * FROM scans WHERE id=$1 AND user_id=$2 LIMIT 1',[id,uid]); if(!r.rows[0])return null;const x=r.rows[0];return {id:x.id,userId:x.user_id,createdAt:new Date(x.created_at).toISOString(),inputType:x.input_type,preview:x.preview,result:x.result}; }

  async insertReport(r){
    if(!this.usePg){const xs=this._read('reports');xs.unshift(r);this._write('reports',xs.slice(0,10000));return r;}
    await this.q(`INSERT INTO reports(id,user_id,created_at,category,target,description,incident_date,amount_lost,status,evidence_count,reviewed_at,reviewed_by,review_note,report_counted,report_counted_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15)`,[r.id,r.userId||null,r.createdAt,r.category,r.target,r.description,r.incidentDate||null,r.amountLost==null?null:Number(r.amountLost),r.status||'submitted',Number(r.evidenceCount||0),r.reviewedAt||null,r.reviewedBy||null,r.reviewNote||null,Boolean(r.reportCounted),r.reportCountedAt||null]);return r;
  }
  _report(x){return {id:x.id,userId:x.user_id,createdAt:new Date(x.created_at).toISOString(),category:x.category,target:x.target,description:x.description,incidentDate:x.incident_date?new Date(x.incident_date).toISOString().slice(0,10):'',amountLost:x.amount_lost==null?null:Number(x.amount_lost),status:x.status,evidenceCount:x.evidence_count,reviewedAt:x.reviewed_at?new Date(x.reviewed_at).toISOString():null,reviewedBy:x.reviewed_by,reviewNote:x.review_note,reportCounted:Boolean(x.report_counted),reportCountedAt:x.report_counted_at?new Date(x.report_counted_at).toISOString():null};}
  async listReportsForUser(uid){if(!this.usePg)return this._read('reports').filter(x=>x.userId===uid).slice(0,100);const r=await this.q('SELECT * FROM reports WHERE user_id=$1 ORDER BY created_at DESC LIMIT 100',[uid]);return r.rows.map(x=>this._report(x));}
  async listRecentReports(){if(!this.usePg){const users=this._read('users');return this._read('reports').slice(0,20).map(x=>{const u=users.find(a=>a.id===x.userId);return {...x,reporter:u?.displayName||'Anonymous',reporterUsername:u?.username||'',reporterEmail:u?.email||''};});}const r=await this.q('SELECT r.*,u.display_name as reporter,u.username as reporter_username,u.email as reporter_email FROM reports r LEFT JOIN users u ON u.id=r.user_id ORDER BY r.created_at DESC LIMIT 20');return r.rows.map(x=>({...this._report(x),reporter:x.reporter||'Anonymous',reporterUsername:x.reporter_username||'',reporterEmail:x.reporter_email||''}));}
  async findReport(id){if(!this.usePg)return this._read('reports').find(x=>x.id===id)||null;const r=await this.q('SELECT * FROM reports WHERE id=$1 LIMIT 1',[id]);return r.rows[0]?this._report(r.rows[0]):null;}
  async updateReport(r){if(!this.usePg){const xs=this._read('reports');const i=xs.findIndex(x=>x.id===r.id);if(i>=0)xs[i]=r;this._write('reports',xs);return r;}await this.q(`UPDATE reports SET status=$2,reviewed_at=$3,reviewed_by=$4,review_note=$5,report_counted=$6,report_counted_at=$7,evidence_count=$8 WHERE id=$1`,[r.id,r.status,r.reviewedAt||null,r.reviewedBy||null,r.reviewNote||null,Boolean(r.reportCounted),r.reportCountedAt||null,Number(r.evidenceCount||0)]);return r;}

  async insertEvidence(reportId,evidence){ if(!this.usePg)return; for(const e of evidence) await this.q('INSERT INTO report_evidence(id,report_id,file_name,mime,size_bytes,storage_key) VALUES($1,$2,$3,$4,$5,$6)',[e.id,reportId,e.fileName,e.mime,e.size,e.file||e.storageKey]); }

  async insertDeepcheck(d){if(!this.usePg){const xs=this._read('deepchecks');xs.unshift(d);this._write('deepchecks',xs.slice(0,10000));return d;}await this.q(`INSERT INTO deepchecks(order_id,user_id,created_at,updated_at,price,status,target,type,context,evidence_count,evidence,result) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)`,[d.orderId,d.userId,d.createdAt,d.updatedAt,Number(d.price||50),d.status,d.target,d.type,d.context||'',Number(d.evidenceCount||0),d.evidence||[],d.result||{}]);return d;}
  _deep(x){return {orderId:x.order_id,userId:x.user_id,createdAt:new Date(x.created_at).toISOString(),updatedAt:new Date(x.updated_at).toISOString(),price:Number(x.price),status:x.status,target:x.target,type:x.type,context:x.context||'',evidenceCount:x.evidence_count,evidence:x.evidence||[],result:x.result||{}};}
  async listDeepchecksForUser(uid){if(!this.usePg)return this._read('deepchecks').filter(x=>x.userId===uid).slice(0,100);const r=await this.q('SELECT * FROM deepchecks WHERE user_id=$1 ORDER BY created_at DESC LIMIT 100',[uid]);return r.rows.map(x=>this._deep(x));}
  async listRecentDeepchecks(){if(!this.usePg)return this._read('deepchecks').slice(0,10);const r=await this.q('SELECT * FROM deepchecks ORDER BY created_at DESC LIMIT 10');return r.rows.map(x=>this._deep(x));}
  async findDeepcheck(orderId,uid){if(!this.usePg)return this._read('deepchecks').find(x=>x.orderId===orderId&&x.userId===uid)||null;const r=await this.q('SELECT * FROM deepchecks WHERE order_id=$1 AND user_id=$2 LIMIT 1',[orderId,uid]);return r.rows[0]?this._deep(r.rows[0]):null;}
  async findDeepcheckByOrder(orderId){if(!this.usePg)return this._read('deepchecks').find(x=>x.orderId===orderId)||null;const r=await this.q('SELECT * FROM deepchecks WHERE order_id=$1 LIMIT 1',[orderId]);return r.rows[0]?this._deep(r.rows[0]):null;}
  async updateDeepcheck(d){if(!this.usePg){const xs=this._read('deepchecks');const i=xs.findIndex(x=>x.orderId===d.orderId);if(i>=0)xs[i]=d;this._write('deepchecks',xs);return d;}await this.q('UPDATE deepchecks SET updated_at=$2,status=$3,evidence_count=$4,evidence=$5,result=$6 WHERE order_id=$1',[d.orderId,d.updatedAt,d.status,Number(d.evidenceCount||0),d.evidence||[],d.result||{}]);return d;}

  async createSaved(item){if(!this.usePg){const xs=this._read('saved-checks');xs.unshift(item);this._write('saved-checks',xs.slice(0,10000));return item;}await this.q('INSERT INTO saved_checks(id,user_id,scan_id,created_at,input_type,preview,result) VALUES($1,$2,$3,$4,$5,$6,$7)',[item.id,item.userId,item.scanId,item.createdAt,item.inputType,item.preview,item.result]);return item;}
  async listSaved(uid){if(!this.usePg)return this._read('saved-checks').filter(x=>x.userId===uid).slice(0,100);const r=await this.q('SELECT * FROM saved_checks WHERE user_id=$1 ORDER BY created_at DESC LIMIT 100',[uid]);return r.rows.map(x=>({id:x.id,userId:x.user_id,scanId:x.scan_id,createdAt:new Date(x.created_at).toISOString(),inputType:x.input_type,preview:x.preview,result:x.result}));}
  async savedExists(uid,scanId){if(!this.usePg)return this._read('saved-checks').some(x=>x.userId===uid&&x.scanId===scanId);const r=await this.q('SELECT 1 FROM saved_checks WHERE user_id=$1 AND scan_id=$2 LIMIT 1',[uid,scanId]);return Boolean(r.rows[0]);}
  async deleteSaved(id,uid){if(!this.usePg){const xs=this._read('saved-checks');if(!xs.some(x=>x.id===id&&x.userId===uid))return false;this._write('saved-checks',xs.filter(x=>!(x.id===id&&x.userId===uid)));return true;}const r=await this.q('DELETE FROM saved_checks WHERE id=$1 AND user_id=$2',[id,uid]);return r.rowCount>0;}

  async notify(n){if(!this.usePg){const xs=this._read('notifications');xs.unshift(n);this._write('notifications',xs.slice(0,10000));return n;}await this.q('INSERT INTO notifications(id,user_id,title,message,kind,read,created_at) VALUES($1,$2,$3,$4,$5,$6,$7)',[n.id,n.userId,n.title,n.message,n.kind||'info',false,n.createdAt]);return n;}
  async listNotifications(uid){if(!this.usePg)return this._read('notifications').filter(x=>x.userId===uid).slice(0,100);const r=await this.q('SELECT * FROM notifications WHERE user_id=$1 ORDER BY created_at DESC LIMIT 100',[uid]);return r.rows.map(x=>({id:x.id,userId:x.user_id,title:x.title,message:x.message,kind:x.kind,read:Boolean(x.read),createdAt:new Date(x.created_at).toISOString()}));}
  async markNotificationsRead(uid){if(!this.usePg){const xs=this._read('notifications');for(const x of xs)if(x.userId===uid)x.read=true;this._write('notifications',xs);return;}await this.q('UPDATE notifications SET read=TRUE WHERE user_id=$1',[uid]);}

  async createReset(x){if(!this.usePg){const xs=this._read('password-resets');xs.push(x);this._write('password-resets',xs.slice(-5000));return x;}await this.q('INSERT INTO password_resets(kind,user_id,token_hash,created_at,expires_at) VALUES($1,$2,$3,$4,$5)',[x.kind,x.userId,x.tokenHash,x.createdAt,x.expiresAt]);return x;}
  async findReset(kind,userId,tokenHash){
    if(!this.usePg){return this._read('password-resets').find(x=>x.kind===kind&&(userId==null||x.userId===userId)&&x.tokenHash===tokenHash&&x.expiresAt>new Date().toISOString())||null;}
    const params=[kind,tokenHash]; let sql='SELECT * FROM password_resets WHERE kind=$1 AND token_hash=$2 AND expires_at>now()'; if(userId!=null){params.push(userId);sql+=' AND user_id=$3';} sql+=' ORDER BY created_at DESC LIMIT 1'; const r=await this.q(sql,params);if(!r.rows[0])return null;const x=r.rows[0];return {id:String(x.id),kind:x.kind,userId:x.user_id,tokenHash:x.token_hash,createdAt:new Date(x.created_at).toISOString(),expiresAt:new Date(x.expires_at).toISOString()};
  }
  async deleteReset(tokenHash){if(!this.usePg){this._write('password-resets',this._read('password-resets').filter(x=>x.tokenHash!==tokenHash));return;}await this.q('DELETE FROM password_resets WHERE token_hash=$1',[tokenHash]);}

  async createApiKey(x){if(!this.usePg){const xs=this._read('api-keys');xs.unshift(x);this._write('api-keys',xs);return x;}await this.q('INSERT INTO api_keys(id,name,hash,created_at,revoked,revoked_at,created_by) VALUES($1,$2,$3,$4,$5,$6,$7)',[x.id,x.name,x.hash,x.createdAt,false,null,x.createdBy]);return x;}
  async listApiKeys(){if(!this.usePg)return this._read('api-keys');const r=await this.q('SELECT * FROM api_keys ORDER BY created_at DESC');return r.rows.map(x=>({id:x.id,name:x.name,hash:x.hash,createdAt:new Date(x.created_at).toISOString(),revoked:Boolean(x.revoked),revokedAt:x.revoked_at?new Date(x.revoked_at).toISOString():null,createdBy:x.created_by}));}
  async findApiKey(hash){if(!this.usePg)return this._read('api-keys').find(x=>x.hash===hash&&!x.revoked)||null;const r=await this.q('SELECT * FROM api_keys WHERE hash=$1 AND revoked=FALSE LIMIT 1',[hash]);return r.rows[0]||null;}
  async revokeApiKey(id){if(!this.usePg){const xs=this._read('api-keys'),x=xs.find(a=>a.id===id);if(!x)return null;x.revoked=true;x.revokedAt=new Date().toISOString();this._write('api-keys',xs);return x;}const r=await this.q('UPDATE api_keys SET revoked=TRUE,revoked_at=now() WHERE id=$1 RETURNING *',[id]);return r.rows[0]||null;}


  async createPayment(x){
    if(!this.usePg){const f=this.files['payments'];if(!f)return x;const xs=this._read('payments');xs.unshift(x);this._write('payments',xs.slice(0,10000));return x;}
    await this.q('INSERT INTO payment_transactions(id,order_id,provider,provider_reference,checkout_url,amount,currency,status,created_at,updated_at,metadata) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)',[x.id,x.orderId,x.provider,x.providerReference||null,x.checkoutUrl||null,Number(x.amount),x.currency||'PHP',x.status,x.createdAt,x.updatedAt,x.metadata||{}]);return x;
  }
  async updatePaymentByOrder(orderId,patch){
    if(!this.usePg){const xs=this._read('payments'),x=xs.find(a=>a.orderId===orderId);if(!x)return null;Object.assign(x,patch,{updatedAt:new Date().toISOString()});this._write('payments',xs);return x;}
    const sets=[],params=[orderId];let i=2;for(const [k,v] of Object.entries(patch)){const col={providerReference:'provider_reference',checkoutUrl:'checkout_url',amount:'amount',currency:'currency',status:'status',metadata:'metadata'}[k];if(!col)continue;sets.push(`${col}=$${i++}`);params.push(v);}
    if(!sets.length)return null;sets.push(`updated_at=now()`);const r=await this.q(`UPDATE payment_transactions SET ${sets.join(',')} WHERE order_id=$1 RETURNING *`,params);return r.rows[0]||null;
  }
  async findPaymentByProviderReference(provider,reference){
    if(!this.usePg)return this._read('payments').find(x=>x.provider===provider&&x.providerReference===reference)||null;
    const r=await this.q('SELECT * FROM payment_transactions WHERE provider=$1 AND provider_reference=$2 LIMIT 1',[provider,reference]);return r.rows[0]||null;
  }
  async recordWebhookEvent(provider,eventKey,payload){
    if(!this.usePg){const xs=this._read('webhook-events');if(xs.some(x=>x.provider===provider&&x.eventKey===eventKey))return false;xs.unshift({id:crypto.randomUUID(),provider,eventKey,receivedAt:new Date().toISOString(),payload});this._write('webhook-events',xs.slice(0,10000));return true;}
    try{await this.q('INSERT INTO webhook_events(id,provider,event_key,payload) VALUES($1,$2,$3,$4)',[crypto.randomUUID(),provider,eventKey,payload]);return true;}catch(e){if(e.code==='23505')return false;throw e;}
  }

  async audit(a){if(!this.usePg){const xs=this._read('audit');xs.unshift(a);this._write('audit',xs.slice(0,5000));return;}await this.q('INSERT INTO audit_logs(id,at,actor,action,target,meta) VALUES($1,$2,$3,$4,$5,$6)',[a.id,a.at,a.actor||null,a.action,a.target||null,a.meta||{}]);}
  async listAudit(){if(!this.usePg)return this._read('audit').slice(0,250);const r=await this.q('SELECT * FROM audit_logs ORDER BY at DESC LIMIT 250');return r.rows.map(x=>({id:x.id,at:new Date(x.at).toISOString(),actor:x.actor,action:x.action,target:x.target,meta:x.meta||{}}));}

  async seed() {
    const sampleScams = [
      {id:'sc_demo_phone',target:'09171234567',normalized:'09171234567',type:'Phone',status:'reported',reports:12,note:'Community reports mention payment and fake-prize messages.',lastReviewed:new Date().toISOString()},
      {id:'sc_demo_domain',target:'example-login-verify.com',normalized:'example-login-verify.com',type:'Domain',status:'suspicious',reports:4,note:'Phishing-style indicators in submitted URLs.',lastReviewed:new Date().toISOString()},
      {id:'sc_demo_job',target:'ABC Quick Jobs',normalized:'abc quick jobs',type:'Job listing',status:'under_review',reports:3,note:'Reports mention upfront registration fees.',lastReviewed:new Date().toISOString()},
      {id:'sc_demo_shop',target:'Verified Local Shop',normalized:'verified local shop',type:'Business',status:'no_known_reports',reports:0,note:'No known community reports in this demo database.',lastReviewed:new Date().toISOString()}
    ];
    if(this.usePg){
      const count=await this.q('SELECT count(*)::int AS n FROM scams');
      if(count.rows[0].n===0) for(const x of sampleScams) await this.insertScam(x);
      const admin=await this.findUserByEmail(process.env.ADMIN_EMAIL || 'admin@scamcheck.ph');
      if(!admin){
        const hash=await new Promise((resolve,reject)=>crypto.scrypt(process.env.ADMIN_PASSWORD || 'ChangeMe123!',crypto.randomBytes(16).toString('hex'),64,(e,k)=>e?reject(e):resolve(k)));
        // Kept for compatibility; server will seed using its password helper when no DB admin exists.
      }
      return;
    }
    if(!this._read('scams').length)this._write('scams',sampleScams);
  }
}
module.exports = { Store };
