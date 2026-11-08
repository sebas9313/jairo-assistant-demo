import express from 'express';
import pg from 'pg';
import { randomBytes, scrypt as scryptCb, timingSafeEqual, createHash, randomUUID } from 'node:crypto';
import { promisify } from 'node:util';
const scrypt=promisify(scryptCb);
const app=express();app.disable('x-powered-by');app.use(express.json({limit:'300kb'}));
const origin=process.env.APP_ORIGIN||'https://sebas9313.github.io';
const dbUrl=process.env.DATABASE_URL;
if(!dbUrl)throw Error('DATABASE_URL required');
const pool=new pg.Pool({connectionString:dbUrl,ssl:process.env.DB_SSL==='true'?{rejectUnauthorized:true}:undefined});
app.use((req,res,next)=>{res.set('Vary','Origin');if(req.headers.origin===origin){res.set('Access-Control-Allow-Origin',origin);res.set('Access-Control-Allow-Headers','Authorization,Content-Type');res.set('Access-Control-Allow-Methods','GET,POST,PATCH,DELETE,OPTIONS')}if(req.method==='OPTIONS')return res.sendStatus(req.headers.origin===origin?204:403);next()});
const hash=x=>createHash('sha256').update(x).digest('hex');
async function passwordHash(password){const salt=randomBytes(16).toString('hex');const key=await scrypt(password,salt,64);return salt+':'+key.toString('hex')}
async function verifyPassword(password,stored){if(!stored||!stored.includes(':'))return false;const [salt,key]=stored.split(':');const actual=await scrypt(password,salt,64);const expected=Buffer.from(key,'hex');return expected.length===actual.length&&timingSafeEqual(expected,actual)}
const q=(sql,args=[])=>pool.query(sql,args);
async function init(){
 await q(`CREATE TABLE IF NOT EXISTS family_users(id uuid PRIMARY KEY,name text NOT NULL,email text UNIQUE NOT NULL,password_hash text NOT NULL,created_at timestamptz NOT NULL DEFAULT now());
 CREATE TABLE IF NOT EXISTS family_sessions(token_hash text PRIMARY KEY,user_id uuid NOT NULL REFERENCES family_users(id),expires_at timestamptz NOT NULL);
 CREATE TABLE IF NOT EXISTS family_records(id uuid PRIMARY KEY,kind text NOT NULL CHECK(kind IN ('task','note','exercise','completion')),body jsonb NOT NULL,version integer NOT NULL DEFAULT 1,deleted_at timestamptz,updated_at timestamptz NOT NULL DEFAULT now(),updated_by uuid REFERENCES family_users(id));
 CREATE TABLE IF NOT EXISTS family_audit(id bigserial PRIMARY KEY,record_id uuid NOT NULL,actor_id uuid NOT NULL REFERENCES family_users(id),action text NOT NULL,before jsonb,after jsonb,at timestamptz NOT NULL DEFAULT now());`);
 const adminEmail=process.env.INITIAL_ADMIN_EMAIL?.trim().toLowerCase(),adminPassword=process.env.INITIAL_ADMIN_PASSWORD;
 if(adminEmail&&adminPassword){if(adminPassword.length<12)throw Error('Initial password must be at least 12 characters');const count=await q('SELECT count(*)::int AS n FROM family_users');if(count.rows[0].n===0){await q('INSERT INTO family_users(id,name,email,password_hash) VALUES($1,$2,$3,$4)',[randomUUID(),process.env.INITIAL_ADMIN_NAME||'Administrador',adminEmail,await passwordHash(adminPassword)]);console.log('Initial admin created')} }
 const recoveryKey=process.env.ADMIN_RECOVERY_ONCE;
 if(recoveryKey){
  if(recoveryKey.length<24||!adminEmail||!adminPassword||adminPassword.length<12)throw Error('Recovery requires ADMIN_RECOVERY_ONCE (24+ characters) and valid INITIAL_ADMIN_EMAIL / INITIAL_ADMIN_PASSWORD');
  const client=await pool.connect();
  try{
   await client.query('BEGIN');
   await client.query('CREATE TABLE IF NOT EXISTS admin_recovery_used(key_hash text PRIMARY KEY,used_at timestamptz NOT NULL DEFAULT now())');
   await client.query('LOCK TABLE admin_recovery_used IN EXCLUSIVE MODE');
   const used=await client.query('SELECT 1 FROM admin_recovery_used WHERE key_hash=$1',[hash(recoveryKey)]);
   if(!used.rowCount){
    const users=await client.query('SELECT id FROM family_users');
    if(users.rowCount!==1)throw Error('Admin recovery only allowed when exactly one account exists');
    await client.query('UPDATE family_users SET email=$1,password_hash=$2 WHERE id=$3',[adminEmail,await passwordHash(adminPassword),users.rows[0].id]);
    await client.query('DELETE FROM family_sessions WHERE user_id=$1',[users.rows[0].id]);
    await client.query('INSERT INTO admin_recovery_used(key_hash) VALUES($1)',[hash(recoveryKey)]);
    console.log('One-time admin recovery completed');
   }
   await client.query('COMMIT');
  }catch(e){await client.query('ROLLBACK');throw e}finally{client.release()}
 }
}
const wrap=fn=>(req,res,next)=>Promise.resolve(fn(req,res,next)).catch(next);
const auth=wrap(async(req,res,next)=>{const token=/^Bearer ([a-f0-9]{64})$/.exec(req.headers.authorization||'')?.[1];if(!token)return res.sendStatus(401);const result=await q('SELECT u.id,u.name,u.email FROM family_sessions s JOIN family_users u ON u.id=s.user_id WHERE s.token_hash=$1 AND s.expires_at>now()',[hash(token)]);if(!result.rowCount)return res.sendStatus(401);req.user=result.rows[0];next()});
const limit=new Map();app.post('/api/login',wrap(async(req,res)=>{const ip=req.ip,now=Date.now(),slot=limit.get(ip)||{count:0,until:now+900000};if(now>slot.until){slot.count=0;slot.until=now+900000}if(++slot.count>15){limit.set(ip,slot);return res.status(429).json({error:'Too many attempts'})}limit.set(ip,slot);const email=String(req.body.email||'').trim().toLowerCase(),password=String(req.body.password||'');const user=(await q('SELECT * FROM family_users WHERE email=$1',[email])).rows[0];if(!user||!await verifyPassword(password,user.password_hash))return res.status(401).json({error:'Invalid credentials'});slot.count=0;const token=randomBytes(32).toString('hex');await q("INSERT INTO family_sessions(token_hash,user_id,expires_at) VALUES($1,$2,now()+interval '30 days')",[hash(token),user.id]);res.json({token,user:{id:user.id,name:user.name,email:user.email}})}));
app.post('/api/logout',auth,wrap(async(req,res)=>{const token=req.headers.authorization.slice(7);await q('DELETE FROM family_sessions WHERE token_hash=$1',[hash(token)]);res.sendStatus(204)}));
app.get('/api/me',auth,(req,res)=>res.json(req.user));
app.get('/api/users',auth,wrap(async(req,res)=>res.json((await q('SELECT id,name,email FROM family_users ORDER BY name')).rows)));
app.post('/api/users',auth,wrap(async(req,res)=>{if(req.user.email!==String(process.env.INITIAL_ADMIN_EMAIL||'').trim().toLowerCase())return res.sendStatus(403);const name=String(req.body.name||'').trim(),email=String(req.body.email||'').trim().toLowerCase(),password=String(req.body.password||'');if(!name||!/^\S+@\S+\.\S+$/.test(email)||password.length<12)return res.status(400).json({error:'Name, email and 12+ character password required'});const count=await q('SELECT count(*)::int AS n FROM family_users');if(count.rows[0].n>=5)return res.status(409).json({error:'Five family accounts already exist'});try{const id=randomUUID();await q('INSERT INTO family_users(id,name,email,password_hash) VALUES($1,$2,$3,$4)',[id,name,email,await passwordHash(password)]);res.status(201).json({id,name,email})}catch(e){if(e.code==='23505')return res.status(409).json({error:'Email already registered'});throw e}}));
app.get('/api/health',(_,res)=>res.json({ok:true}));
app.get('/api/records',auth,wrap(async(req,res)=>res.json((await q('SELECT id,kind,body,version,updated_at,updated_by FROM family_records WHERE deleted_at IS NULL ORDER BY updated_at DESC LIMIT 1000')).rows)));
const kinds=new Set(['task','note','exercise','completion']);
app.post('/api/records',auth,wrap(async(req,res)=>{const {kind,body}=req.body;if(!kinds.has(kind)||!body||typeof body!=='object'||Array.isArray(body)||JSON.stringify(body).length>12000)return res.sendStatus(400);const id=randomUUID(),client=await pool.connect();try{await client.query('BEGIN');await client.query('INSERT INTO family_records(id,kind,body,updated_by) VALUES($1,$2,$3,$4)',[id,kind,body,req.user.id]);await client.query('INSERT INTO family_audit(record_id,actor_id,action,after) VALUES($1,$2,$3,$4)',[id,req.user.id,'create',body]);await client.query('COMMIT');res.status(201).json({id,kind,body,version:1})}catch(e){await client.query('ROLLBACK');throw e}finally{client.release()}}));
app.patch('/api/records/:id',auth,wrap(async(req,res)=>{const {body,version}=req.body;if(!body||typeof body!=='object'||Array.isArray(body)||JSON.stringify(body).length>12000||!Number.isInteger(version))return res.sendStatus(400);const client=await pool.connect();try{await client.query('BEGIN');const previous=await client.query('SELECT * FROM family_records WHERE id=$1 AND deleted_at IS NULL FOR UPDATE',[req.params.id]);if(!previous.rowCount){await client.query('ROLLBACK');return res.sendStatus(404)}if(previous.rows[0].version!==version){await client.query('ROLLBACK');return res.status(409).json({error:'Changed by another family member; refresh before editing'})}const updated=await client.query('UPDATE family_records SET body=$2,version=version+1,updated_at=now(),updated_by=$3 WHERE id=$1 RETURNING id,kind,body,version,updated_at,updated_by',[req.params.id,body,req.user.id]);await client.query('INSERT INTO family_audit(record_id,actor_id,action,before,after) VALUES($1,$2,$3,$4,$5)',[req.params.id,req.user.id,'update',previous.rows[0].body,body]);await client.query('COMMIT');res.json(updated.rows[0])}catch(e){await client.query('ROLLBACK');throw e}finally{client.release()}}));
app.delete('/api/records/:id',auth,wrap(async(req,res)=>{if(req.body.confirm!==true||!Number.isInteger(req.body.version))return res.status(400).json({error:'Explicit confirmation and version required'});const client=await pool.connect();try{await client.query('BEGIN');const old=await client.query('SELECT * FROM family_records WHERE id=$1 AND deleted_at IS NULL FOR UPDATE',[req.params.id]);if(!old.rowCount){await client.query('ROLLBACK');return res.sendStatus(404)}if(old.rows[0].version!==req.body.version){await client.query('ROLLBACK');return res.sendStatus(409)}await client.query('UPDATE family_records SET deleted_at=now(),updated_by=$2 WHERE id=$1',[req.params.id,req.user.id]);await client.query('INSERT INTO family_audit(record_id,actor_id,action,before) VALUES($1,$2,$3,$4)',[req.params.id,req.user.id,'delete',old.rows[0].body]);await client.query('COMMIT');res.sendStatus(204)}catch(e){await client.query('ROLLBACK');throw e}finally{client.release()}}));
app.get('/api/history',auth,wrap(async(req,res)=>res.json((await q('SELECT a.id,a.record_id,a.action,a.before,a.after,a.at,u.name AS actor FROM family_audit a JOIN family_users u ON u.id=a.actor_id ORDER BY a.id DESC LIMIT 200')).rows)));
app.use((err,req,res,next)=>{console.error(err);res.status(500).json({error:'Internal error'})});
await init();app.listen(process.env.PORT||3000,'0.0.0.0',()=>console.log('Jairo API ready'));
