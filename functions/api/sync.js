const json=(body,status=200)=>new Response(JSON.stringify(body),{status,headers:{"content-type":"application/json; charset=utf-8","cache-control":"no-store"}});
const digest=async value=>Array.from(new Uint8Array(await crypto.subtle.digest("SHA-256",new TextEncoder().encode(value)))).map(x=>x.toString(16).padStart(2,"0")).join("");
const randomHex=(bytes=32)=>Array.from(crypto.getRandomValues(new Uint8Array(bytes))).map(x=>x.toString(16).padStart(2,"0")).join("");
const validFavorites=ids=>Array.isArray(ids)?[...new Set(ids.filter(x=>typeof x==="string"&&/^[a-z0-9-]{1,80}$/.test(x)))].slice(0,200):[];
const getDevice=async(db,token)=>{if(typeof token!=="string"||!/^[a-f0-9]{64}$/.test(token))return null;return db.prepare("SELECT id, sync_group_id FROM devices WHERE token_hash=?").bind(await digest(token)).first()};
async function replaceFavorites(db,group,ids){const list=validFavorites(ids);await db.batch([db.prepare("DELETE FROM favorites WHERE sync_group_id=?").bind(group),...list.map(id=>db.prepare("INSERT INTO favorites (sync_group_id,recipe_id) VALUES (?,?)").bind(group,id))]);return list}
async function listFavorites(db,group){const r=await db.prepare("SELECT recipe_id FROM favorites WHERE sync_group_id=? ORDER BY recipe_id").bind(group).all();return r.results.map(x=>x.recipe_id)}
export async function onRequestPost({request,env}){
 if(!env.DB)return json({error:"Database is not connected."},503);
 const db=env.DB;
 let body;try{if(Number(request.headers.get("content-length")||0)>10000)return json({error:"Request too large."},413);body=await request.json()}catch{return json({error:"Invalid JSON."},400)}
 const action=body?.action;const now=Math.floor(Date.now()/1000);
 try{
  if(action==="create"){
   const token=randomHex(),id=randomHex(16),group=randomHex(16),favorites=validFavorites(body.favorites);
   await db.batch([db.prepare("INSERT INTO devices(id,sync_group_id,token_hash) VALUES(?,?,?)").bind(id,group,await digest(token)),...favorites.map(recipe=>db.prepare("INSERT INTO favorites(sync_group_id,recipe_id) VALUES(?,?)").bind(group,recipe))]);
   return json({token,favorites});
  }
  if(action==="join"){
   if(typeof body.code!=="string"||!/^[0-9]{4}$/.test(body.code))return json({error:"Enter a four-digit code."},400);
   const ip=request.headers.get("CF-Connecting-IP")||"unknown";
   const clientKey=await digest(ip);
   // Atomic rate limit: at most five attempts per 15-minute window per client IP.
   await db.prepare("INSERT INTO pairing_rate_limits(client_key,attempts,window_start) VALUES(?,1,?) ON CONFLICT(client_key) DO UPDATE SET attempts=CASE WHEN window_start<? THEN 1 ELSE attempts+1 END,window_start=CASE WHEN window_start<? THEN excluded.window_start ELSE window_start END").bind(clientKey,now,now-900,now-900).run();
   const limit=await db.prepare("SELECT attempts FROM pairing_rate_limits WHERE client_key=?").bind(clientKey).first();
   if(limit.attempts>5)return json({error:"Too many attempts. Try again in 15 minutes."},429);
   const codeHash=await digest(body.code);
   const used=await db.prepare("DELETE FROM pairing_codes WHERE code_hash=? AND expires_at>? RETURNING sync_group_id").bind(codeHash,now).first();
   if(!used)return json({error:"Invalid or expired code."},400);
   const token=randomHex(),id=randomHex(16),group=used.sync_group_id;
   const existing=await listFavorites(db,group),merged=[...new Set([...existing,...validFavorites(body.favorites)])];
   await db.batch([db.prepare("INSERT INTO devices(id,sync_group_id,token_hash) VALUES(?,?,?)").bind(id,group,await digest(token)),...merged.filter(x=>!existing.includes(x)).map(recipe=>db.prepare("INSERT OR IGNORE INTO favorites(sync_group_id,recipe_id) VALUES(?,?)").bind(group,recipe))]);
   return json({token,favorites:merged});
  }
  const device=await getDevice(db,body.token);
  if(!device)return json({error:"Device not connected. Pair it again.",code:"UNAUTHORIZED"},401);
  if(action==="get")return json({favorites:await listFavorites(db,device.sync_group_id)});
  if(action==="save")return json({favorites:await replaceFavorites(db,device.sync_group_id,body.favorites)});
  if(action==="code"){
   // Limit active pairing code generation per device.
   const key="device:"+device.id;
   await db.prepare("INSERT INTO pairing_rate_limits(client_key,attempts,window_start) VALUES(?,1,?) ON CONFLICT(client_key) DO UPDATE SET attempts=CASE WHEN window_start<? THEN 1 ELSE attempts+1 END,window_start=CASE WHEN window_start<? THEN excluded.window_start ELSE window_start END").bind(key,now,now-3600,now-3600).run();
   const count=await db.prepare("SELECT attempts FROM pairing_rate_limits WHERE client_key=?").bind(key).first();
   if(count.attempts>10)return json({error:"Too many codes requested. Try again later."},429);
   await db.prepare("DELETE FROM pairing_codes WHERE sync_group_id=? OR expires_at<=?").bind(device.sync_group_id,now).run();
   for(let i=0;i<10;i++){
    const code=String(crypto.getRandomValues(new Uint32Array(1))[0]%10000).padStart(4,"0");
    try{await db.prepare("INSERT INTO pairing_codes(code_hash,sync_group_id,expires_at) VALUES(?,?,?)").bind(await digest(code),device.sync_group_id,now+300).run();return json({code,expiresIn:300})}catch(e){if(!String(e).includes("UNIQUE"))throw e}
   }
   return json({error:"Could not generate a code. Try again."},503);
  }
  return json({error:"Unknown action."},400);
 }catch(e){return json({error:"Sync is temporarily unavailable. Please try again."},503)}
}
export async function onRequestGet(){return json({error:"Method not allowed."},405)}
