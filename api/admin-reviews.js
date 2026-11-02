const crypto=require('node:crypto');
const PROJECT='autismo-familiar',ADMIN='parisnovoraul2@gmail.com';
const b64=v=>Buffer.from(typeof v==='string'?v:JSON.stringify(v)).toString('base64url');
function validSession(req){
 const secret=process.env.ADMIN_SESSION_SECRET;if(!secret)return false;
 const raw=(req.headers.cookie||'').split(';').map(x=>x.trim()).find(x=>x.startsWith('af_admin_session='));if(!raw)return false;
 let token;try{token=decodeURIComponent(raw.slice('af_admin_session='.length));}catch{return false;}
 const p=token.split('.');if(p.length!==2||!/^\d+$/.test(p[0]))return false;
 const now=Math.floor(Date.now()/1000),issued=Number(p[0]);if(issued>now+60||now-issued>30*24*60*60)return false;
 const expected=crypto.createHmac('sha256',secret).update(p[0]).digest('base64url'),a=Buffer.from(p[1]),b=Buffer.from(expected);
 return a.length===b.length&&crypto.timingSafeEqual(a,b);
}
async function accessToken(){
 const email=process.env.GA4_CLIENT_EMAIL,key=(process.env.GA4_PRIVATE_KEY||'').replace(/\\n/g,'\n');
 if(!email||!key)throw new Error('Faltan las credenciales de servicio de Google en Vercel.');
 const now=Math.floor(Date.now()/1000),head=b64({alg:'RS256',typ:'JWT'}),claim=b64({iss:email,scope:'https://www.googleapis.com/auth/datastore',aud:'https://oauth2.googleapis.com/token',iat:now,exp:now+3600});
 const unsigned=head+'.'+claim,signer=crypto.createSign('RSA-SHA256');signer.update(unsigned);signer.end();
 const assertion=unsigned+'.'+signer.sign(key,'base64url');
 const r=await fetch('https://oauth2.googleapis.com/token',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:new URLSearchParams({grant_type:'urn:ietf:params:oauth:grant-type:jwt-bearer',assertion})}),j=await r.json().catch(()=>({}));
 if(!r.ok||!j.access_token)throw new Error('No se pudo autenticar con Google para revisar anuncios.');return j.access_token;
}
function decode(v){
 if(!v||typeof v!=='object')return v;
 if('stringValue'in v)return v.stringValue;if('booleanValue'in v)return v.booleanValue;if('integerValue'in v)return Number(v.integerValue);if('doubleValue'in v)return Number(v.doubleValue);
 if('timestampValue'in v)return {seconds:Math.floor(Date.parse(v.timestampValue)/1000)};if('nullValue'in v)return null;
 if('arrayValue'in v)return(v.arrayValue.values||[]).map(decode);
 if('mapValue'in v)return Object.fromEntries(Object.entries(v.mapValue.fields||{}).map(([k,x])=>[k,decode(x)]));return v;
}
function encode(v){
 if(v===null)return{nullValue:null};if(typeof v==='string')return{stringValue:v};if(typeof v==='boolean')return{booleanValue:v};
 if(typeof v==='number')return Number.isInteger(v)?{integerValue:String(v)}:{doubleValue:v};
 if(Array.isArray(v))return{arrayValue:{values:v.map(encode)}};
 if(v&&typeof v==='object'&&typeof v.seconds==='number')return{timestampValue:new Date(v.seconds*1000).toISOString()};
 if(v&&typeof v==='object')return{mapValue:{fields:Object.fromEntries(Object.entries(v).map(([k,x])=>[k,encode(x)]))}};return{nullValue:null};
}
module.exports=async function(req,res){
 res.setHeader('Cache-Control','no-store');if(req.method!=='POST'){res.setHeader('Allow','POST');return res.status(405).json({error:'Método no permitido.'});}
 if(!validSession(req))return res.status(401).json({error:'La sesión del panel ha caducado. Vuelve a entrar.'});
 try{
  const token=await accessToken(),base='https://firestore.googleapis.com/v1/projects/'+PROJECT+'/databases/(default)/documents',headers={Authorization:'Bearer '+token,'Content-Type':'application/json'};
  if(req.body?.action==='list'){
   const r=await fetch(base+'/profiles',{headers}),j=await r.json().catch(()=>({}));if(!r.ok)throw new Error(j.error?.message||'No se pudieron cargar los anuncios.');
   const rows=(j.documents||[]).map(d=>({id:d.name.split('/').pop(),...Object.fromEntries(Object.entries(d.fields||{}).map(([k,v])=>[k,decode(v)]))}));
   return res.status(200).json({rows});
  }
  if(req.body?.action==='review'){
   const id=String(req.body.id||''),action=req.body.decision,reason=String(req.body.reason||'').slice(0,1000);
   if(!/^[A-Za-z0-9_-]{1,150}$/.test(id)||!['approve','reject'].includes(action))return res.status(400).json({error:'Solicitud no válida.'});
   if(action==='reject'&&!reason.trim())return res.status(400).json({error:'El motivo de denegación es obligatorio.'});
   const fields={status:encode(action==='approve'?'approved':'rejected'),reviewedAt:encode({seconds:Math.floor(Date.now()/1000)}),reviewedBy:encode(ADMIN),rejectionReason:encode(action==='reject'?reason:'')};
   const params=['status','reviewedAt','reviewedBy','rejectionReason'].map(x=>'updateMask.fieldPaths='+x).join('&');
   const r=await fetch(base+'/profiles/'+encodeURIComponent(id)+'?'+params,{method:'PATCH',headers,body:JSON.stringify({fields})}),j=await r.json().catch(()=>({}));
   if(!r.ok)throw new Error(j.error?.message||'No se pudo guardar la decisión.');return res.status(200).json({ok:true});
  }
  return res.status(400).json({error:'Acción no reconocida.'});
 }catch(e){return res.status(500).json({error:e.message||'Error interno del servidor.'});}
};