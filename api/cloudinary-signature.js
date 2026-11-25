const crypto = require('node:crypto');

module.exports = async function handler(req, res) {
  res.setHeader('Cache-Control', 'no-store');
  if (req.method !== 'POST') {
    res.setHeader('Allow', 'POST');
    return res.status(405).json({ error: 'Método no permitido.' });
  }
  const cloud = process.env.CLOUDINARY_CLOUD_NAME;
  const key = process.env.CLOUDINARY_API_KEY;
  const secret = process.env.CLOUDINARY_API_SECRET;
  const firebaseKey = process.env.FIREBASE_WEB_API_KEY;
  if (!cloud || !key || !secret || !firebaseKey) {
    return res.status(503).json({ error: 'Falta configurar Cloudinary o Firebase en Vercel.' });
  }
  const match = String(req.headers.authorization || '').match(/^Bearer\s+(.+)$/i);
  if (!match) return res.status(401).json({ error: 'Inicia sesión para subir el vídeo.' });
  try {
    const verify = await fetch('https://identitytoolkit.googleapis.com/v1/accounts:lookup?key=' + encodeURIComponent(firebaseKey), {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ idToken: match[1] }),
      signal: AbortSignal.timeout(10000)
    });
    const identity = await verify.json().catch(() => ({}));
    const user = identity.users && identity.users[0];
    if (!verify.ok || !user || !user.localId) return res.status(401).json({ error: 'La sesión ha caducado. Inicia sesión de nuevo.' });
    if (req.body?.action === 'submitConsent') {
      const name=String(req.body.name||'').trim(), signatureImage=String(req.body.signature||'');
      if(name.length<3||name.length>150||req.body.accepted!==true||!/^data:image\/png;base64,[A-Za-z0-9+/=]+$/.test(signatureImage)||signatureImage.length>500000)return res.status(400).json({error:'Completa el nombre, acepta las condiciones y firma.'});
      const {PDFDocument,StandardFonts,rgb}=require('pdf-lib');
      const date=new Date().toISOString(),slug=name.normalize('NFD').replace(/[\u0300-\u036f]/g,'').replace(/[^a-zA-Z0-9_-]+/g,'-').slice(0,100);
      const filename=(slug||'Firmante')+'.autorizacion.pdf';
      const public_id='autismo-familiar/authorizations/'+crypto.randomUUID()+'/'+filename;
      const doc=await PDFDocument.create(),font=await doc.embedFont(StandardFonts.Helvetica),bold=await doc.embedFont(StandardFonts.HelveticaBold);
      doc.setTitle('Autorización de '+name);
      let page=doc.addPage([595,842]),y=790;
      function write(value,size=11,f=font){
        const safe=String(value).replace(/[^\u0020-\u007e\u00a0-\u00ff]/g,'?');
        let line='';for(const word of safe.split(/\s+/)){const next=line?line+' '+word:word;if(line&&f.widthOfTextAtSize(next,size)>495){page.drawText(line,{x:50,y,size,font:f,color:rgb(.1,.15,.2)});y-=size+5;line=word}else line=next}if(line){page.drawText(line,{x:50,y,size,font:f,color:rgb(.1,.15,.2)});y-=size+5}y-=10;
      }
      write('Autorización de uso de imagen, voz y contenidos',18,bold);
      write('Firmante: '+name);write('Correo de cuenta: '+(user.email||''));write('Fecha UTC: '+date);
      write("Autorizo a Autismo Familiar a publicar y difundir los materiales que facilite voluntariamente en su web y redes sociales con fines informativos, de sensibilización, divulgación, promoción, económicos y comerciales. La autorización es no exclusiva y sin remuneración al firmante. Declaro disponer de los derechos y permisos necesarios. Podrán establecerse cuotas por presencia en el mapa y publicación de vídeos; esta autorización no implica contratar ni aceptar una cuota. Podré retirar la autorización para usos futuros solicitándolo al responsable.");
      write('Condiciones aceptadas expresamente.');write('Firma manuscrita',13,bold);
      const img=await doc.embedPng(Buffer.from(signatureImage.split(',')[1],'base64'));const scale=Math.min(1,400/img.width,140/img.height);page.drawImage(img,{x:50,y:y-img.height*scale,width:img.width*scale,height:img.height*scale});
      const pdf=await doc.save();
      const params={public_id,timestamp:Math.floor(Date.now()/1000),type:'authenticated',overwrite:'false'};
      const signature=crypto.createHash('sha1').update(Object.keys(params).sort().map(k=>k+'='+params[k]).join('&')+secret).digest('hex');
      const form=new FormData();form.append('file',new Blob([pdf],{type:'application/pdf'}),filename);for(const [k,v] of Object.entries({...params,api_key:key,signature}))form.append(k,String(v));
      const upload=await fetch('https://api.cloudinary.com/v1_1/'+encodeURIComponent(cloud)+'/raw/upload',{method:'POST',body:form});
      const result=await upload.json();if(!upload.ok||result.public_id!==public_id||result.type!=='authenticated')return res.status(502).json({error:'No se pudo guardar la autorización privada.'});
      return res.status(200).json({ok:true,receipt:crypto.createHash('sha256').update(public_id).digest('hex')});
    }
    const timestamp = Math.floor(Date.now() / 1000);
    const folder = 'autismo-familiar/profile-videos';
    const params = { folder, timestamp };
    const toSign = Object.keys(params).sort().map(k => k + '=' + params[k]).join('&') + secret;
    const signature = crypto.createHash('sha1').update(toSign).digest('hex');
    return res.status(200).json({ cloudName: cloud, apiKey: key, timestamp, folder, signature });
  } catch (error) {
    return res.status(500).json({ error: 'No se pudo preparar la subida segura del vídeo.' });
  }
};
