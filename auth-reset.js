import { getApps } from 'https://www.gstatic.com/firebasejs/10.12.5/firebase-app.js';
import { getAuth, sendPasswordResetEmail } from 'https://www.gstatic.com/firebasejs/10.12.5/firebase-auth.js';

const sleep=ms=>new Promise(r=>setTimeout(r,ms));
async function app(){for(let i=0;i<100;i++){const found=getApps()[0];if(found)return found;await sleep(50);}throw new Error('Firebase app indisponível');}

(async()=>{
  const firebaseApp=await app();
  const auth=getAuth(firebaseApp);
  const button=document.getElementById('resetPassword');
  if(!button)return;
  button.addEventListener('click',async event=>{
    event.preventDefault();
    event.stopImmediatePropagation();
    const status=document.getElementById('loginStatus');
    const email=String(document.getElementById('email')?.value||'').trim().toLowerCase();
    if(!email){if(status)status.textContent='Informe o e-mail primeiro.';return;}
    try{await sendPasswordResetEmail(auth,email);}catch(error){console.warn('[LPS Auth] reset request',error?.code||'request_failed');}
    if(status)status.textContent='Se a conta estiver cadastrada, as instruções de redefinição serão enviadas.';
  },true);
})().catch(error=>console.error('[LPS Auth] reset guard',error));
